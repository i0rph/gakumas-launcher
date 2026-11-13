//! OpenVPN 클라이언트 (VPN Gate 가 쓰는 범위만 구현)
//!
//! 지원: TCP, tls-client, key-method 2, AES-128-CBC + HMAC-SHA1 데이터 채널, comp-lzo 틀(압축 안 함)
//! 미지원: UDP, tls-auth/tls-crypt, AEAD 암호, 실제 압축, 재협상
//!
//! 가상 네트워크 장치나 라우팅 표를 건드리지 않습니다. 복호화한 IP 패킷은 `take_inbound` 로
//! 꺼내 사용자 공간 TCP/IP 스택에 넘기고, 보낼 IP 패킷은 `send_ip` 로 넣습니다.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use md5::Md5;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use sha1::Sha1;

use crate::vpngate::OvpnConfig;

const OP_CONTROL_V1: u8 = 4;
const OP_ACK_V1: u8 = 5;
const OP_DATA_V1: u8 = 6;
const OP_HARD_RESET_CLIENT_V2: u8 = 7;
const OP_HARD_RESET_SERVER_V2: u8 = 8;
const OP_DATA_V2: u8 = 9;

/// 데이터 채널로 오는 OpenVPN keepalive 패킷
const PING_MAGIC: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];
/// 서버(SoftEther)가 이 문자열에서 cipher/auth 를 읽어 데이터 채널 방식을 정함
const OPTIONS_STRING: &str = "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client";
const PEER_INFO: &str = "IV_VER=2.5.0\nIV_PLAT=win\n";
/// 제어 채널 패킷 하나에 싣는 TLS 바이트 수
const CONTROL_CHUNK: usize = 1000;

/// 서버 key-method 2 응답의 난수 두 개 (random1, random2)
type ServerRandoms = ([u8; 32], [u8; 32]);
type HmacSha1 = Hmac<Sha1>;
type HmacMd5 = Hmac<Md5>;
type AesCbcEnc = cbc::Encryptor<Aes128>;
type AesCbcDec = cbc::Decryptor<Aes128>;

/// 서버가 알려 준 터널 주소 정보
#[derive(Clone, Debug)]
pub struct PushInfo {
    pub local_ip: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
    pub topology: String,
    pub comp_lzo: bool,
}

struct DataKeys {
    enc_cipher: [u8; 16],
    enc_hmac: [u8; 20],
    dec_cipher: [u8; 16],
    dec_hmac: [u8; 20],
}

struct Control {
    sid: [u8; 8],
    pid: Option<u32>,
    payload: Vec<u8>,
}

pub struct Tunnel {
    stream: TcpStream,
    rbuf: Vec<u8>,
    local_sid: [u8; 8],
    remote_sid: [u8; 8],
    next_pid: u32,
    next_remote_pid: u32,
    tls: ClientConnection,
    plain: Vec<u8>,
    keys: Option<DataKeys>,
    data_pid: u32,
    comp_lzo: bool,
    inbox: VecDeque<Vec<u8>>,
    pub push: Option<PushInfo>,
    /// VPN 서버 인증서 검증 결과 (DMM 과의 통신은 터널 안에서 별도 TLS 로 다시 검증됨)
    pub server_cert_status: String,
    pub server_options: String,
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS random generator");
    b
}

fn write_string(m: &mut Vec<u8>, s: &str) {
    m.extend_from_slice(&((s.len() + 1) as u16).to_be_bytes());
    m.extend_from_slice(s.as_bytes());
    m.push(0);
}

fn parse_control(p: &[u8]) -> Option<Control> {
    if p.len() < 10 {
        return None;
    }
    let opcode = p[0] >> 3;
    let mut sid = [0u8; 8];
    sid.copy_from_slice(&p[1..9]);
    let ack_len = p[9] as usize;
    let mut off = 10 + 4 * ack_len;
    if ack_len > 0 {
        off += 8;
    }
    let pid = if opcode != OP_ACK_V1 {
        let b = p.get(off..off + 4)?;
        off += 4;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    } else {
        None
    };
    Some(Control {
        sid,
        pid,
        payload: p.get(off..)?.to_vec(),
    })
}

fn parse_v4(s: &str) -> Option<[u8; 4]> {
    s.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets())
}

// --- 키 생성 (OpenVPN key-method 2 = TLS 1.0 PRF) ---

fn p_hash<M: Mac + KeyInit>(secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mac = |parts: &[&[u8]]| -> Vec<u8> {
        let mut m = <M as Mac>::new_from_slice(secret).expect("HMAC key");
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().to_vec()
    };
    let mut out = Vec::with_capacity(len + 32);
    let mut a = mac(&[seed]);
    while out.len() < len {
        out.extend(mac(&[&a[..], seed]));
        a = mac(&[&a[..]]);
    }
    out.truncate(len);
    out
}

fn prf(secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let half = secret.len().div_ceil(2);
    let a = p_hash::<HmacMd5>(&secret[..half], seed, len);
    let b = p_hash::<HmacSha1>(&secret[secret.len() - half..], seed, len);
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// --- VPN 서버 인증서 검증 (결과만 기록하고 연결은 계속) ---

#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    status: Arc<Mutex<String>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        *self.status.lock().unwrap() = match &result {
            Ok(_) => "verified".to_string(),
            Err(e) => format!("not verified ({e})"),
        };
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// VPN Gate 공용 클라이언트 인증서는 오래된 X.509 v1 형식이라 rustls 의 일반 경로
/// (with_client_auth_cert)가 거부함. 검사 없이 그대로 보내도록 직접 넘겨 줌
#[derive(Debug)]
struct FixedClientCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for FixedClientCert {
    fn resolve(
        &self,
        _hints: &[&[u8]],
        _schemes: &[SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn build_tls_config(cfg: &OvpnConfig, status: Arc<Mutex<String>>) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut cfg.ca_pem.as_bytes()) {
        let c = c.map_err(|e| format!("CA certificate: {e}"))?;
        roots.add(c).map_err(|e| format!("CA certificate: {e}"))?;
    }
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cfg.cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("client certificate: {e}"))?;
    let key = rustls_pemfile::private_key(&mut cfg.key_pem.as_bytes())
        .map_err(|e| format!("client key: {e}"))?
        .ok_or("client key missing")?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("client key: {e}"))?;
    let client_cert = FixedClientCert(Arc::new(rustls::sign::CertifiedKey::new(
        certs,
        signing_key,
    )));
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| format!("verifier: {e}"))?;
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RecordingVerifier { inner, status }))
        .with_client_cert_resolver(Arc::new(client_cert)))
}

impl Tunnel {
    /// VPN 서버에 접속해 터널 주소를 받을 때까지 진행
    pub fn connect(
        cfg: &OvpnConfig,
        tls_name: &str,
        log: &mut dyn FnMut(String),
    ) -> Result<Tunnel, String> {
        if !cfg.proto.starts_with("tcp") {
            return Err(format!("unsupported protocol '{}' (TCP only)", cfg.proto));
        }
        if !cfg.cipher.eq_ignore_ascii_case("AES-128-CBC") || !cfg.auth.eq_ignore_ascii_case("SHA1")
        {
            return Err(format!(
                "unsupported cipher/auth {}/{}",
                cfg.cipher, cfg.auth
            ));
        }
        let addr: SocketAddr = format!("{}:{}", cfg.remote_ip, cfg.port)
            .parse()
            .map_err(|e| format!("bad server address: {e}"))?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
            .map_err(|e| format!("TCP connect: {e}"))?;
        stream.set_nodelay(true).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
        log(format!("TCP connected to {addr}"));

        let status = Arc::new(Mutex::new(String::from("not checked")));
        let tls_cfg = build_tls_config(cfg, status.clone())?;
        let name =
            ServerName::try_from(tls_name.to_string()).map_err(|e| format!("server name: {e}"))?;
        let tls =
            ClientConnection::new(Arc::new(tls_cfg), name).map_err(|e| format!("TLS init: {e}"))?;

        let mut t = Tunnel {
            stream,
            rbuf: Vec::new(),
            local_sid: rand_bytes(),
            remote_sid: [0; 8],
            next_pid: 0,
            next_remote_pid: 0,
            tls,
            plain: Vec::new(),
            keys: None,
            data_pid: 1,
            comp_lzo: false,
            inbox: VecDeque::new(),
            push: None,
            server_cert_status: String::new(),
            server_options: String::new(),
        };

        // 1) 세션 시작
        let pkt = t.control_packet(OP_HARD_RESET_CLIENT_V2, &[]);
        t.send_frame(&pkt)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let p = t
                .read_frame_until(deadline)?
                .ok_or("no reply to session reset")?;
            if !p.is_empty() && p[0] >> 3 == OP_HARD_RESET_SERVER_V2 {
                let c = parse_control(&p).ok_or("malformed reset reply")?;
                let pid = c.pid.unwrap_or(0);
                t.remote_sid = c.sid;
                t.next_remote_pid = pid + 1;
                t.send_ack(pid)?;
                break;
            }
        }
        log("session reset acknowledged".to_string());

        // 2) 제어 채널 TLS
        let deadline = Instant::now() + Duration::from_secs(20);
        while t.tls.is_handshaking() {
            t.flush_tls()?;
            match t.read_frame_until(deadline)? {
                Some(p) => t.handle_packet(p)?,
                None => return Err("TLS handshake timed out".into()),
            }
        }
        t.flush_tls()?;
        t.server_cert_status = status.lock().unwrap().clone();
        log(format!(
            "TLS handshake done ({:?}); VPN server certificate {}",
            t.tls
                .protocol_version()
                .map(|v| format!("{v:?}"))
                .unwrap_or_default(),
            t.server_cert_status
        ));

        // 3) key-method 2 키 교환
        let pre_master: [u8; 48] = rand_bytes();
        let r1: [u8; 32] = rand_bytes();
        let r2: [u8; 32] = rand_bytes();
        let mut m = vec![0u8, 0, 0, 0, 2];
        m.extend_from_slice(&pre_master);
        m.extend_from_slice(&r1);
        m.extend_from_slice(&r2);
        write_string(&mut m, OPTIONS_STRING);
        m.extend_from_slice(&[0, 0, 0, 0]); // 사용자 이름/비밀번호 없음
        write_string(&mut m, PEER_INFO);
        t.tls
            .writer()
            .write_all(&m)
            .map_err(|e| format!("TLS write: {e}"))?;
        t.flush_tls()?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let (sr1, sr2) = loop {
            if let Some(v) = t.take_server_key_method()? {
                break v;
            }
            match t.read_frame_until(deadline)? {
                Some(p) => t.handle_packet(p)?,
                None => return Err("no key exchange reply".into()),
            }
        };
        t.derive_keys(&pre_master, &r1, &r2, &sr1, &sr2);
        log(format!(
            "key exchange done (server options: {})",
            t.server_options
        ));

        // 4) 터널 주소 받기
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut next_request = Instant::now();
        let reply = loop {
            if let Some(r) = t.take_control_message("PUSH_REPLY")? {
                break r;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("no PUSH_REPLY from server".into());
            }
            if now >= next_request {
                t.tls
                    .writer()
                    .write_all(b"PUSH_REQUEST\0")
                    .map_err(|e| format!("TLS write: {e}"))?;
                t.flush_tls()?;
                next_request = now + Duration::from_secs(3);
            }
            if let Some(p) = t.read_frame_until((now + Duration::from_millis(500)).min(deadline))? {
                t.handle_packet(p)?;
            }
        };
        t.apply_push(&reply)?;
        let push = t.push.clone().unwrap();
        log(format!(
            "tunnel address {}/{} (gateway {:?}, topology {}, comp-lzo {})",
            std::net::Ipv4Addr::from(push.local_ip),
            push.prefix_len,
            push.gateway.map(std::net::Ipv4Addr::from),
            push.topology,
            push.comp_lzo
        ));
        Ok(t)
    }

    // --- 프레임 입출력 (TCP 위에서는 2바이트 길이 + 패킷) ---

    fn send_frame(&mut self, pkt: &[u8]) -> Result<(), String> {
        let mut f = Vec::with_capacity(pkt.len() + 2);
        f.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        f.extend_from_slice(pkt);
        self.stream
            .write_all(&f)
            .map_err(|e| format!("VPN send: {e}"))
    }

    fn read_frame_until(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>, String> {
        loop {
            if self.rbuf.len() >= 2 {
                let n = u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]) as usize;
                if self.rbuf.len() >= 2 + n {
                    let pkt = self.rbuf[2..2 + n].to_vec();
                    self.rbuf.drain(..2 + n);
                    return Ok(Some(pkt));
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let wait = (deadline - now).max(Duration::from_millis(1));
            self.stream
                .set_read_timeout(Some(wait))
                .map_err(|e| e.to_string())?;
            let mut tmp = [0u8; 16384];
            match self.stream.read(&mut tmp) {
                Ok(0) => return Err("VPN server closed the connection".into()),
                Ok(n) => self.rbuf.extend_from_slice(&tmp[..n]),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(None)
                }
                Err(e) => return Err(format!("VPN connection: {e}")),
            }
        }
    }

    // --- 제어 채널 ---

    fn control_packet(&mut self, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(14 + payload.len());
        p.push(opcode << 3);
        p.extend_from_slice(&self.local_sid);
        p.push(0); // 확인 응답은 P_ACK_V1 로 따로 보냄
        p.extend_from_slice(&self.next_pid.to_be_bytes());
        self.next_pid += 1;
        p.extend_from_slice(payload);
        p
    }

    fn send_ack(&mut self, pid: u32) -> Result<(), String> {
        let mut p = Vec::with_capacity(22);
        p.push(OP_ACK_V1 << 3);
        p.extend_from_slice(&self.local_sid);
        p.push(1);
        p.extend_from_slice(&pid.to_be_bytes());
        p.extend_from_slice(&self.remote_sid);
        self.send_frame(&p)
    }

    fn flush_tls(&mut self) -> Result<(), String> {
        while self.tls.wants_write() {
            let mut out = Vec::new();
            self.tls
                .write_tls(&mut out)
                .map_err(|e| format!("TLS write: {e}"))?;
            for chunk in out.chunks(CONTROL_CHUNK) {
                let pkt = self.control_packet(OP_CONTROL_V1, chunk);
                self.send_frame(&pkt)?;
            }
        }
        Ok(())
    }

    fn handle_packet(&mut self, p: Vec<u8>) -> Result<(), String> {
        if p.is_empty() {
            return Ok(());
        }
        match p[0] >> 3 {
            OP_DATA_V1 | OP_DATA_V2 => {
                if let Some(ip) = self.decrypt_data(&p)? {
                    if ip.as_slice() != PING_MAGIC {
                        self.inbox.push_back(ip);
                    }
                }
            }
            OP_CONTROL_V1 => {
                let c = parse_control(&p).ok_or("malformed control packet")?;
                let pid = c.pid.unwrap_or(0);
                self.send_ack(pid)?;
                if pid < self.next_remote_pid {
                    return Ok(()); // 재전송된 중복 패킷
                }
                self.next_remote_pid = pid + 1;
                let mut rd: &[u8] = &c.payload;
                while !rd.is_empty() {
                    self.tls
                        .read_tls(&mut rd)
                        .map_err(|e| format!("TLS read: {e}"))?;
                    self.tls
                        .process_new_packets()
                        .map_err(|e| format!("TLS: {e}"))?;
                }
                let mut buf = [0u8; 4096];
                loop {
                    match self.tls.reader().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => self.plain.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(format!("TLS plaintext: {e}")),
                    }
                }
            }
            OP_HARD_RESET_SERVER_V2 => {
                if let Some(c) = parse_control(&p) {
                    self.send_ack(c.pid.unwrap_or(0))?;
                }
            }
            _ => {} // P_ACK_V1 등
        }
        Ok(())
    }

    /// 서버의 key-method 2 응답에서 난수 두 개를 꺼냄
    fn take_server_key_method(&mut self) -> Result<Option<ServerRandoms>, String> {
        let p = &self.plain;
        if p.len() < 71 {
            return Ok(None);
        }
        if p[0..4] != [0, 0, 0, 0] || p[4] != 2 {
            return Err(format!(
                "unexpected key exchange message (starts {:02x?})",
                &p[..5]
            ));
        }
        let olen = u16::from_be_bytes([p[69], p[70]]) as usize;
        if p.len() < 71 + olen {
            return Ok(None);
        }
        let mut r1 = [0u8; 32];
        r1.copy_from_slice(&p[5..37]);
        let mut r2 = [0u8; 32];
        r2.copy_from_slice(&p[37..69]);
        self.server_options = String::from_utf8_lossy(&p[71..71 + olen])
            .trim_end_matches('\0')
            .to_string();
        self.plain.drain(..71 + olen);
        Ok(Some((r1, r2)))
    }

    /// 제어 채널의 NUL 로 끝나는 문자열 메시지 중 prefix 로 시작하는 것을 꺼냄
    fn take_control_message(&mut self, prefix: &str) -> Result<Option<String>, String> {
        while let Some(pos) = self.plain.iter().position(|&b| b == 0) {
            let msg = String::from_utf8_lossy(&self.plain[..pos]).into_owned();
            self.plain.drain(..=pos);
            if msg.starts_with("AUTH_FAILED") {
                return Err(format!("server refused: {msg}"));
            }
            if msg.starts_with(prefix) {
                return Ok(Some(msg));
            }
        }
        Ok(None)
    }

    fn derive_keys(
        &mut self,
        pre: &[u8; 48],
        cr1: &[u8; 32],
        cr2: &[u8; 32],
        sr1: &[u8; 32],
        sr2: &[u8; 32],
    ) {
        let mut seed = b"OpenVPN master secret".to_vec();
        seed.extend_from_slice(cr1);
        seed.extend_from_slice(sr1);
        let master = prf(pre, &seed, 48);
        let mut seed = b"OpenVPN key expansion".to_vec();
        seed.extend_from_slice(cr2);
        seed.extend_from_slice(sr2);
        seed.extend_from_slice(&self.local_sid);
        seed.extend_from_slice(&self.remote_sid);
        let kb = prf(&master, &seed, 256);
        // key[0] = 클라이언트→서버, key[1] = 서버→클라이언트. 각 key 는 cipher 64 바이트 + hmac 64 바이트
        let mut k = DataKeys {
            enc_cipher: [0; 16],
            enc_hmac: [0; 20],
            dec_cipher: [0; 16],
            dec_hmac: [0; 20],
        };
        k.enc_cipher.copy_from_slice(&kb[0..16]);
        k.enc_hmac.copy_from_slice(&kb[64..84]);
        k.dec_cipher.copy_from_slice(&kb[128..144]);
        k.dec_hmac.copy_from_slice(&kb[192..212]);
        self.keys = Some(k);
    }

    fn apply_push(&mut self, reply: &str) -> Result<(), String> {
        let mut ip = None;
        let mut second = None;
        let mut gw = None;
        let mut topology = String::from("net30");
        for opt in reply.trim_start_matches("PUSH_REPLY").split(',') {
            let parts: Vec<&str> = opt.split_whitespace().collect();
            match parts.first().copied() {
                Some("ifconfig") => {
                    ip = parts.get(1).and_then(|s| parse_v4(s));
                    second = parts.get(2).and_then(|s| parse_v4(s));
                }
                Some("route-gateway") => gw = parts.get(1).and_then(|s| parse_v4(s)),
                Some("topology") => topology = parts.get(1).copied().unwrap_or("").to_string(),
                Some("comp-lzo") => self.comp_lzo = true,
                Some("compress") => {
                    return Err("server requires 'compress' framing (not supported)".into())
                }
                Some("cipher") => {
                    if let Some(c) = parts.get(1) {
                        if !c.eq_ignore_ascii_case("AES-128-CBC") {
                            return Err(format!("server pushed cipher {c} (not supported)"));
                        }
                    }
                }
                _ => {}
            }
        }
        let ip = ip.ok_or("no ifconfig in PUSH_REPLY")?;
        let (prefix_len, gateway) = match second {
            Some(mask) if mask[0] == 255 => {
                let bits = u32::from_be_bytes(mask).count_ones() as u8;
                let net = u32::from_be_bytes(ip) & u32::from_be_bytes(mask);
                (bits, gw.or(Some((net + 1).to_be_bytes())))
            }
            Some(peer) => (32, gw.or(Some(peer))),
            None => (32, gw),
        };
        self.push = Some(PushInfo {
            local_ip: ip,
            prefix_len,
            gateway,
            topology,
            comp_lzo: self.comp_lzo,
        });
        Ok(())
    }

    // --- 데이터 채널 ---

    fn decrypt_data(&self, p: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let Some(k) = self.keys.as_ref() else {
            return Ok(None);
        };
        let off = if p[0] >> 3 == OP_DATA_V2 { 4 } else { 1 };
        if p.len() < off + 20 + 16 + 16 {
            return Err("short data packet".into());
        }
        let (tag, rest) = p[off..].split_at(20);
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&k.dec_hmac).expect("HMAC key");
        mac.update(rest);
        if mac.verify_slice(tag).is_err() {
            return Err("data packet failed authentication (key mismatch)".into());
        }
        let (iv, ct) = rest.split_at(16);
        let plain = AesCbcDec::new_from_slices(&k.dec_cipher, iv)
            .map_err(|e| format!("{e:?}"))?
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .map_err(|_| "bad padding in data packet".to_string())?;
        if plain.len() < 4 {
            return Err("short data plaintext".into());
        }
        let mut body = &plain[4..];
        if self.comp_lzo {
            match body.first() {
                Some(0xFA) => body = &body[1..],
                Some(b) => return Err(format!("compressed data packet (0x{b:02x}) not supported")),
                None => {}
            }
        }
        Ok(Some(body.to_vec()))
    }

    /// IP 패킷 하나를 암호화해 서버로 보냄
    pub fn send_ip(&mut self, ip: &[u8]) -> Result<(), String> {
        let pid = self.data_pid;
        self.data_pid = self.data_pid.wrapping_add(1);
        let k = self.keys.as_ref().ok_or("data channel not ready")?;
        let mut plain = Vec::with_capacity(ip.len() + 8);
        plain.extend_from_slice(&pid.to_be_bytes());
        if self.comp_lzo {
            plain.push(0xFA);
        }
        plain.extend_from_slice(ip);
        let iv: [u8; 16] = rand_bytes();
        let ct = AesCbcEnc::new_from_slices(&k.enc_cipher, &iv)
            .map_err(|e| format!("{e:?}"))?
            .encrypt_padded_vec_mut::<Pkcs7>(&plain);
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&k.enc_hmac).expect("HMAC key");
        mac.update(&iv);
        mac.update(&ct);
        let tag = mac.finalize().into_bytes();
        let mut pkt = Vec::with_capacity(1 + 20 + 16 + ct.len());
        pkt.push(OP_DATA_V1 << 3);
        pkt.extend_from_slice(&tag);
        pkt.extend_from_slice(&iv);
        pkt.extend_from_slice(&ct);
        self.send_frame(&pkt)
    }

    /// 서버에서 온 패킷을 최대 `wait` 동안 기다려 처리
    pub fn pump(&mut self, wait: Duration) -> Result<(), String> {
        let mut deadline = Instant::now() + wait;
        for _ in 0..256 {
            match self.read_frame_until(deadline)? {
                Some(p) => self.handle_packet(p)?,
                None => break,
            }
            deadline = Instant::now() + Duration::from_millis(1);
        }
        Ok(())
    }

    /// 복호화된 IP 패킷 하나를 꺼냄
    pub fn take_inbound(&mut self) -> Option<Vec<u8>> {
        self.inbox.pop_front()
    }
}
