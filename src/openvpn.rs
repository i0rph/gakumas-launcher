//! OpenVPN 클라이언트 (사용자 공간)
//!
//! 지원: TCP / UDP, tls-client, key-method 2, tls-auth / tls-crypt, 아이디·비밀번호 로그인,
//!       데이터 채널 AES-128/192/256-CBC + HMAC(SHA1/256/384/512), AES-128/256-GCM, CHACHA20-POLY1305,
//!       cipher 협상(NCP), P_DATA_V2, comp-lzo / compress stub 틀(압축은 안 함), fragment
//! 미지원: tls-crypt-v2, 실제 압축, 재협상, dev tap
//!
//! 가상 네트워크 장치나 라우팅 표를 건드리지 않습니다. 복호화한 IP 패킷은 `take_inbound` 로
//! 꺼내 사용자 공간 TCP/IP 스택에 넘기고, 보낼 IP 패킷은 `send_ip` 로 넣습니다.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ctr::cipher::StreamCipher;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use md5::Md5;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hmac as rhmac;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
};
use sha1::Sha1;

use crate::netstack::{IpTunnel, TunnelAddr};

const OP_CONTROL_SOFT_RESET_V1: u8 = 3;
const OP_CONTROL_V1: u8 = 4;
const OP_ACK_V1: u8 = 5;
const OP_DATA_V1: u8 = 6;
const OP_HARD_RESET_CLIENT_V2: u8 = 7;
const OP_HARD_RESET_SERVER_V2: u8 = 8;
const OP_DATA_V2: u8 = 9;

/// 데이터 채널로 오는 OpenVPN keepalive 패킷
pub const PING_MAGIC: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];
/// 이 클라이언트가 쓸 수 있는 데이터 채널 암호 (서버와 협상할 때 알려 줌, 선호 순)
const SUPPORTED_CIPHERS: &[&str] = &[
    "AES-256-GCM",
    "AES-128-GCM",
    "CHACHA20-POLY1305",
    "AES-256-CBC",
    "AES-192-CBC",
    "AES-128-CBC",
];
/// 제어 채널 패킷 하나에 싣는 TLS 바이트 수
const CONTROL_CHUNK: usize = 1000;
/// UDP 에서 확인 응답이 없을 때 제어 패킷을 다시 보내는 간격
const RETRANSMIT_AFTER: Duration = Duration::from_millis(1500);
/// 터널 안 IP 패킷 최대 크기 기본값. 작게 잡아 TCP 세그먼트가 터널에서 잘리지 않게 함
const DEFAULT_MTU: usize = 1350;

/// 서버 key-method 2 응답의 난수 두 개 (random1, random2)
type ServerRandoms = ([u8; 32], [u8; 32]);
type HmacSha1 = Hmac<Sha1>;
type HmacMd5 = Hmac<Md5>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

// ---------------------------------------------------------------------------
// 설정 파일
// ---------------------------------------------------------------------------

/// 압축 틀 (실제 압축은 하지 않고, 서버가 기대하는 표시 바이트만 맞춤)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compress {
    None,
    /// comp-lzo: 앞에 0xFA
    Lzo,
    /// compress (v1): 첫 바이트를 0xFB 로 바꾸고 원래 첫 바이트를 끝에 붙임
    Stub,
    /// compress stub-v2: 첫 바이트가 0x50 일 때만 표시
    StubV2,
}

#[derive(Clone, Debug)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    pub udp: bool,
}

/// OpenVPN 정적 키 (tls-auth / tls-crypt). 256 바이트 = 키 2개 × (암호 64 + HMAC 64)
#[derive(Clone)]
pub struct StaticKey([u8; 256]);

impl std::fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticKey(..)")
    }
}

impl StaticKey {
    fn parse(text: &str) -> Result<Self, String> {
        let hex: String = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("-----"))
            .collect();
        if hex.len() != 512 {
            return Err("static key must be 2048 bits".into());
        }
        let mut k = [0u8; 256];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "bad static key")?;
        }
        Ok(Self(k))
    }
    fn cipher(&self, i: usize) -> &[u8] {
        &self.0[i * 128..i * 128 + 64]
    }
    fn hmac(&self, i: usize) -> &[u8] {
        &self.0[i * 128 + 64..i * 128 + 128]
    }
}

#[derive(Clone, Debug)]
pub struct OvpnConfig {
    pub remotes: Vec<Remote>,
    pub remote_random: bool,
    /// 예전 방식의 고정 암호 (협상하지 않는 서버용)
    pub cipher: Option<String>,
    pub data_ciphers: Vec<String>,
    pub auth: String,
    pub ca_pem: String,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    /// tls-auth 키와 key-direction
    pub tls_auth: Option<(StaticKey, Option<u8>)>,
    pub tls_crypt: Option<StaticKey>,
    pub auth_user_pass: bool,
    pub compress: Compress,
    pub fragment: Option<usize>,
}

fn inline_block(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(text[start..end].trim().to_string())
}

/// 지시어 줄 (주석·인라인 블록 내용 제외)
fn directive_lines(text: &str) -> Vec<Vec<&str>> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("</") {
            in_block = false;
            continue;
        }
        if l.starts_with('<') {
            in_block = !l.contains("</");
            continue;
        }
        if in_block || l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        out.push(l.split_whitespace().collect());
    }
    out
}

impl OvpnConfig {
    /// .ovpn 텍스트를 해석. 외부 파일을 가리키는 지시어는 `inline_external_files` 로 미리 넣어 둬야 함
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut udp = true;
        let mut port: u16 = 1194;
        let mut raw_remotes: Vec<(String, Option<u16>, Option<bool>)> = Vec::new();
        let mut cfg = OvpnConfig {
            remotes: Vec::new(),
            remote_random: false,
            cipher: None,
            data_ciphers: Vec::new(),
            auth: "SHA1".into(),
            ca_pem: String::new(),
            cert_pem: None,
            key_pem: None,
            tls_auth: None,
            tls_crypt: None,
            auth_user_pass: false,
            compress: Compress::None,
            fragment: None,
        };
        let mut key_direction: Option<u8> = None;
        let mut tls_auth_inline = false;
        for d in directive_lines(text) {
            let arg = d.get(1).copied();
            match d[0] {
                "proto" => udp = !arg.unwrap_or("udp").starts_with("tcp"),
                "port" | "rport" => {
                    port = arg.and_then(|p| p.parse().ok()).ok_or("bad port")?;
                }
                "remote" => {
                    let host = arg.ok_or("remote without host")?.to_string();
                    let p = d.get(2).and_then(|p| p.parse().ok());
                    let u = d.get(3).map(|p| !p.starts_with("tcp"));
                    raw_remotes.push((host, p, u));
                }
                "remote-random" => cfg.remote_random = true,
                "cipher" => cfg.cipher = arg.map(|s| s.to_ascii_uppercase()),
                "data-ciphers" | "ncp-ciphers" => {
                    cfg.data_ciphers = arg
                        .unwrap_or("")
                        .split(':')
                        .map(|s| s.to_ascii_uppercase())
                        .collect()
                }
                "auth" => cfg.auth = arg.unwrap_or("SHA1").to_ascii_uppercase(),
                "auth-user-pass" => {
                    if arg.is_some() {
                        return Err("auth-user-pass 파일은 가져오기 때 읽어야 합니다".into());
                    }
                    cfg.auth_user_pass = true
                }
                "comp-lzo" => cfg.compress = Compress::Lzo,
                "compress" => {
                    cfg.compress = if arg == Some("stub-v2") {
                        Compress::StubV2
                    } else {
                        Compress::Stub
                    }
                }
                "fragment" => cfg.fragment = arg.and_then(|n| n.parse().ok()),
                "key-direction" => key_direction = arg.and_then(|n| n.parse().ok()),
                "dev" if arg.is_some_and(|a| a.starts_with("tap")) => {
                    return Err("dev tap 설정은 지원하지 않습니다 (dev tun 만 지원)".into())
                }
                "tls-crypt-v2" => return Err("tls-crypt-v2 는 지원하지 않습니다".into()),
                "pkcs12" => return Err("pkcs12 인증서는 지원하지 않습니다".into()),
                "ca" | "cert" | "key" | "tls-crypt" if arg.is_some_and(|a| a != "[inline]") => {
                    return Err(format!(
                        "{} 이 다른 파일을 가리킵니다. 인증서가 들어 있는 .ovpn 파일을 쓰세요",
                        d[0]
                    ))
                }
                "tls-auth" => {
                    match arg {
                        Some("[inline]") | None => tls_auth_inline = true,
                        Some(_) => {
                            return Err(
                                "tls-auth 가 다른 파일을 가리킵니다. 키가 들어 있는 .ovpn 파일을 쓰세요"
                                    .into(),
                            )
                        }
                    }
                    if let Some(dir) = d.get(2).and_then(|n| n.parse().ok()) {
                        key_direction = Some(dir);
                    }
                }
                _ => {}
            }
        }
        cfg.ca_pem = inline_block(text, "ca").ok_or("<ca> 인증서가 없습니다")?;
        cfg.cert_pem = inline_block(text, "cert");
        cfg.key_pem = inline_block(text, "key");
        if let Some(k) = inline_block(text, "tls-auth") {
            cfg.tls_auth = Some((StaticKey::parse(&k)?, key_direction));
        } else if tls_auth_inline {
            return Err("<tls-auth> 키가 없습니다".into());
        }
        if let Some(k) = inline_block(text, "tls-crypt") {
            cfg.tls_crypt = Some(StaticKey::parse(&k)?);
        }
        if text.contains("<tls-crypt-v2>") {
            return Err("tls-crypt-v2 는 지원하지 않습니다".into());
        }
        cfg.remotes = raw_remotes
            .into_iter()
            .map(|(host, p, u)| Remote {
                host,
                port: p.unwrap_or(port),
                udp: u.unwrap_or(udp),
            })
            .collect();
        if cfg.remotes.is_empty() {
            return Err("remote (서버 주소)가 없습니다".into());
        }
        Ok(cfg)
    }

    /// 접속할 서버 순서 (remote-random 이면 섞음, 같은 주소는 한 번만)
    pub fn remote_order(&self) -> Vec<Remote> {
        let mut seen = std::collections::HashSet::new();
        let mut v: Vec<Remote> = self
            .remotes
            .iter()
            .filter(|r| seen.insert((r.host.clone(), r.port, r.udp)))
            .cloned()
            .collect();
        if self.remote_random {
            for i in (1..v.len()).rev() {
                let r: [u8; 4] = rand_bytes();
                v.swap(i, u32::from_le_bytes(r) as usize % (i + 1));
            }
        }
        v
    }
}

/// .ovpn 이 같은 폴더의 다른 파일(ca.crt, ta.key, 아이디·비밀번호 파일 등)을 가리키면 그 내용을 넣어
/// 파일 하나로 만듦. 아이디·비밀번호 파일이 있으면 (아이디, 비밀번호)를 따로 돌려줌
pub fn inline_external_files(
    text: &str,
    dir: &Path,
) -> Result<(String, Option<(String, String)>), String> {
    let mut out = String::new();
    let mut creds = None;
    let mut in_block = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("</") {
            in_block = false;
        } else if l.starts_with('<') {
            in_block = !l.contains("</");
        }
        let parts: Vec<&str> = l.split_whitespace().collect();
        let file_arg = parts.get(1).filter(|a| **a != "[inline]");
        match (in_block, parts.first().copied(), file_arg) {
            (false, Some(tag @ ("ca" | "cert" | "key" | "tls-auth" | "tls-crypt")), Some(f)) => {
                let content = std::fs::read_to_string(dir.join(f))
                    .map_err(|e| format!("{f} 을(를) 읽지 못했습니다: {e}"))?;
                out.push_str(&format!("<{tag}>\n{}\n</{tag}>\n", content.trim()));
                if tag == "tls-auth" {
                    if let Some(kd) = parts.get(2) {
                        out.push_str(&format!("key-direction {kd}\n"));
                    }
                }
            }
            (false, Some("auth-user-pass"), Some(f)) => {
                let content = std::fs::read_to_string(dir.join(f))
                    .map_err(|e| format!("{f} 을(를) 읽지 못했습니다: {e}"))?;
                let mut it = content.lines();
                if let (Some(u), Some(p)) = (it.next(), it.next()) {
                    creds = Some((u.trim().to_string(), p.trim_end().to_string()));
                }
                out.push_str("auth-user-pass\n");
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    Ok((out, creds))
}

// ---------------------------------------------------------------------------
// 공통 도우미
// ---------------------------------------------------------------------------

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

fn parse_v4(s: &str) -> Option<[u8; 4]> {
    s.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn unix_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug)]
enum Digest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    fn parse(name: &str) -> Result<Self, String> {
        match name.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Ok(Digest::Sha1),
            "SHA256" => Ok(Digest::Sha256),
            "SHA384" => Ok(Digest::Sha384),
            "SHA512" => Ok(Digest::Sha512),
            other => Err(format!("auth {other} 는 지원하지 않습니다")),
        }
    }
    fn algorithm(self) -> rhmac::Algorithm {
        match self {
            Digest::Sha1 => rhmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Digest::Sha256 => rhmac::HMAC_SHA256,
            Digest::Sha384 => rhmac::HMAC_SHA384,
            Digest::Sha512 => rhmac::HMAC_SHA512,
        }
    }
    fn len(self) -> usize {
        match self {
            Digest::Sha1 => 20,
            Digest::Sha256 => 32,
            Digest::Sha384 => 48,
            Digest::Sha512 => 64,
        }
    }
    fn key(self, material: &[u8]) -> rhmac::Key {
        rhmac::Key::new(self.algorithm(), &material[..self.len()])
    }
}

fn hmac_parts(key: &rhmac::Key, parts: &[&[u8]]) -> Vec<u8> {
    let mut c = rhmac::Context::with_key(key);
    for p in parts {
        c.update(p);
    }
    c.sign().as_ref().to_vec()
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

// ---------------------------------------------------------------------------
// VPN 서버 인증서 검증
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct OvpnVerifier {
    inner: Arc<WebPkiServerVerifier>,
    status: Arc<Mutex<String>>,
    /// true: 설정 파일의 CA 로 검증되지 않으면 연결 거부 (서버 이름은 보지 않음, OpenVPN 기본 동작과 같음)
    /// false: 결과만 기록하고 계속 (VPN Gate)
    strict: bool,
}

impl ServerCertVerifier for OvpnVerifier {
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
        let result = match result {
            // OpenVPN 은 인증서의 호스트 이름을 확인하지 않음 (CA 로만 확인)
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) if self.strict => Ok(ServerCertVerified::assertion()),
            r => r,
        };
        *self.status.lock().unwrap() = match &result {
            Ok(_) => "verified".to_string(),
            Err(e) => format!("not verified ({e})"),
        };
        if self.strict {
            result
        } else {
            Ok(ServerCertVerified::assertion())
        }
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

fn build_tls_config(
    cfg: &OvpnConfig,
    status: Arc<Mutex<String>>,
    strict: bool,
) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut cfg.ca_pem.as_bytes()) {
        let c = c.map_err(|e| format!("CA certificate: {e}"))?;
        roots.add(c).map_err(|e| format!("CA certificate: {e}"))?;
    }
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| format!("verifier: {e}"))?;
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(OvpnVerifier {
            inner,
            status,
            strict,
        }));
    match (&cfg.cert_pem, &cfg.key_pem) {
        (Some(cert), Some(key)) => {
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert.as_bytes())
                .collect::<Result<_, _>>()
                .map_err(|e| format!("client certificate: {e}"))?;
            let key = rustls_pemfile::private_key(&mut key.as_bytes())
                .map_err(|e| format!("client key: {e}"))?
                .ok_or("client key missing")?;
            let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
                .map_err(|e| format!("client key: {e}"))?;
            Ok(
                builder.with_client_cert_resolver(Arc::new(FixedClientCert(Arc::new(
                    rustls::sign::CertifiedKey::new(certs, signing_key),
                )))),
            )
        }
        _ => Ok(builder.with_no_client_auth()),
    }
}

// ---------------------------------------------------------------------------
// 전송 (TCP: 2바이트 길이 + 패킷 / UDP: 데이터그램 하나 = 패킷 하나)
// ---------------------------------------------------------------------------

enum Link {
    Tcp { s: TcpStream, rbuf: Vec<u8> },
    Udp(UdpSocket),
}

impl Link {
    fn open(addr: SocketAddr, udp: bool) -> Result<Link, String> {
        if udp {
            let bind: SocketAddr = if addr.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let s = UdpSocket::bind(bind).map_err(|e| format!("UDP: {e}"))?;
            s.connect(addr).map_err(|e| format!("UDP: {e}"))?;
            Ok(Link::Udp(s))
        } else {
            let s = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
                .map_err(|e| format!("TCP connect: {e}"))?;
            s.set_nodelay(true).ok();
            s.set_write_timeout(Some(Duration::from_secs(10))).ok();
            Ok(Link::Tcp {
                s,
                rbuf: Vec::new(),
            })
        }
    }

    fn is_udp(&self) -> bool {
        matches!(self, Link::Udp(_))
    }

    fn send(&mut self, pkt: &[u8]) -> Result<(), String> {
        match self {
            Link::Tcp { s, .. } => {
                let mut f = Vec::with_capacity(pkt.len() + 2);
                f.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
                f.extend_from_slice(pkt);
                s.write_all(&f).map_err(|e| format!("VPN send: {e}"))
            }
            Link::Udp(s) => s
                .send(pkt)
                .map(|_| ())
                .map_err(|e| format!("VPN send: {e}")),
        }
    }

    fn recv_until(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>, String> {
        let timed_out = |e: &io::Error| {
            e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut
        };
        match self {
            Link::Tcp { s, rbuf } => loop {
                if rbuf.len() >= 2 {
                    let n = u16::from_be_bytes([rbuf[0], rbuf[1]]) as usize;
                    if rbuf.len() >= 2 + n {
                        let pkt = rbuf[2..2 + n].to_vec();
                        rbuf.drain(..2 + n);
                        return Ok(Some(pkt));
                    }
                }
                let now = Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                s.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))))
                    .map_err(|e| e.to_string())?;
                let mut tmp = [0u8; 16384];
                match s.read(&mut tmp) {
                    Ok(0) => return Err("VPN server closed the connection".into()),
                    Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
                    Err(e) if timed_out(&e) => return Ok(None),
                    Err(e) => return Err(format!("VPN connection: {e}")),
                }
            },
            Link::Udp(s) => {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                s.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))))
                    .map_err(|e| e.to_string())?;
                let mut tmp = vec![0u8; 65536];
                match s.recv(&mut tmp) {
                    Ok(n) => {
                        tmp.truncate(n);
                        Ok(Some(tmp))
                    }
                    Err(e) if timed_out(&e) => Ok(None),
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                        Err("VPN 서버가 응답하지 않습니다 (UDP 포트 닫힘)".into())
                    }
                    Err(e) => Err(format!("VPN connection: {e}")),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 제어 채널 보호 (tls-auth / tls-crypt)
// ---------------------------------------------------------------------------

enum Wrap {
    None,
    Auth {
        digest: Digest,
        send: rhmac::Key,
        recv: rhmac::Key,
    },
    Crypt {
        enc: [u8; 32],
        send: rhmac::Key,
        dec: [u8; 32],
        recv: rhmac::Key,
    },
}

impl Wrap {
    fn new(cfg: &OvpnConfig) -> Result<Wrap, String> {
        if let Some(k) = &cfg.tls_crypt {
            // 클라이언트는 키 1 로 보내고 키 0 으로 받음
            let mut enc = [0u8; 32];
            enc.copy_from_slice(&k.cipher(1)[..32]);
            let mut dec = [0u8; 32];
            dec.copy_from_slice(&k.cipher(0)[..32]);
            return Ok(Wrap::Crypt {
                enc,
                send: rhmac::Key::new(rhmac::HMAC_SHA256, &k.hmac(1)[..32]),
                dec,
                recv: rhmac::Key::new(rhmac::HMAC_SHA256, &k.hmac(0)[..32]),
            });
        }
        if let Some((k, dir)) = &cfg.tls_auth {
            let digest = Digest::parse(&cfg.auth)?;
            // key-direction 1: 키 1 로 보내고 키 0 으로 받음 / 0: 반대 / 없음: 둘 다 키 0
            let (out, inn) = match dir {
                Some(1) => (1, 0),
                Some(0) => (0, 1),
                _ => (0, 0),
            };
            return Ok(Wrap::Auth {
                digest,
                send: digest.key(k.hmac(out)),
                recv: digest.key(k.hmac(inn)),
            });
        }
        Ok(Wrap::None)
    }

    /// 보낼 제어 패킷 (opcode + 세션 ID + body)을 보호해 전송 형식으로
    fn wrap(&self, op: u8, sid: &[u8; 8], body: &[u8], replay: &mut u32) -> Vec<u8> {
        let mut head = vec![op];
        head.extend_from_slice(sid);
        match self {
            Wrap::None => [head, body.to_vec()].concat(),
            Wrap::Auth { send, .. } => {
                let mut pt = replay.to_be_bytes().to_vec();
                *replay += 1;
                pt.extend_from_slice(&unix_time().to_be_bytes());
                let tag = hmac_parts(send, &[&pt, &head, body]);
                [head, tag, pt, body.to_vec()].concat()
            }
            Wrap::Crypt { enc, send, .. } => {
                head.extend_from_slice(&replay.to_be_bytes());
                *replay += 1;
                head.extend_from_slice(&unix_time().to_be_bytes());
                let tag = hmac_parts(send, &[&head, body]);
                let mut ct = body.to_vec();
                Aes256Ctr::new(enc.into(), tag[..16].into()).apply_keystream(&mut ct);
                [head, tag, ct].concat()
            }
        }
    }

    /// 받은 제어 패킷을 확인해 opcode + 세션 ID + body 로 되돌림
    fn unwrap(&self, p: &[u8]) -> Result<Vec<u8>, String> {
        if p.len() < 9 {
            return Err("short control packet".into());
        }
        match self {
            Wrap::None => Ok(p.to_vec()),
            Wrap::Auth { digest, recv, .. } => {
                let h = digest.len();
                if p.len() < 9 + h + 8 {
                    return Err("short tls-auth packet".into());
                }
                let (head, rest) = p.split_at(9);
                let (tag, rest) = rest.split_at(h);
                let (pt, body) = rest.split_at(8);
                if !ct_eq(&hmac_parts(recv, &[pt, head, body]), tag) {
                    return Err("tls-auth 확인 실패 (키 또는 key-direction 이 다름)".into());
                }
                Ok([head, body].concat())
            }
            Wrap::Crypt { dec, recv, .. } => {
                if p.len() < 17 + 32 {
                    return Err("short tls-crypt packet".into());
                }
                let (head, rest) = p.split_at(17);
                let (tag, ct) = rest.split_at(32);
                let mut body = ct.to_vec();
                Aes256Ctr::new(dec.into(), tag[..16].into()).apply_keystream(&mut body);
                if !ct_eq(&hmac_parts(recv, &[head, &body]), tag) {
                    return Err("tls-crypt 확인 실패 (키가 다름)".into());
                }
                Ok([&head[..9], &body].concat())
            }
        }
    }
}

struct Control {
    opcode: u8,
    sid: [u8; 8],
    acks: Vec<u32>,
    pid: Option<u32>,
    payload: Vec<u8>,
}

fn parse_control(p: &[u8]) -> Option<Control> {
    if p.len() < 10 {
        return None;
    }
    let opcode = p[0] >> 3;
    let mut sid = [0u8; 8];
    sid.copy_from_slice(&p[1..9]);
    let ack_len = p[9] as usize;
    let mut off = 10;
    let mut acks = Vec::with_capacity(ack_len);
    for _ in 0..ack_len {
        let b = p.get(off..off + 4)?;
        acks.push(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        off += 4;
    }
    if ack_len > 0 {
        off += 8; // 상대가 알고 있는 우리 세션 ID
    }
    let pid = if opcode != OP_ACK_V1 {
        let b = p.get(off..off + 4)?;
        off += 4;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    } else {
        None
    };
    Some(Control {
        opcode,
        sid,
        acks,
        pid,
        payload: p.get(off..)?.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// 데이터 채널
// ---------------------------------------------------------------------------

// 터널마다 하나만 만들므로 AEAD 키 크기 차이는 문제 되지 않음
#[allow(clippy::large_enum_variant)]
enum DataCipher {
    Cbc {
        bits: usize,
        enc: Vec<u8>,
        dec: Vec<u8>,
        digest: Digest,
        enc_mac: rhmac::Key,
        dec_mac: rhmac::Key,
    },
    Aead {
        enc: LessSafeKey,
        dec: LessSafeKey,
        enc_iv: [u8; 8],
        dec_iv: [u8; 8],
    },
}

impl DataCipher {
    /// key-method 2 로 만든 키 재료(256 바이트)에서 데이터 채널 키를 만듦.
    /// 키 0 = 클라이언트→서버, 키 1 = 서버→클라이언트. 각 키는 암호 64 + HMAC 64 바이트
    fn new(name: &str, auth: &str, km: &[u8]) -> Result<DataCipher, String> {
        let (enc_c, enc_h, dec_c, dec_h) = (&km[0..64], &km[64..128], &km[128..192], &km[192..256]);
        let aead_alg: Option<&'static aead::Algorithm> = match name {
            "AES-128-GCM" => Some(&aead::AES_128_GCM),
            "AES-256-GCM" => Some(&aead::AES_256_GCM),
            "CHACHA20-POLY1305" => Some(&aead::CHACHA20_POLY1305),
            _ => None,
        };
        if let Some(alg) = aead_alg {
            let n = alg.key_len();
            let key = |k: &[u8]| -> Result<LessSafeKey, String> {
                Ok(LessSafeKey::new(
                    UnboundKey::new(alg, &k[..n]).map_err(|_| "AEAD key")?,
                ))
            };
            let mut enc_iv = [0u8; 8];
            enc_iv.copy_from_slice(&enc_h[..8]);
            let mut dec_iv = [0u8; 8];
            dec_iv.copy_from_slice(&dec_h[..8]);
            return Ok(DataCipher::Aead {
                enc: key(enc_c)?,
                dec: key(dec_c)?,
                enc_iv,
                dec_iv,
            });
        }
        let bits = match name {
            "AES-128-CBC" => 128,
            "AES-192-CBC" => 192,
            "AES-256-CBC" => 256,
            other => return Err(format!("데이터 암호 {other} 는 지원하지 않습니다")),
        };
        let digest = Digest::parse(auth)?;
        Ok(DataCipher::Cbc {
            bits,
            enc: enc_c[..bits / 8].to_vec(),
            dec: dec_c[..bits / 8].to_vec(),
            digest,
            enc_mac: digest.key(enc_h),
            dec_mac: digest.key(dec_h),
        })
    }
}

fn cbc_encrypt(bits: usize, key: &[u8], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    match bits {
        128 => cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
            .expect("key")
            .encrypt_padded_vec_mut::<Pkcs7>(pt),
        192 => cbc::Encryptor::<Aes192>::new_from_slices(key, iv)
            .expect("key")
            .encrypt_padded_vec_mut::<Pkcs7>(pt),
        _ => cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
            .expect("key")
            .encrypt_padded_vec_mut::<Pkcs7>(pt),
    }
}

fn cbc_decrypt(bits: usize, key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    let r = match bits {
        128 => cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|e| format!("{e:?}"))?
            .decrypt_padded_vec_mut::<Pkcs7>(ct),
        192 => cbc::Decryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|e| format!("{e:?}"))?
            .decrypt_padded_vec_mut::<Pkcs7>(ct),
        _ => cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|e| format!("{e:?}"))?
            .decrypt_padded_vec_mut::<Pkcs7>(ct),
    };
    r.map_err(|_| "bad padding in data packet".to_string())
}

// fragment 헤더 (32비트): 종류 2비트 | 순번 8비트 | 조각 번호 5비트 | 크기
const FRAG_WHOLE: u32 = 0;
const FRAG_YES_NOTLAST: u32 = 1;
const FRAG_YES_LAST: u32 = 2;

// ---------------------------------------------------------------------------
// 터널
// ---------------------------------------------------------------------------

/// 서버가 알려 준 터널 주소 정보
#[derive(Clone, Debug)]
pub struct PushInfo {
    pub local_ip: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
    pub topology: String,
    pub cipher: String,
    pub peer_id: Option<u32>,
    pub dns: Vec<[u8; 4]>,
    pub compress: Compress,
}

struct Pending {
    opcode: u8,
    body: Vec<u8>,
    pid: u32,
    sent: Instant,
    tries: u32,
}

/// 접속 방법
pub struct ConnectOptions<'a> {
    pub remote: &'a Remote,
    /// TLS 서버 이름 (VPN Gate: 호스트.opengw.net)
    pub tls_name: &'a str,
    /// true 면 설정 파일의 CA 로 서버 인증서가 확인돼야 연결
    pub strict_verify: bool,
    pub credentials: Option<(&'a str, &'a str)>,
}

pub struct Tunnel {
    link: Link,
    wrap: Wrap,
    replay_pid: u32,
    local_sid: [u8; 8],
    remote_sid: Option<[u8; 8]>,
    next_pid: u32,
    next_remote_pid: u32,
    unacked: Vec<Pending>,
    reorder: BTreeMap<u32, Control>,
    tls: ClientConnection,
    plain: Vec<u8>,
    key_material: Option<Vec<u8>>,
    data: Option<DataCipher>,
    data_pid: u32,
    compress: Compress,
    fragment: bool,
    frags: HashMap<u8, BTreeMap<u8, Vec<u8>>>,
    inbox: VecDeque<Vec<u8>>,
    mtu: usize,
    pub push: Option<PushInfo>,
    /// VPN 서버 인증서 검증 결과 (DMM 과의 통신은 터널 안에서 별도 TLS 로 다시 검증됨)
    pub server_cert_status: String,
    pub server_options: String,
    /// 받은 데이터 패킷 수 (keepalive 포함) / 복호화에 실패한 수 (진단용)
    pub data_rx: u32,
    pub data_rx_errors: u32,
}

fn options_string(cfg: &OvpnConfig, udp: bool) -> String {
    let cipher = cfg.cipher.clone().unwrap_or_else(|| "AES-256-GCM".into());
    let keysize = match cipher.as_str() {
        c if c.starts_with("AES-128") => 128,
        c if c.starts_with("AES-192") => 192,
        _ => 256,
    };
    let mut s = format!(
        "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto {}",
        if udp { "UDPv4" } else { "TCPv4_CLIENT" }
    );
    if cfg.compress == Compress::Lzo {
        s.push_str(",comp-lzo");
    }
    s.push_str(&format!(
        ",cipher {cipher},auth {},keysize {keysize}",
        cfg.auth
    ));
    if cfg.tls_auth.is_some() {
        s.push_str(",tls-auth");
    }
    s.push_str(",key-method 2,tls-client");
    s
}

fn peer_info(cfg: &OvpnConfig) -> String {
    // 설정 파일의 data-ciphers 를 먼저, 이 클라이언트가 쓸 수 있는 것만
    let mut ciphers: Vec<&str> = cfg
        .data_ciphers
        .iter()
        .map(String::as_str)
        .chain(cfg.cipher.as_deref())
        .filter(|c| SUPPORTED_CIPHERS.contains(c))
        .collect();
    for c in SUPPORTED_CIPHERS {
        if !ciphers.contains(c) {
            ciphers.push(c);
        }
    }
    format!(
        "IV_VER=2.6.12\nIV_PLAT=win\nIV_PROTO=2\nIV_NCP=2\nIV_CIPHERS={}\nIV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\nIV_TCPNL=1\n",
        ciphers.join(":")
    )
}

impl Tunnel {
    /// VPN Gate 서버에 접속 (첫 번째 remote, 인증서는 결과만 기록)
    pub fn connect(
        cfg: &OvpnConfig,
        tls_name: &str,
        log: &mut dyn FnMut(String),
    ) -> Result<Tunnel, String> {
        let remote = cfg.remotes.first().ok_or("remote missing")?;
        Self::connect_with(
            cfg,
            &ConnectOptions {
                remote,
                tls_name,
                strict_verify: false,
                credentials: None,
            },
            log,
        )
    }

    /// VPN 서버에 접속해 터널 주소를 받을 때까지 진행
    pub fn connect_with(
        cfg: &OvpnConfig,
        opts: &ConnectOptions,
        log: &mut dyn FnMut(String),
    ) -> Result<Tunnel, String> {
        if cfg.auth_user_pass && opts.credentials.is_none() {
            return Err("VPN 아이디와 비밀번호가 필요합니다".into());
        }
        let addr = (opts.remote.host.as_str(), opts.remote.port)
            .to_socket_addrs()
            .map_err(|e| format!("{} 주소를 찾지 못했습니다: {e}", opts.remote.host))?
            .min_by_key(|a| !a.is_ipv4())
            .ok_or_else(|| format!("{} 주소를 찾지 못했습니다", opts.remote.host))?;
        let link = Link::open(addr, opts.remote.udp)?;
        log(format!(
            "{} connected to {addr}",
            if opts.remote.udp { "UDP" } else { "TCP" }
        ));

        let status = Arc::new(Mutex::new(String::from("not checked")));
        let tls_cfg = build_tls_config(cfg, status.clone(), opts.strict_verify)?;
        let name = ServerName::try_from(opts.tls_name.to_string())
            .map_err(|e| format!("server name: {e}"))?;
        let tls =
            ClientConnection::new(Arc::new(tls_cfg), name).map_err(|e| format!("TLS init: {e}"))?;

        let mtu = match cfg.fragment {
            Some(f) => DEFAULT_MTU.min(f.saturating_sub(100).max(576)),
            None => DEFAULT_MTU,
        };
        let mut t = Tunnel {
            link,
            wrap: Wrap::new(cfg)?,
            replay_pid: 1,
            local_sid: rand_bytes(),
            remote_sid: None,
            next_pid: 0,
            next_remote_pid: 0,
            unacked: Vec::new(),
            reorder: BTreeMap::new(),
            tls,
            plain: Vec::new(),
            key_material: None,
            data: None,
            data_pid: 1,
            compress: cfg.compress,
            fragment: cfg.fragment.is_some(),
            frags: HashMap::new(),
            inbox: VecDeque::new(),
            mtu,
            push: None,
            server_cert_status: String::new(),
            server_options: String::new(),
            data_rx: 0,
            data_rx_errors: 0,
        };

        // 1) 세션 시작
        t.send_control(OP_HARD_RESET_CLIENT_V2, &[])?;
        t.wait_for(Duration::from_secs(10), "no reply to session reset", |t| {
            Ok(t.remote_sid.is_some())
        })?;
        log("session reset acknowledged".to_string());

        // 2) 제어 채널 TLS
        t.flush_tls()?;
        t.wait_for(Duration::from_secs(20), "TLS handshake timed out", |t| {
            t.flush_tls()?;
            Ok(!t.tls.is_handshaking())
        })?;
        t.server_cert_status = status.lock().unwrap().clone();
        log(format!(
            "TLS handshake done ({:?}); VPN server certificate {}",
            t.tls
                .protocol_version()
                .map(|v| format!("{v:?}"))
                .unwrap_or_default(),
            t.server_cert_status
        ));

        // 3) key-method 2 키 교환 (아이디·비밀번호도 여기서 보냄)
        let pre_master: [u8; 48] = rand_bytes();
        let r1: [u8; 32] = rand_bytes();
        let r2: [u8; 32] = rand_bytes();
        let mut m = vec![0u8, 0, 0, 0, 2];
        m.extend_from_slice(&pre_master);
        m.extend_from_slice(&r1);
        m.extend_from_slice(&r2);
        write_string(&mut m, &options_string(cfg, opts.remote.udp));
        match opts.credentials {
            Some((u, p)) => {
                write_string(&mut m, u);
                write_string(&mut m, p);
            }
            None => m.extend_from_slice(&[0, 0, 0, 0]),
        }
        write_string(&mut m, &peer_info(cfg));
        t.tls
            .writer()
            .write_all(&m)
            .map_err(|e| format!("TLS write: {e}"))?;
        t.flush_tls()?;
        let mut randoms = None;
        t.wait_for(Duration::from_secs(15), "no key exchange reply", |t| {
            randoms = t.take_server_key_method()?;
            Ok(randoms.is_some())
        })?;
        let (sr1, sr2) = randoms.unwrap();
        t.key_material = Some(t.derive_key_material(&pre_master, &r1, &r2, &sr1, &sr2));
        log(format!(
            "key exchange done (server options: {})",
            t.server_options
        ));

        // 4) 터널 주소와 데이터 채널 설정 받기 (길면 push-continuation 으로 나뉘어 옴)
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut next_request = Instant::now();
        let mut options: Vec<String> = Vec::new();
        loop {
            let mut done = false;
            while let Some(r) = t.take_control_message("PUSH_REPLY")? {
                let body = r.trim_start_matches("PUSH_REPLY").trim_start_matches(',');
                let mut more = false;
                for o in body.split(',') {
                    if o.trim() == "push-continuation 2" {
                        more = true;
                    } else if !o.trim().starts_with("push-continuation") {
                        options.push(o.trim().to_string());
                    }
                }
                done = !more;
            }
            if done {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("no PUSH_REPLY from server".into());
            }
            if now >= next_request && options.is_empty() {
                t.tls
                    .writer()
                    .write_all(b"PUSH_REQUEST\0")
                    .map_err(|e| format!("TLS write: {e}"))?;
                t.flush_tls()?;
                next_request = now + Duration::from_secs(3);
            }
            t.retransmit()?;
            if let Some(p) = t
                .link
                .recv_until((now + Duration::from_millis(300)).min(deadline))?
            {
                t.handle_packet(p)?;
            }
        }
        t.apply_push(cfg, &options)?;
        let push = t.push.clone().unwrap();
        log(format!(
            "tunnel address {}/{} (gateway {:?}, cipher {}, peer-id {:?}, compress {:?})",
            std::net::Ipv4Addr::from(push.local_ip),
            push.prefix_len,
            push.gateway.map(std::net::Ipv4Addr::from),
            push.cipher,
            push.peer_id,
            push.compress
        ));
        Ok(t)
    }

    /// 조건이 맞을 때까지 패킷을 받으며 기다림 (UDP 면 재전송도 함)
    fn wait_for(
        &mut self,
        limit: Duration,
        timeout_msg: &str,
        mut done: impl FnMut(&mut Tunnel) -> Result<bool, String>,
    ) -> Result<(), String> {
        let deadline = Instant::now() + limit;
        loop {
            if done(self)? {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(timeout_msg.to_string());
            }
            self.retransmit()?;
            if let Some(p) = self
                .link
                .recv_until((now + Duration::from_millis(300)).min(deadline))?
            {
                self.handle_packet(p)?;
            }
        }
    }

    // --- 제어 채널 ---

    fn send_raw(&mut self, opcode: u8, body: &[u8]) -> Result<(), String> {
        let pkt = self
            .wrap
            .wrap(opcode << 3, &self.local_sid, body, &mut self.replay_pid);
        self.link.send(&pkt)
    }

    /// 확인 응답이 필요한 제어 패킷 보내기
    fn send_control(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let pid = self.next_pid;
        self.next_pid += 1;
        let mut body = Vec::with_capacity(5 + payload.len());
        body.push(0); // 확인 응답은 P_ACK_V1 로 따로 보냄
        body.extend_from_slice(&pid.to_be_bytes());
        body.extend_from_slice(payload);
        self.send_raw(opcode, &body)?;
        if self.link.is_udp() {
            self.unacked.push(Pending {
                opcode,
                body,
                pid,
                sent: Instant::now(),
                tries: 1,
            });
        }
        Ok(())
    }

    fn send_ack(&mut self, pid: u32) -> Result<(), String> {
        let Some(remote) = self.remote_sid else {
            return Ok(());
        };
        let mut body = Vec::with_capacity(13);
        body.push(1);
        body.extend_from_slice(&pid.to_be_bytes());
        body.extend_from_slice(&remote);
        self.send_raw(OP_ACK_V1, &body)
    }

    /// UDP 에서 확인 응답이 없는 제어 패킷 다시 보내기
    fn retransmit(&mut self) -> Result<(), String> {
        let now = Instant::now();
        let mut due = Vec::new();
        for p in &mut self.unacked {
            if now.duration_since(p.sent) >= RETRANSMIT_AFTER {
                if p.tries >= 12 {
                    return Err("VPN 서버가 응답하지 않습니다".into());
                }
                p.sent = now;
                p.tries += 1;
                due.push((p.opcode, p.body.clone()));
            }
        }
        for (op, body) in due {
            self.send_raw(op, &body)?;
        }
        Ok(())
    }

    fn flush_tls(&mut self) -> Result<(), String> {
        while self.tls.wants_write() {
            let mut out = Vec::new();
            self.tls
                .write_tls(&mut out)
                .map_err(|e| format!("TLS write: {e}"))?;
            for chunk in out.chunks(CONTROL_CHUNK) {
                self.send_control(OP_CONTROL_V1, chunk)?;
            }
        }
        Ok(())
    }

    fn handle_packet(&mut self, p: Vec<u8>) -> Result<(), String> {
        if p.is_empty() {
            return Ok(());
        }
        let opcode = p[0] >> 3;
        if opcode == OP_DATA_V1 || opcode == OP_DATA_V2 {
            let r = self.decrypt_data(&p);
            match &r {
                Ok(Some(_)) => self.data_rx += 1,
                Err(_) => self.data_rx_errors += 1,
                _ => {}
            }
            if let Some(ip) = r? {
                if ip.as_slice() != PING_MAGIC {
                    self.inbox.push_back(ip);
                }
            }
            return Ok(());
        }
        if p[0] & 7 != 0 {
            return Ok(()); // 다른 키 번호 (재협상) - 쓰지 않음
        }
        let raw = match self.wrap.unwrap(&p) {
            Ok(r) => r,
            Err(e) if self.remote_sid.is_none() => return Err(e),
            Err(_) => return Ok(()), // 연결 뒤 들어온 깨진 패킷은 버림
        };
        let c = parse_control(&raw).ok_or("malformed control packet")?;
        if !c.acks.is_empty() {
            self.unacked.retain(|u| !c.acks.contains(&u.pid));
        }
        let Some(pid) = c.pid else {
            return Ok(()); // P_ACK_V1
        };
        if self.remote_sid.is_none() {
            if c.opcode != OP_HARD_RESET_SERVER_V2 {
                return Ok(());
            }
            self.remote_sid = Some(c.sid);
        }
        self.send_ack(pid)?;
        if pid < self.next_remote_pid {
            return Ok(()); // 재전송된 중복 패킷
        }
        self.reorder.insert(pid, c);
        while let Some(c) = self.reorder.remove(&self.next_remote_pid) {
            self.next_remote_pid += 1;
            if c.opcode == OP_CONTROL_V1 {
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
            } else if c.opcode == OP_CONTROL_SOFT_RESET_V1 {
                // 재협상 요청은 무시 (짧게 쓰고 끊으므로)
            }
        }
        Ok(())
    }

    /// 서버의 key-method 2 응답에서 난수 두 개를 꺼냄
    fn take_server_key_method(&mut self) -> Result<Option<ServerRandoms>, String> {
        let p = &self.plain;
        if p.len() < 71 {
            if let Some(pos) = p.iter().position(|&b| b == 0) {
                if p.starts_with(b"AUTH_FAILED") {
                    let msg = String::from_utf8_lossy(&p[..pos]).into_owned();
                    return Err(format!("server refused: {msg}"));
                }
            }
            return Ok(None);
        }
        if p[0..4] != [0, 0, 0, 0] || p[4] != 2 {
            if p.starts_with(b"AUTH_FAILED") {
                let end = p.iter().position(|&b| b == 0).unwrap_or(p.len());
                return Err(format!(
                    "server refused: {}",
                    String::from_utf8_lossy(&p[..end])
                ));
            }
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
        // 서버가 보낸 아이디·비밀번호·peer-info 칸(보통 비어 있음)은 건너뜀
        let mut off = 71 + olen;
        for _ in 0..3 {
            if p.len() >= off + 2 {
                let n = u16::from_be_bytes([p[off], p[off + 1]]) as usize;
                if p.len() >= off + 2 + n && (n == 0 || p[off + 1 + n] == 0) {
                    off += 2 + n;
                    continue;
                }
            }
            break;
        }
        self.plain.drain(..off);
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

    fn derive_key_material(
        &self,
        pre: &[u8; 48],
        cr1: &[u8; 32],
        cr2: &[u8; 32],
        sr1: &[u8; 32],
        sr2: &[u8; 32],
    ) -> Vec<u8> {
        let mut seed = b"OpenVPN master secret".to_vec();
        seed.extend_from_slice(cr1);
        seed.extend_from_slice(sr1);
        let master = prf(pre, &seed, 48);
        let mut seed = b"OpenVPN key expansion".to_vec();
        seed.extend_from_slice(cr2);
        seed.extend_from_slice(sr2);
        seed.extend_from_slice(&self.local_sid);
        seed.extend_from_slice(&self.remote_sid.unwrap_or_default());
        prf(&master, &seed, 256)
    }

    fn apply_push(&mut self, cfg: &OvpnConfig, options: &[String]) -> Result<(), String> {
        let mut ip = None;
        let mut second = None;
        let mut gw = None;
        let mut topology = String::from("net30");
        let mut cipher = cfg.cipher.clone();
        let mut auth = cfg.auth.clone();
        let mut peer_id = None;
        let mut dns = Vec::new();
        for opt in options {
            let parts: Vec<&str> = opt.split_whitespace().collect();
            match parts.first().copied() {
                Some("ifconfig") => {
                    ip = parts.get(1).and_then(|s| parse_v4(s));
                    second = parts.get(2).and_then(|s| parse_v4(s));
                }
                Some("route-gateway") => gw = parts.get(1).and_then(|s| parse_v4(s)),
                Some("topology") => topology = parts.get(1).copied().unwrap_or("").to_string(),
                Some("comp-lzo") => self.compress = Compress::Lzo,
                Some("compress") => {
                    self.compress = if parts.get(1) == Some(&"stub-v2") {
                        Compress::StubV2
                    } else {
                        Compress::Stub
                    }
                }
                Some("cipher") => cipher = parts.get(1).map(|c| c.to_ascii_uppercase()),
                Some("auth") => {
                    if let Some(a) = parts.get(1) {
                        auth = a.to_ascii_uppercase();
                    }
                }
                Some("peer-id") => peer_id = parts.get(1).and_then(|n| n.parse().ok()),
                Some("dhcp-option") if parts.get(1) == Some(&"DNS") => {
                    if let Some(a) = parts.get(2).and_then(|s| parse_v4(s)) {
                        dns.push(a);
                    }
                }
                Some("key-derivation") => {
                    return Err("server requires key-derivation tls-ekm (not supported)".into())
                }
                _ => {}
            }
        }
        let cipher = cipher
            .ok_or("데이터 암호가 정해지지 않았습니다 (BF-CBC 는 지원하지 않습니다)".to_string())?;
        let km = self.key_material.as_ref().ok_or("no key material")?;
        self.data = Some(DataCipher::new(&cipher, &auth, km)?);
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
            cipher,
            peer_id,
            dns,
            compress: self.compress,
        });
        Ok(())
    }

    // --- 데이터 채널 ---

    fn data_header(&self) -> Vec<u8> {
        match self.push.as_ref().and_then(|p| p.peer_id) {
            Some(id) => {
                let b = id.to_be_bytes();
                vec![OP_DATA_V2 << 3, b[1], b[2], b[3]]
            }
            None => vec![OP_DATA_V1 << 3],
        }
    }

    fn decrypt_data(&mut self, p: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let Some(data) = self.data.as_ref() else {
            return Ok(None);
        };
        let v2 = p[0] >> 3 == OP_DATA_V2;
        let off = if v2 { 4 } else { 1 };
        let inner = match data {
            DataCipher::Cbc {
                bits,
                dec,
                digest,
                dec_mac,
                ..
            } => {
                let h = digest.len();
                if p.len() < off + h + 16 + 16 {
                    return Err("short data packet".into());
                }
                let (tag, rest) = p[off..].split_at(h);
                if !ct_eq(&hmac_parts(dec_mac, &[rest]), tag) {
                    return Err("data packet failed authentication (key mismatch)".into());
                }
                let (iv, ct) = rest.split_at(16);
                let plain = cbc_decrypt(*bits, dec, iv, ct)?;
                if plain.len() < 4 {
                    return Err("short data plaintext".into());
                }
                plain[4..].to_vec()
            }
            DataCipher::Aead { dec, dec_iv, .. } => {
                if p.len() < off + 4 + 16 {
                    return Err("short data packet".into());
                }
                let pid = &p[off..off + 4];
                let tag = &p[off + 4..off + 20];
                let mut buf = [&p[off + 20..], tag].concat();
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(pid);
                nonce[4..].copy_from_slice(dec_iv);
                let aad = if v2 {
                    [&p[..4], pid].concat()
                } else {
                    pid.to_vec()
                };
                let plain = dec
                    .open_in_place(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(aad),
                        &mut buf,
                    )
                    .map_err(|_| "data packet failed authentication (key mismatch)")?;
                plain.to_vec()
            }
        };
        let Some(inner) = self.defragment(inner)? else {
            return Ok(None);
        };
        self.decompress(inner).map(Some)
    }

    fn defragment(&mut self, mut b: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        if !self.fragment {
            return Ok(Some(b));
        }
        if b.len() < 4 {
            return Err("short fragment".into());
        }
        let h = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        b.drain(..4);
        let kind = h & 3;
        let seq = ((h >> 2) & 0xff) as u8;
        let id = ((h >> 10) & 0x1f) as u8;
        match kind {
            FRAG_WHOLE => Ok(Some(b)),
            FRAG_YES_NOTLAST => {
                if self.frags.len() > 16 {
                    self.frags.clear();
                }
                self.frags.entry(seq).or_default().insert(id, b);
                Ok(None)
            }
            FRAG_YES_LAST => {
                let mut parts = self.frags.remove(&seq).unwrap_or_default();
                parts.insert(id, b);
                if parts.len() != id as usize + 1 {
                    return Ok(None); // 조각이 빠짐 - 버림 (TCP 가 다시 보냄)
                }
                Ok(Some(parts.into_values().flatten().collect()))
            }
            _ => Ok(None), // FRAG_TEST
        }
    }

    fn decompress(&self, b: Vec<u8>) -> Result<Vec<u8>, String> {
        if self.compress == Compress::None || b.is_empty() {
            return Ok(b);
        }
        match b[0] {
            0xFA => Ok(b[1..].to_vec()),
            0xFB if b.len() >= 2 => {
                let mut v = b;
                let last = v.pop().unwrap();
                v[0] = last;
                Ok(v)
            }
            0x50 if self.compress == Compress::StubV2 && b.len() >= 2 => {
                if b[1] != 0 {
                    return Err("compressed data packet (not supported)".into());
                }
                Ok(b[2..].to_vec())
            }
            x if self.compress == Compress::StubV2 || x >> 4 == 4 => Ok(b),
            x => Err(format!("compressed data packet (0x{x:02x}) not supported")),
        }
    }

    fn frame_inner(&self, ip: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(ip.len() + 8);
        if self.fragment {
            v.extend_from_slice(&FRAG_WHOLE.to_be_bytes());
        }
        match self.compress {
            Compress::None => v.extend_from_slice(ip),
            Compress::Lzo => {
                v.push(0xFA);
                v.extend_from_slice(ip);
            }
            Compress::Stub => {
                if let Some((first, rest)) = ip.split_first() {
                    v.push(0xFB);
                    v.extend_from_slice(rest);
                    v.push(*first);
                }
            }
            Compress::StubV2 => {
                if ip.first() == Some(&0x50) {
                    v.extend_from_slice(&[0x50, 0x00]);
                }
                v.extend_from_slice(ip);
            }
        }
        v
    }

    /// IP 패킷 하나를 암호화해 서버로 보냄
    pub fn send_ip(&mut self, ip: &[u8]) -> Result<(), String> {
        let pid = self.data_pid;
        self.data_pid = self.data_pid.wrapping_add(1);
        let inner = self.frame_inner(ip);
        let header = self.data_header();
        let data = self.data.as_ref().ok_or("data channel not ready")?;
        let pkt = match data {
            DataCipher::Cbc {
                bits, enc, enc_mac, ..
            } => {
                let mut plain = Vec::with_capacity(inner.len() + 4);
                plain.extend_from_slice(&pid.to_be_bytes());
                plain.extend_from_slice(&inner);
                let iv: [u8; 16] = rand_bytes();
                let ct = cbc_encrypt(*bits, enc, &iv, &plain);
                let tag = hmac_parts(enc_mac, &[&iv, &ct]);
                [header, tag, iv.to_vec(), ct].concat()
            }
            DataCipher::Aead { enc, enc_iv, .. } => {
                let pidb = pid.to_be_bytes();
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(&pidb);
                nonce[4..].copy_from_slice(enc_iv);
                let aad = if header.len() == 4 {
                    [&header[..], &pidb].concat()
                } else {
                    pidb.to_vec()
                };
                let mut buf = inner;
                let tag = enc
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(aad),
                        &mut buf,
                    )
                    .map_err(|_| "encrypt failed")?;
                [header, pidb.to_vec(), tag.as_ref().to_vec(), buf].concat()
            }
        };
        self.link.send(&pkt)
    }

    /// 서버에서 온 패킷을 최대 `wait` 동안 기다려 처리
    pub fn pump(&mut self, wait: Duration) -> Result<(), String> {
        let mut deadline = Instant::now() + wait;
        for _ in 0..256 {
            match self.link.recv_until(deadline)? {
                Some(p) => {
                    // 연결 뒤에는 깨진 데이터 패킷 하나로 전체를 끊지 않음
                    if let Err(e) = self.handle_packet(p) {
                        if !e.contains("authentication") && !e.contains("padding") {
                            return Err(e);
                        }
                    }
                }
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

impl IpTunnel for Tunnel {
    fn address(&self) -> TunnelAddr {
        let p = self.push.as_ref().expect("connected tunnel");
        TunnelAddr {
            local_ip: p.local_ip,
            prefix_len: p.prefix_len,
            gateway: p.gateway,
            mtu: self.mtu,
            dns: p.dns.clone(),
        }
    }
    fn send_ip(&mut self, ip: &[u8]) -> Result<(), String> {
        Tunnel::send_ip(self, ip)
    }
    fn pump(&mut self, wait: Duration) -> Result<(), String> {
        Tunnel::pump(self, wait)
    }
    fn take_inbound(&mut self) -> Option<Vec<u8>> {
        Tunnel::take_inbound(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_roundtrip_tls_crypt() {
        // 서버 쪽은 키 방향이 반대이므로, 키 0/1 을 바꾼 정적 키로 서버를 흉내 냄
        let mut raw = [0u8; 256];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut swapped = [0u8; 256];
        swapped[..128].copy_from_slice(&raw[128..]);
        swapped[128..].copy_from_slice(&raw[..128]);
        let mk = |k: [u8; 256]| OvpnConfig {
            remotes: vec![],
            remote_random: false,
            cipher: None,
            data_ciphers: vec![],
            auth: "SHA256".into(),
            ca_pem: String::new(),
            cert_pem: None,
            key_pem: None,
            tls_auth: None,
            tls_crypt: Some(StaticKey(k)),
            auth_user_pass: false,
            compress: Compress::None,
            fragment: None,
        };
        let client = Wrap::new(&mk(raw)).unwrap();
        let server = Wrap::new(&mk(swapped)).unwrap();
        let mut pid = 1;
        let sid = [9u8; 8];
        let pkt = client.wrap(OP_CONTROL_V1 << 3, &sid, b"hello body", &mut pid);
        let back = server.unwrap(&pkt).unwrap();
        assert_eq!(&back[9..], b"hello body");
        assert!(client.unwrap(&pkt).is_err());
    }

    #[test]
    fn wrap_roundtrip_tls_auth() {
        let mut raw = [0u8; 256];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i * 7) as u8;
        }
        let mk = |dir| OvpnConfig {
            remotes: vec![],
            remote_random: false,
            cipher: None,
            data_ciphers: vec![],
            auth: "SHA512".into(),
            ca_pem: String::new(),
            cert_pem: None,
            key_pem: None,
            tls_auth: Some((StaticKey(raw), Some(dir))),
            tls_crypt: None,
            auth_user_pass: false,
            compress: Compress::None,
            fragment: None,
        };
        let client = Wrap::new(&mk(1)).unwrap();
        let server = Wrap::new(&mk(0)).unwrap();
        let mut pid = 1;
        let pkt = client.wrap(OP_ACK_V1 << 3, &[1; 8], b"abc", &mut pid);
        assert_eq!(&server.unwrap(&pkt).unwrap()[9..], b"abc");
    }
}
