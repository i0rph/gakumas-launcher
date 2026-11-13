//! WireGuard 클라이언트 (사용자 공간, boringtun)
//!
//! 가상 네트워크 장치를 만들지 않고, UDP 소켓 하나로 WireGuard 서버와 통신합니다.
//! 복호화한 IP 패킷은 사용자 공간 TCP/IP 스택(netstack)이 처리합니다.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::netstack::{IpTunnel, TunnelAddr};

/// WireGuard 기본 MTU (1420) 보다 조금 작게 잡아 TCP 세그먼트가 잘리지 않게 함
const DEFAULT_MTU: usize = 1380;
const BUF: usize = 65536;

#[derive(Clone)]
pub struct WgConfig {
    private_key: [u8; 32],
    peer_public: [u8; 32],
    preshared: Option<[u8; 32]>,
    pub address: [u8; 4],
    pub prefix_len: u8,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub keepalive: Option<u16>,
    pub dns: Vec<[u8; 4]>,
    pub mtu: usize,
}

impl std::fmt::Debug for WgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgConfig")
            .field(
                "endpoint",
                &format!("{}:{}", self.endpoint_host, self.endpoint_port),
            )
            .finish_non_exhaustive()
    }
}

fn key32(v: &str, what: &str) -> Result<[u8; 32], String> {
    let b = base64::engine::general_purpose::STANDARD
        .decode(v.trim())
        .map_err(|_| format!("{what} 형식이 올바르지 않습니다"))?;
    b.try_into()
        .map_err(|_| format!("{what} 길이가 올바르지 않습니다"))
}

impl WgConfig {
    /// WireGuard .conf 해석 ([Interface] PrivateKey/Address/MTU, [Peer] PublicKey/PresharedKey/Endpoint/PersistentKeepalive)
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut section = String::new();
        let mut private_key = None;
        let mut peer_public = None;
        let mut preshared = None;
        let mut address = None;
        let mut endpoint = None;
        let mut keepalive = None;
        let mut mtu = None;
        let mut dns = Vec::new();
        let mut peers = 0;
        for line in text.lines() {
            let l = line.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            if l.starts_with('[') {
                section = l
                    .trim_matches(|c| c == '[' || c == ']')
                    .to_ascii_lowercase();
                if section == "peer" {
                    peers += 1;
                }
                continue;
            }
            let Some((k, v)) = l.split_once('=') else {
                continue;
            };
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match (section.as_str(), k.as_str()) {
                ("interface", "privatekey") => private_key = Some(key32(v, "PrivateKey")?),
                ("interface", "address") => {
                    // IPv4 주소만 씀 (IPv6 는 이 프로그램이 쓰지 않음)
                    address = v.split(',').map(str::trim).find_map(|a| {
                        let (ip, len) = a.split_once('/').unwrap_or((a, "32"));
                        let ip: std::net::Ipv4Addr = ip.parse().ok()?;
                        Some((ip.octets(), len.parse::<u8>().ok()?.min(32)))
                    });
                }
                ("interface", "mtu") => mtu = v.parse::<usize>().ok(),
                ("interface", "dns") => {
                    dns = v
                        .split(',')
                        .filter_map(|a| a.trim().parse::<std::net::Ipv4Addr>().ok())
                        .map(|a| a.octets())
                        .collect()
                }
                ("peer", "publickey") if peers == 1 => peer_public = Some(key32(v, "PublicKey")?),
                ("peer", "presharedkey") if peers == 1 => {
                    preshared = Some(key32(v, "PresharedKey")?)
                }
                ("peer", "endpoint") if peers == 1 => endpoint = Some(v.to_string()),
                ("peer", "persistentkeepalive") if peers == 1 => {
                    keepalive = v.parse::<u16>().ok().filter(|n| *n > 0)
                }
                _ => {}
            }
        }
        let (address, prefix_len) = address.ok_or("Address 에 IPv4 주소가 없습니다")?;
        let endpoint = endpoint.ok_or("Endpoint (서버 주소)가 없습니다")?;
        let (host, port) = endpoint
            .rsplit_once(':')
            .ok_or("Endpoint 에 포트가 없습니다")?;
        Ok(WgConfig {
            private_key: private_key.ok_or("PrivateKey 가 없습니다")?,
            peer_public: peer_public.ok_or("[Peer] PublicKey 가 없습니다")?,
            preshared,
            address,
            prefix_len,
            endpoint_host: host.trim_matches(|c| c == '[' || c == ']').to_string(),
            endpoint_port: port
                .parse()
                .map_err(|_| "Endpoint 포트가 올바르지 않습니다")?,
            keepalive,
            dns,
            mtu: mtu.map_or(DEFAULT_MTU, |m| {
                m.saturating_sub(40).clamp(576, DEFAULT_MTU)
            }),
        })
    }
}

pub struct WgTunnel {
    sock: UdpSocket,
    peer: SocketAddr,
    tunn: Tunn,
    inbox: VecDeque<Vec<u8>>,
    addr: TunnelAddr,
    last_timers: Instant,
    buf: Vec<u8>,
}

impl WgTunnel {
    /// 서버와 핸드셰이크를 마칠 때까지 진행
    pub fn connect(cfg: &WgConfig, log: &mut dyn FnMut(String)) -> Result<WgTunnel, String> {
        let peer = (cfg.endpoint_host.as_str(), cfg.endpoint_port)
            .to_socket_addrs()
            .map_err(|e| format!("{} 주소를 찾지 못했습니다: {e}", cfg.endpoint_host))?
            .min_by_key(|a| !a.is_ipv4())
            .ok_or_else(|| format!("{} 주소를 찾지 못했습니다", cfg.endpoint_host))?;
        let bind: SocketAddr = if peer.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).map_err(|e| format!("UDP: {e}"))?;
        sock.connect(peer).map_err(|e| format!("UDP: {e}"))?;
        let mut idx = [0u8; 3];
        getrandom::getrandom(&mut idx).map_err(|e| e.to_string())?;
        let tunn = Tunn::new(
            StaticSecret::from(cfg.private_key),
            PublicKey::from(cfg.peer_public),
            cfg.preshared,
            cfg.keepalive,
            u32::from_le_bytes([idx[0], idx[1], idx[2], 0]),
            None,
        );
        let mut t = WgTunnel {
            sock,
            peer,
            tunn,
            inbox: VecDeque::new(),
            addr: TunnelAddr {
                local_ip: cfg.address,
                prefix_len: cfg.prefix_len,
                gateway: None,
                mtu: cfg.mtu,
                dns: cfg.dns.clone(),
            },
            last_timers: Instant::now(),
            buf: vec![0u8; BUF],
        };
        log(format!("UDP ready for {peer}"));

        // 핸드셰이크: 처음 보내고, 응답이 없으면 2초마다 다시
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut next_init = Instant::now();
        let mut sent = false;
        while t.tunn.time_since_last_handshake().is_none() {
            let now = Instant::now();
            if now >= deadline {
                return Err(
                    "WireGuard 서버가 응답하지 않습니다 (키가 맞지 않거나 UDP 가 막혀 있음)".into(),
                );
            }
            if now >= next_init {
                let force = sent;
                sent = true;
                match t.tunn.format_handshake_initiation(&mut t.buf, force) {
                    TunnResult::WriteToNetwork(p) => {
                        t.sock.send(p).map_err(|e| format!("VPN send: {e}"))?;
                    }
                    TunnResult::Err(e) => return Err(format!("WireGuard: {e:?}")),
                    _ => {}
                }
                next_init = now + Duration::from_secs(2);
            }
            t.recv_once((now + Duration::from_millis(200)).min(deadline))?;
        }
        log("WireGuard handshake done".to_string());
        Ok(t)
    }

    /// 데이터그램 하나를 기다려 처리. 받은 게 있으면 true
    fn recv_once(&mut self, deadline: Instant) -> Result<bool, String> {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        self.sock
            .set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))))
            .map_err(|e| e.to_string())?;
        let mut dgram = vec![0u8; BUF];
        let n = match self.sock.recv(&mut dgram) {
            Ok(n) => n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(false)
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                return Err("WireGuard 서버가 응답하지 않습니다 (UDP 포트 닫힘)".into())
            }
            Err(e) => return Err(format!("VPN connection: {e}")),
        };
        let src: Option<IpAddr> = Some(self.peer.ip());
        let mut first = true;
        loop {
            let input: &[u8] = if first { &dgram[..n] } else { &[] };
            match self.tunn.decapsulate(src, input, &mut self.buf) {
                TunnResult::WriteToNetwork(p) => {
                    self.sock.send(p).map_err(|e| format!("VPN send: {e}"))?;
                    first = false; // 대기 중인 패킷이 더 있으면 이어서 보냄
                }
                TunnResult::WriteToTunnelV4(p, _) => {
                    self.inbox.push_back(p.to_vec());
                    break;
                }
                TunnResult::WriteToTunnelV6(..) | TunnResult::Done => break,
                TunnResult::Err(_) => break, // 깨진 패킷 하나는 버림
            }
        }
        Ok(true)
    }

    fn tick_timers(&mut self) -> Result<(), String> {
        if self.last_timers.elapsed() < Duration::from_millis(250) {
            return Ok(());
        }
        self.last_timers = Instant::now();
        match self.tunn.update_timers(&mut self.buf) {
            TunnResult::WriteToNetwork(p) => {
                self.sock.send(p).map_err(|e| format!("VPN send: {e}"))?;
            }
            TunnResult::Err(boringtun::noise::errors::WireGuardError::ConnectionExpired) => {
                return Err("WireGuard 연결이 끊어졌습니다".into())
            }
            _ => {}
        }
        Ok(())
    }
}

impl IpTunnel for WgTunnel {
    fn address(&self) -> TunnelAddr {
        self.addr.clone()
    }

    fn send_ip(&mut self, ip: &[u8]) -> Result<(), String> {
        let mut out = vec![0u8; ip.len() + 256];
        match self.tunn.encapsulate(ip, &mut out) {
            TunnResult::WriteToNetwork(p) => {
                self.sock.send(p).map_err(|e| format!("VPN send: {e}"))?;
                Ok(())
            }
            TunnResult::Err(e) => Err(format!("WireGuard: {e:?}")),
            _ => Ok(()),
        }
    }

    fn pump(&mut self, wait: Duration) -> Result<(), String> {
        self.tick_timers()?;
        let mut deadline = Instant::now() + wait;
        for _ in 0..256 {
            if !self.recv_once(deadline)? {
                break;
            }
            deadline = Instant::now() + Duration::from_millis(1);
        }
        Ok(())
    }

    fn take_inbound(&mut self) -> Option<Vec<u8>> {
        self.inbox.pop_front()
    }
}
