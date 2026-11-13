//! 터널 위에서 도는 사용자 공간 TCP/IP 스택 (smoltcp)
//!
//! Windows 네트워크 설정을 건드리지 않고, 이 프로그램이 여는 TCP 연결만 VPN 터널을 탑니다.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::http;
/// 사용자 공간 TCP/IP 스택 아래에 놓이는 VPN 터널 (OpenVPN, WireGuard)
pub trait IpTunnel: Send {
    fn address(&self) -> TunnelAddr;
    /// IP 패킷 하나를 암호화해 보냄
    fn send_ip(&mut self, ip: &[u8]) -> Result<(), String>;
    /// 서버에서 온 패킷을 최대 `wait` 동안 기다려 처리
    fn pump(&mut self, wait: Duration) -> Result<(), String>;
    /// 복호화된 IP 패킷 하나를 꺼냄
    fn take_inbound(&mut self) -> Option<Vec<u8>>;
}

/// 터널 안에서 이 프로그램이 쓰는 주소
#[derive(Clone, Debug)]
pub struct TunnelAddr {
    pub local_ip: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
    /// 터널 안 IP 패킷 최대 크기. 작게 잡아 TCP 세그먼트가 터널에서 잘리지 않게 함
    pub mtu: usize,
    /// 터널이 알려 준 DNS 서버 (OpenVPN dhcp-option DNS, WireGuard DNS)
    pub dns: Vec<[u8; 4]>,
}

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for RxTok {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

impl<'a> phy::TxToken for TxTok<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a>
        = RxTok
    where
        Self: 'a;
    type TxToken<'a>
        = TxTok<'a>
    where
        Self: 'a;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxTok(p), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

pub struct TunnelStack {
    tun: Box<dyn IpTunnel>,
    dev: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    epoch: Instant,
    /// 터널 안에서 찾은 주소 (일본 쪽에서 본 주소)
    hosts: HashMap<String, Ipv4Addr>,
    dns: Vec<[u8; 4]>,
}

/// DNS-over-TCP 질의 (2바이트 길이 + DNS 메시지, A 레코드)
fn dns_query(host: &str, id: [u8; 2]) -> Vec<u8> {
    let mut m = vec![id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.trim_end_matches('.').split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    [(m.len() as u16).to_be_bytes().to_vec(), m].concat()
}

fn dns_tcp_complete(r: &[u8]) -> bool {
    r.len() >= 2 && r.len() >= 2 + u16::from_be_bytes([r[0], r[1]]) as usize
}

/// DNS 응답 이름 건너뛰기 (압축 포인터 포함)
fn dns_skip_name(m: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *m.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(off + 2);
        }
        off += 1 + len;
    }
}

/// DNS-over-TCP 응답에서 첫 A 레코드
fn dns_answer(raw: &[u8], id: [u8; 2]) -> Result<Ipv4Addr, String> {
    let m = raw.get(2..).ok_or("short DNS response")?;
    if m.len() < 12 || m[0..2] != id {
        return Err("bad DNS response".into());
    }
    if m[3] & 0x0F != 0 {
        return Err(format!("DNS error code {}", m[3] & 0x0F));
    }
    let qd = u16::from_be_bytes([m[4], m[5]]);
    let an = u16::from_be_bytes([m[6], m[7]]);
    let mut off = 12;
    for _ in 0..qd {
        off = dns_skip_name(m, off).ok_or("bad DNS response")? + 4;
    }
    for _ in 0..an {
        off = dns_skip_name(m, off).ok_or("bad DNS response")?;
        let h = m.get(off..off + 10).ok_or("bad DNS response")?;
        let (rtype, rdlen) = (
            u16::from_be_bytes([h[0], h[1]]),
            u16::from_be_bytes([h[8], h[9]]) as usize,
        );
        off += 10;
        if rtype == 1 && rdlen == 4 {
            let a = m.get(off..off + 4).ok_or("bad DNS response")?;
            return Ok(Ipv4Addr::new(a[0], a[1], a[2], a[3]));
        }
        off += rdlen;
    }
    Err("no A record".into())
}

/// 터널 안에서 쓰는 DNS-over-HTTPS (주소, TLS 이름, 경로). 시스템 DNS 를 거치지 않도록 IP 로 접속
const DOH_SERVERS: &[([u8; 4], &str, &str)] = &[
    ([8, 8, 8, 8], "dns.google", "/resolve"),
    ([1, 1, 1, 1], "cloudflare-dns.com", "/dns-query"),
];

pub fn resolve_v4(host: &str) -> Result<Ipv4Addr, String> {
    (host, 0)
        .to_socket_addrs()
        .map_err(|e| format!("DNS {host}: {e}"))?
        .find_map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or(format!("no IPv4 address for {host}"))
}

impl TunnelStack {
    pub fn new<T: IpTunnel + 'static>(tun: T) -> Result<Self, String> {
        let push = tun.address();
        let ip = push.local_ip;
        let mut dev = QueueDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: push.mtu,
        };
        let mut cfg = Config::new(HardwareAddress::Ip);
        let mut seed = [0u8; 8];
        getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
        cfg.random_seed = u64::from_le_bytes(seed);
        let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::v4(ip[0], ip[1], ip[2], ip[3]),
                push.prefix_len,
            ));
        });
        // WireGuard 처럼 게이트웨이가 없는 터널은 같은 대역의 .1 을 씀 (IP 장치라 실제로 쓰이지는 않음)
        let gw = push
            .gateway
            .unwrap_or([ip[0], ip[1], ip[2], if ip[3] == 1 { 2 } else { 1 }]);
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(gw[0], gw[1], gw[2], gw[3]))
            .map_err(|e| format!("route: {e:?}"))?;
        Ok(Self {
            tun: Box::new(tun),
            dev,
            iface,
            sockets: SocketSet::new(Vec::new()),
            epoch: Instant::now(),
            hosts: HashMap::new(),
            dns: push.dns.clone(),
        })
    }

    /// `host` 의 주소를 터널 안에서(일본 쪽 DNS 로) 찾아 이후 요청에 씀.
    /// CDN 은 묻는 쪽 위치에 따라 다른 서버를 알려 주는데, 한국 쪽 서버는 VPN Gate 에서 연결되지 않을 수 있음
    pub fn resolve_in_tunnel(&mut self, host: &str) -> Result<Ipv4Addr, String> {
        let mut errors = Vec::new();
        for &(ip, name, path) in DOH_SERVERS {
            let req = format!(
                "GET {path}?name={host}&type=A HTTP/1.1\r\nHost: {name}\r\n\
                 Accept: application/dns-json\r\nConnection: close\r\n\r\n"
            );
            let answer = self
                .request_ip(
                    Ipv4Addr::from(ip),
                    name,
                    443,
                    Some(http::dmm_tls_config()),
                    req.as_bytes(),
                    Duration::from_secs(6),
                )
                .and_then(|raw| http::parse_response(&raw))
                .and_then(|(_, body)| {
                    let v: serde_json::Value =
                        serde_json::from_slice(&body).map_err(|e| e.to_string())?;
                    v["Answer"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|a| a["type"] == 1)
                        .find_map(|a| a["data"].as_str()?.parse::<Ipv4Addr>().ok())
                        .ok_or_else(|| "no A record".to_string())
                });
            match answer {
                Ok(addr) => {
                    self.hosts.insert(host.to_string(), addr);
                    return Ok(addr);
                }
                Err(e) => errors.push(format!("{name}: {e}")),
            }
        }
        // DoH 가 막힌 VPN(광고 차단 기능 등)도 있어, 터널이 알려 준 DNS 와 공개 DNS 에 TCP 로 직접 물어봄
        let mut servers = self.dns.clone();
        for s in [[8, 8, 8, 8], [1, 1, 1, 1]] {
            if !servers.contains(&s) {
                servers.push(s);
            }
        }
        for s in servers {
            let server = Ipv4Addr::from(s);
            let id: [u8; 2] = {
                let mut b = [0u8; 2];
                getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
                b
            };
            let query = dns_query(host, id);
            let answer = self
                .request_ip_until(
                    server,
                    "",
                    53,
                    None,
                    &query,
                    Duration::from_secs(6),
                    dns_tcp_complete,
                )
                .and_then(|raw| dns_answer(&raw, id));
            match answer {
                Ok(addr) => {
                    self.hosts.insert(host.to_string(), addr);
                    return Ok(addr);
                }
                Err(e) => errors.push(format!("DNS {server}: {e}")),
            }
        }
        Err(errors.join(" / "))
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_millis(self.epoch.elapsed().as_millis() as i64)
    }

    /// TCP/IP 스택 한 번 돌리기: 보낼 패킷을 터널로, 터널에서 온 패킷을 스택으로
    fn step(&mut self) -> Result<(), String> {
        let now = self.now();
        self.iface.poll(now, &mut self.dev, &mut self.sockets);
        while let Some(p) = self.dev.tx.pop_front() {
            self.tun.send_ip(&p)?;
        }
        let delay = self
            .iface
            .poll_delay(now, &self.sockets)
            .map(|d| Duration::from_millis(d.total_millis()))
            .unwrap_or(Duration::from_millis(20));
        self.tun
            .pump(delay.clamp(Duration::from_millis(1), Duration::from_millis(20)))?;
        while let Some(p) = self.tun.take_inbound() {
            self.dev.rx.push_back(p);
        }
        Ok(())
    }

    /// 터널을 통해 HTTP(S) 요청을 보내고 응답 전체를 돌려줌. `tls` 가 None 이면 평문 HTTP
    pub fn request(
        &mut self,
        host: &str,
        port: u16,
        tls: Option<Arc<ClientConfig>>,
        req: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let ip = match self.hosts.get(host) {
            Some(ip) => *ip,
            None => resolve_v4(host)?,
        };
        self.request_ip(ip, host, port, tls, req, timeout)
    }

    /// `ip` 로 접속해 `host` 이름으로 HTTP(S) 요청
    fn request_ip(
        &mut self,
        ip: Ipv4Addr,
        host: &str,
        port: u16,
        tls: Option<Arc<ClientConfig>>,
        req: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        self.request_ip_until(ip, host, port, tls, req, timeout, http::is_complete)
    }

    /// `ip` 로 접속해 요청을 보내고, `complete` 가 참이 되거나 연결이 닫힐 때까지 응답을 받음
    #[allow(clippy::too_many_arguments)]
    fn request_ip_until(
        &mut self,
        ip: Ipv4Addr,
        host: &str,
        port: u16,
        tls: Option<Arc<ClientConfig>>,
        req: &[u8],
        timeout: Duration,
        complete: fn(&[u8]) -> bool,
    ) -> Result<Vec<u8>, String> {
        let ip = ip.octets();
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 65535]),
            tcp::SocketBuffer::new(vec![0u8; 65535]),
        );
        let mut r = [0u8; 2];
        getrandom::getrandom(&mut r).map_err(|e| e.to_string())?;
        let local_port = 49152 + (u16::from_le_bytes(r) % 16000);
        sock.connect(
            self.iface.context(),
            (IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), port),
            local_port,
        )
        .map_err(|e| format!("TCP connect: {e:?}"))?;
        let h = self.sockets.add(sock);
        let result = self.exchange(h, host, tls, req, timeout, complete);
        self.sockets.get_mut::<tcp::Socket>(h).abort();
        let _ = self.step();
        self.sockets.remove(h);
        result
    }

    fn exchange(
        &mut self,
        h: SocketHandle,
        host: &str,
        tls: Option<Arc<ClientConfig>>,
        req: &[u8],
        timeout: Duration,
        complete: fn(&[u8]) -> bool,
    ) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + timeout;
        let mut conn = match tls {
            Some(cfg) => {
                let name = ServerName::try_from(host.to_string())
                    .map_err(|e| format!("server name: {e}"))?;
                let mut c =
                    ClientConnection::new(cfg, name).map_err(|e| format!("TLS init: {e}"))?;
                c.writer()
                    .write_all(req)
                    .map_err(|e| format!("TLS write: {e}"))?;
                Some(c)
            }
            None => None,
        };
        let mut out_pending: Vec<u8> = if conn.is_none() {
            req.to_vec()
        } else {
            Vec::new()
        };
        let mut resp = Vec::new();
        let mut buf = vec![0u8; 16384];
        let mut connected = false;
        loop {
            if Instant::now() >= deadline {
                return Err(if connected {
                    "response timed out"
                } else {
                    "TCP connect timed out"
                }
                .into());
            }
            self.step()?;
            let sock = self.sockets.get_mut::<tcp::Socket>(h);
            if sock.state() == tcp::State::Established {
                connected = true;
            }
            if let Some(c) = conn.as_mut() {
                while c.wants_write() {
                    c.write_tls(&mut out_pending)
                        .map_err(|e| format!("TLS write: {e}"))?;
                }
            }
            if sock.can_send() && !out_pending.is_empty() {
                let n = sock
                    .send_slice(&out_pending)
                    .map_err(|e| format!("TCP send: {e:?}"))?;
                out_pending.drain(..n);
            }
            let mut tls_closed = false;
            while sock.can_recv() {
                let n = sock
                    .recv_slice(&mut buf)
                    .map_err(|e| format!("TCP recv: {e:?}"))?;
                if n == 0 {
                    break;
                }
                match conn.as_mut() {
                    Some(c) => {
                        let mut rd: &[u8] = &buf[..n];
                        while !rd.is_empty() {
                            c.read_tls(&mut rd).map_err(|e| format!("TLS read: {e}"))?;
                            c.process_new_packets().map_err(|e| format!("TLS: {e}"))?;
                        }
                        let mut pb = [0u8; 16384];
                        loop {
                            match c.reader().read(&mut pb) {
                                Ok(0) => {
                                    tls_closed = true;
                                    break;
                                }
                                Ok(k) => resp.extend_from_slice(&pb[..k]),
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(e) => return Err(format!("TLS plaintext: {e}")),
                            }
                        }
                    }
                    None => resp.extend_from_slice(&buf[..n]),
                }
            }
            if complete(&resp) || tls_closed {
                return Ok(resp);
            }
            let remote_closed = matches!(
                sock.state(),
                tcp::State::CloseWait
                    | tcp::State::LastAck
                    | tcp::State::Closing
                    | tcp::State::TimeWait
                    | tcp::State::Closed
            );
            if remote_closed && !sock.can_recv() {
                if !resp.is_empty() {
                    return Ok(resp);
                }
                return Err(if connected {
                    "connection closed without a response"
                } else {
                    "connection refused"
                }
                .into());
            }
        }
    }
}
