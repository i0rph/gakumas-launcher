//! 터널 위에서 도는 사용자 공간 TCP/IP 스택 (smoltcp)
//!
//! Windows 네트워크 설정을 건드리지 않고, 이 프로그램이 여는 TCP 연결만 VPN 터널을 탑니다.

use std::collections::VecDeque;
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
use crate::openvpn::Tunnel;

/// 터널 안 IP 패킷 최대 크기. 작게 잡아 TCP 세그먼트가 터널에서 잘리지 않게 함
const MTU: usize = 1350;

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
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
    type RxToken<'a> = RxTok where Self: 'a;
    type TxToken<'a> = TxTok<'a> where Self: 'a;

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
        c.max_transmission_unit = MTU;
        c
    }
}

pub struct TunnelStack {
    tun: Tunnel,
    dev: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    epoch: Instant,
}

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
    pub fn new(tun: Tunnel) -> Result<Self, String> {
        let push = tun.push.clone().ok_or("tunnel has no address")?;
        let ip = push.local_ip;
        let mut dev = QueueDevice { rx: VecDeque::new(), tx: VecDeque::new() };
        let mut cfg = Config::new(HardwareAddress::Ip);
        let mut seed = [0u8; 8];
        getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
        cfg.random_seed = u64::from_le_bytes(seed);
        let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), push.prefix_len));
        });
        let gw = push.gateway.unwrap_or([ip[0], ip[1], ip[2], 1]);
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(gw[0], gw[1], gw[2], gw[3]))
            .map_err(|e| format!("route: {e:?}"))?;
        Ok(Self { tun, dev, iface, sockets: SocketSet::new(Vec::new()), epoch: Instant::now() })
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
        self.tun.pump(delay.clamp(Duration::from_millis(1), Duration::from_millis(20)))?;
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
        let ip = resolve_v4(host)?.octets();
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 65535]),
            tcp::SocketBuffer::new(vec![0u8; 65535]),
        );
        let mut r = [0u8; 2];
        getrandom::getrandom(&mut r).map_err(|e| e.to_string())?;
        let local_port = 49152 + (u16::from_le_bytes(r) % 16000);
        sock.connect(self.iface.context(), (IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), port), local_port)
            .map_err(|e| format!("TCP connect: {e:?}"))?;
        let h = self.sockets.add(sock);
        let result = self.exchange(h, host, tls, req, timeout);
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
    ) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + timeout;
        let mut conn = match tls {
            Some(cfg) => {
                let name = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
                let mut c = ClientConnection::new(cfg, name).map_err(|e| format!("TLS init: {e}"))?;
                c.writer().write_all(req).map_err(|e| format!("TLS write: {e}"))?;
                Some(c)
            }
            None => None,
        };
        let mut out_pending: Vec<u8> = if conn.is_none() { req.to_vec() } else { Vec::new() };
        let mut resp = Vec::new();
        let mut buf = vec![0u8; 16384];
        let mut connected = false;
        loop {
            if Instant::now() >= deadline {
                return Err(if connected { "response timed out" } else { "TCP connect timed out" }.into());
            }
            self.step()?;
            let sock = self.sockets.get_mut::<tcp::Socket>(h);
            if sock.state() == tcp::State::Established {
                connected = true;
            }
            if let Some(c) = conn.as_mut() {
                while c.wants_write() {
                    c.write_tls(&mut out_pending).map_err(|e| format!("TLS write: {e}"))?;
                }
            }
            if sock.can_send() && !out_pending.is_empty() {
                let n = sock.send_slice(&out_pending).map_err(|e| format!("TCP send: {e:?}"))?;
                out_pending.drain(..n);
            }
            let mut tls_closed = false;
            while sock.can_recv() {
                let n = sock.recv_slice(&mut buf).map_err(|e| format!("TCP recv: {e:?}"))?;
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
            if http::is_complete(&resp) || tls_closed {
                return Ok(resp);
            }
            let remote_closed = matches!(
                sock.state(),
                tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait | tcp::State::Closed
            );
            if remote_closed && !sock.can_recv() {
                if !resp.is_empty() {
                    return Ok(resp);
                }
                return Err(if connected { "connection closed without a response" } else { "connection refused" }.into());
            }
        }
    }
}
