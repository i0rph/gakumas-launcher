//! VPN Gate (쓰쿠바대 학술 실험 프로젝트) 공개 서버 목록과 OpenVPN 설정 해석

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use base64::Engine;

#[derive(Clone, Debug)]
pub struct Server {
    pub host_name: String,
    pub ip: String,
    pub score: u64,
    pub country: String,
    pub config_text: String,
}

impl Server {
    /// 쓰쿠바대가 직접 운영하는 서버 (자원봉사자 서버보다 안정적)
    pub fn is_official(&self) -> bool {
        self.host_name.starts_with("public-vpn-")
    }

    /// TLS 서버 이름 (VPN Gate 서버는 *.opengw.net 인증서를 씀)
    pub fn tls_name(&self) -> String {
        format!("{}.opengw.net", self.host_name)
    }
}

#[derive(Clone, Debug)]
pub struct OvpnConfig {
    pub proto: String,
    pub remote_ip: String,
    pub port: u16,
    pub cipher: String,
    pub auth: String,
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// 서버 목록 CSV 를 받음 (http://www.vpngate.net/api/iphone/)
pub fn fetch_server_list() -> Result<Vec<Server>, String> {
    Ok(parse_server_list(&fetch_server_list_raw()?))
}

/// 일본 TCP 서버만, 쓰쿠바대 운영 서버 먼저, 그다음 점수 순
pub fn japan_tcp_candidates(body: &str) -> Vec<(Server, OvpnConfig)> {
    let mut v: Vec<(Server, OvpnConfig)> = parse_server_list(body)
        .into_iter()
        .filter(|s| s.country == "JP")
        .filter_map(|s| parse_config(&s.config_text).ok().map(|c| (s, c)))
        .filter(|(_, c)| c.proto.starts_with("tcp"))
        .collect();
    v.sort_by(|a, b| b.0.is_official().cmp(&a.0.is_official()).then(b.0.score.cmp(&a.0.score)));
    v
}

/// 서버 목록 CSV 원문 (캐시 파일에 저장해 두고 재사용하기 위함)
pub fn fetch_server_list_raw() -> Result<String, String> {
    let addr = ("www.vpngate.net", 80)
        .to_socket_addrs()
        .map_err(|e| format!("DNS: {e}"))?
        .find(|a| a.is_ipv4())
        .ok_or("no IPv4 address for www.vpngate.net")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(15)).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(60))).ok();
    s.write_all(b"GET /api/iphone/ HTTP/1.0\r\nHost: www.vpngate.net\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        .map_err(|e| format!("send: {e}"))?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| format!("receive: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).ok_or("malformed HTTP response")?;
    if !body.contains("*vpn_servers") && !body.contains("#HostName") {
        return Err("unexpected server list response".into());
    }
    Ok(body.to_string())
}

pub fn parse_server_list(body: &str) -> Vec<Server> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('*') || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 15 {
            continue;
        }
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(cols[cols.len() - 1].trim()) else {
            continue;
        };
        out.push(Server {
            host_name: cols[0].to_string(),
            ip: cols[1].to_string(),
            score: cols[2].parse().unwrap_or(0),
            country: cols[6].to_string(),
            config_text: String::from_utf8_lossy(&raw).into_owned(),
        });
    }
    out
}

/// OpenVPN 설정 파일에서 필요한 값만 꺼냄
pub fn parse_config(text: &str) -> Result<OvpnConfig, String> {
    let block = |tag: &str| -> Result<String, String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = text.find(&open).ok_or(format!("<{tag}> missing"))? + open.len();
        let end = text[start..].find(&close).ok_or(format!("</{tag}> missing"))? + start;
        Ok(text[start..end].trim().to_string())
    };

    let mut proto = String::from("udp");
    let mut remote: Option<(String, u16)> = None;
    let mut cipher = String::from("BF-CBC");
    let mut auth = String::from("SHA1");
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.starts_with(';') || l.starts_with('<') {
            continue;
        }
        let mut it = l.split_whitespace();
        match it.next() {
            Some("proto") => proto = it.next().unwrap_or("udp").to_ascii_lowercase(),
            Some("remote") if remote.is_none() => {
                if let (Some(ip), Some(port)) = (it.next(), it.next()) {
                    remote = Some((ip.to_string(), port.parse::<u16>().map_err(|_| "bad port")?));
                }
            }
            Some("cipher") => cipher = it.next().unwrap_or("").to_string(),
            Some("auth") => auth = it.next().unwrap_or("").to_string(),
            _ => {}
        }
    }
    let (remote_ip, port) = remote.ok_or("remote missing")?;
    Ok(OvpnConfig {
        proto,
        remote_ip,
        port,
        cipher,
        auth,
        ca_pem: block("ca")?,
        cert_pem: block("cert")?,
        key_pem: block("key")?,
    })
}
