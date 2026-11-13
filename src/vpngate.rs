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
    v.sort_by(|a, b| {
        b.0.is_official()
            .cmp(&a.0.is_official())
            .then(b.0.score.cmp(&a.0.score))
    });
    v
}

/// 서버 목록 CSV 원문 (캐시 파일에 저장해 두고 재사용하기 위함).
/// 일반 HTTP 가 막힌 네트워크가 있어 실패하면 HTTPS 로 한 번 더 받음
pub fn fetch_server_list_raw() -> Result<String, String> {
    let http_err = match fetch_http() {
        Ok(body) => return Ok(body),
        Err(e) => e,
    };
    fetch_https().map_err(|e| format!("HTTP: {http_err} / HTTPS: {e}"))
}

/// 디버그 빌드에서만: GAKUMAS_TEST_LIST_FAIL=http|all 이면 목록 받기를 실패시킴 (차단된 네트워크 흉내)
fn simulated_failure(kind: &str) -> Result<(), String> {
    if cfg!(debug_assertions)
        && std::env::var("GAKUMAS_TEST_LIST_FAIL").is_ok_and(|v| v == kind || v == "all")
    {
        return Err("simulated failure".into());
    }
    Ok(())
}

fn check_list(body: String) -> Result<String, String> {
    if !body.contains("*vpn_servers") && !body.contains("#HostName") {
        return Err("unexpected server list response".into());
    }
    Ok(body)
}

/// www.vpngate.net 은 TLS 1.2 CBC 암호만 받아 rustls 로는 연결되지 않으므로 Windows TLS(schannel)를 씀
fn fetch_https() -> Result<String, String> {
    simulated_failure("https")?;
    let tls = native_tls::TlsConnector::new().map_err(|e| format!("TLS: {e}"))?;
    let resp = ureq::AgentBuilder::new()
        .tls_connector(std::sync::Arc::new(tls))
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(60))
        .build()
        .get("https://www.vpngate.net/api/iphone/")
        .set("User-Agent", "Mozilla/5.0")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("HTTP {code}"),
            ureq::Error::Transport(t) => t.to_string(),
        })?;
    let mut body = String::new();
    resp.into_reader()
        .take(32 * 1024 * 1024)
        .read_to_string(&mut body)
        .map_err(|e| format!("receive: {e}"))?;
    check_list(body)
}

/// 쓰쿠바대가 직접 운영하는 일본 서버 (호스트 이름, 마지막으로 확인한 IP).
/// 서버 목록을 받을 수 없을 때만 씀. IP 는 먼저 DNS 로 다시 찾아봄
const BUILTIN_OFFICIAL: &[(&str, &str)] = &[
    ("public-vpn-162", "219.100.37.125"),
    ("public-vpn-42", "219.100.37.6"),
    ("public-vpn-127", "219.100.37.63"),
    ("public-vpn-150", "219.100.37.108"),
    ("public-vpn-214", "219.100.37.204"),
    ("public-vpn-210", "219.100.37.198"),
    ("public-vpn-61", "219.100.37.51"),
    ("public-vpn-81", "219.100.37.28"),
    ("public-vpn-142", "219.100.37.114"),
];

/// 모든 VPN Gate 서버가 같이 쓰는 접속 설정 (CA·클라이언트 인증서·키). 접속 주소만 바꿔 씀
const BUILTIN_PROFILE: &str = include_str!("vpngate_builtin.ovpn");

/// 서버 목록 없이 쓸 수 있는 쓰쿠바대 서버들
pub fn builtin_official_servers() -> Vec<(Server, OvpnConfig)> {
    let Ok(base) = parse_config(BUILTIN_PROFILE) else {
        return Vec::new();
    };
    BUILTIN_OFFICIAL
        .iter()
        .map(|&(host, known_ip)| {
            let server = Server {
                host_name: host.to_string(),
                ip: known_ip.to_string(),
                score: 0,
                country: "JP".into(),
                config_text: String::new(),
            };
            let mut cfg = base.clone();
            cfg.remote_ip = known_ip.to_string();
            (server, cfg)
        })
        .collect()
}

/// 내장 서버의 현재 IP 를 DNS 로 찾음 (못 찾으면 그대로). 서버 인증서로 확인하므로 틀린 IP 면 연결이 실패할 뿐임
pub fn refresh_builtin_ip(server: &Server, cfg: &mut OvpnConfig) {
    if let Ok(mut addrs) = (server.tls_name().as_str(), 443).to_socket_addrs() {
        if let Some(a) = addrs.find(|a| a.is_ipv4()) {
            cfg.remote_ip = a.ip().to_string();
        }
    }
}

fn fetch_http() -> Result<String, String> {
    simulated_failure("http")?;
    let addr = ("www.vpngate.net", 80)
        .to_socket_addrs()
        .map_err(|e| format!("DNS: {e}"))?
        .find(|a| a.is_ipv4())
        .ok_or("no IPv4 address for www.vpngate.net")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(15))
        .map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(60))).ok();
    s.write_all(b"GET /api/iphone/ HTTP/1.0\r\nHost: www.vpngate.net\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        .map_err(|e| format!("send: {e}"))?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)
        .map_err(|e| format!("receive: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .ok_or("malformed HTTP response")?;
    check_list(body.to_string())
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
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(cols[cols.len() - 1].trim())
        else {
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
        let end = text[start..]
            .find(&close)
            .ok_or(format!("</{tag}> missing"))?
            + start;
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
