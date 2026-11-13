//! HTTP 요청/응답 처리와 DMM API 요청 형식

use std::sync::Arc;

use rustls::ClientConfig;

pub const DMM_HOST: &str = "apidgp-gameplayer.games.dmm.com";
pub const CLIENT_VERSION: &str = "5.5.22";

/// DMM 서버 인증서를 검증하는 TLS 설정 (일반 웹 루트 인증서 사용)
pub fn dmm_tls_config() -> Arc<ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// DMM 플레이어와 같은 형식의 POST 요청
pub fn dmm_post(path: &str, body: &str, token: Option<&str>) -> Vec<u8> {
    let mut r = format!(
        "POST {path} HTTP/1.1\r\nHost: {DMM_HOST}\r\nUser-Agent: DMMGamePlayer5-Win/{CLIENT_VERSION} Electron/34.3.0\r\n\
         Client-App: DMMGamePlayer5\r\nClient-version: {CLIENT_VERSION}\r\nAccept-Language: ja\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(t) = token {
        r.push_str("actauth: ");
        r.push_str(t);
        r.push_str("\r\n");
    }
    r.push_str("\r\n");
    r.push_str(body);
    r.into_bytes()
}

pub fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// 응답을 끝까지 받았는지 (Content-Length 또는 chunked 끝 표시 기준)
pub fn is_complete(resp: &[u8]) -> bool {
    let Some(he) = find(resp, b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&resp[..he]).to_ascii_lowercase();
    let body = &resp[he + 4..];
    if head.contains("transfer-encoding: chunked") {
        return dechunk(body).is_some();
    }
    for line in head.lines() {
        if let Some(v) = line.strip_prefix("content-length:") {
            if let Ok(n) = v.trim().parse::<usize>() {
                return body.len() >= n;
            }
        }
    }
    false
}

/// (상태 코드, 본문)
pub fn parse_response(resp: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let he = find(resp, b"\r\n\r\n").ok_or("incomplete HTTP response")?;
    let head = String::from_utf8_lossy(&resp[..he]);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("bad HTTP status line")?;
    let body = &resp[he + 4..];
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body).ok_or("incomplete chunked body")?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let le = find(b, b"\r\n")?;
        let size_str = std::str::from_utf8(&b[..le])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        b = &b[le + 2..];
        if size == 0 {
            return Some(out);
        }
        if b.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}
