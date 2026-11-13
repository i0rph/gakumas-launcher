//! VPN 설정 파일(.ovpn / WireGuard .conf) 연결 시험 프로그램
//!
//! 사용법: vpnfile_probe --file <설정 파일> [--data-dir <PowerShell 판 폴더>] [--tries <N>]
//!                       [--dummy-auth] [--auth-file <아이디·비밀번호 두 줄 파일>]
//! --dummy-auth 는 가짜 아이디로 로그인 단계 직전까지만 확인합니다 (서버가 AUTH_FAILED 로 거부하면 정상).
//! 키·토큰·비밀번호 값은 출력하지 않습니다.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use gakumas_launcher::netstack::TunnelStack;
use gakumas_launcher::openvpn::{self, ConnectOptions, OvpnConfig, Tunnel};
use gakumas_launcher::wireguard::{WgConfig, WgTunnel};
use gakumas_launcher::{dpapi, http};

fn main() {
    if let Err(e) = run() {
        println!("\n오류: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut file: Option<PathBuf> = None;
    let mut data_dir = PathBuf::from("..");
    let mut tries = 3usize;
    let mut dummy = false;
    let mut auth_file: Option<PathBuf> = None;
    let mut ping_test = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--file" => file = args.next().map(PathBuf::from),
            "--data-dir" => data_dir = PathBuf::from(args.next().ok_or("--data-dir")?),
            "--tries" => tries = args.next().and_then(|v| v.parse().ok()).ok_or("--tries")?,
            "--dummy-auth" => dummy = true,
            "--ping-test" => ping_test = true,
            "--auth-file" => auth_file = args.next().map(PathBuf::from),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let file = file.ok_or("--file 이 필요합니다")?;
    let text = std::fs::read_to_string(&file).map_err(|e| format!("파일: {e}"))?;
    let t0 = Instant::now();
    let mut log = |m: String| println!("    {:>6} ms  {m}", t0.elapsed().as_millis());

    let stack = if text.contains("[Interface]") {
        let cfg = WgConfig::parse(&text)?;
        println!(
            "[1] WireGuard 설정: 주소 {}/{}, 서버 포트 {}, keepalive {:?}, MTU {}",
            std::net::Ipv4Addr::from(cfg.address),
            cfg.prefix_len,
            cfg.endpoint_port,
            cfg.keepalive,
            cfg.mtu
        );
        let tun = WgTunnel::connect(&cfg, &mut log)?;
        TunnelStack::new(tun)?
    } else {
        let dir = file.parent().map(PathBuf::from).unwrap_or_default();
        let (inlined, file_creds) = openvpn::inline_external_files(&text, &dir)?;
        let cfg = OvpnConfig::parse(&inlined)?;
        println!(
            "[1] OpenVPN 설정: 서버 {}개 (remote-random {}), cipher {:?}, data-ciphers {:?}, auth {}, tls-auth {}, tls-crypt {}, 로그인 {}, 클라이언트 인증서 {}, compress {:?}, fragment {:?}",
            cfg.remotes.len(),
            cfg.remote_random,
            cfg.cipher,
            cfg.data_ciphers,
            cfg.auth,
            cfg.tls_auth.is_some(),
            cfg.tls_crypt.is_some(),
            cfg.auth_user_pass,
            cfg.cert_pem.is_some(),
            cfg.compress,
            cfg.fragment
        );
        let creds: Option<(String, String)> = if let Some(p) = auth_file {
            let c = std::fs::read_to_string(p).map_err(|e| format!("auth file: {e}"))?;
            let mut it = c.lines();
            Some((
                it.next().unwrap_or("").trim().to_string(),
                it.next().unwrap_or("").trim_end().to_string(),
            ))
        } else if dummy {
            Some(("launcher-probe".into(), "not-a-real-password".into()))
        } else {
            file_creds
        };
        let mut last = String::from("no remote");
        let mut found = None;
        for remote in cfg.remote_order().iter().take(tries) {
            println!(
                "\n[2] {}:{} ({}) 연결 시도",
                remote.host,
                remote.port,
                if remote.udp { "UDP" } else { "TCP" }
            );
            let opts = ConnectOptions {
                remote,
                tls_name: &remote.host,
                strict_verify: true,
                credentials: creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
            };
            match Tunnel::connect_with(&cfg, &opts, &mut log) {
                Ok(t) => {
                    found = Some(t);
                    break;
                }
                Err(e) => {
                    println!("    실패: {e}");
                    last = e;
                    if dummy && last.contains("AUTH_FAILED") {
                        println!(
                            "\n가짜 아이디로 AUTH_FAILED 까지 도달: 로그인 직전 단계까지 정상"
                        );
                        return Ok(());
                    }
                }
            }
        }
        let mut tun = found.ok_or(last)?;
        if ping_test {
            // 데이터 채널 확인: keepalive 패킷을 주고받아 양쪽 암호화가 맞는지 봄
            let end = Instant::now() + Duration::from_secs(8);
            let mut sent = 0;
            while Instant::now() < end {
                tun.send_ip(&openvpn::PING_MAGIC)?;
                sent += 1;
                tun.pump(Duration::from_millis(500))?;
            }
            println!(
                "
[ping] 보냄 {sent}, 받은 데이터 패킷 {} (복호화 실패 {})",
                tun.data_rx, tun.data_rx_errors
            );
            return Ok(());
        }
        TunnelStack::new(tun)?
    };
    probe(stack, &data_dir)
}

fn probe(mut stack: TunnelStack, data_dir: &std::path::Path) -> Result<(), String> {
    let t = Instant::now();
    match stack.resolve_in_tunnel(http::DMM_HOST) {
        Ok(ip) => println!(
            "    DMM 주소 (터널 안 DNS): {ip} ({} ms)",
            t.elapsed().as_millis()
        ),
        Err(e) => println!("    터널 안 DNS 실패, 시스템 DNS 사용: {e}"),
    }

    println!("\n[3] 터널 안에서 접속 국가 확인 (ipinfo.io, 평문 HTTP)");
    let t1 = Instant::now();
    let req = b"GET /country HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n";
    match stack.request("ipinfo.io", 80, None, req, Duration::from_secs(20)) {
        Ok(r) => {
            let (status, body) = http::parse_response(&r)?;
            let body = String::from_utf8_lossy(&body);
            println!(
                "    HTTP {status}, 국가: {} ({} ms)",
                if status == 200 { body.trim() } else { "?" },
                t1.elapsed().as_millis()
            );
        }
        Err(e) => println!("    실패: {e}"),
    }

    let token = std::fs::read_to_string(data_dir.join("dmm_login.dat"))
        .ok()
        .and_then(|t| dpapi::unprotect_powershell_secure_string(&t).ok());
    let device: serde_json::Value = std::fs::read_to_string(data_dir.join("dmm_device.json"))
        .ok()
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
        .unwrap_or(serde_json::Value::Null);
    let Some(tok) = token else {
        println!("\n(로그인 토큰이 없어 DMM API 시험은 건너뜀)");
        return Ok(());
    };
    println!("\n[4] DMM API 호출 (터널 안에서 HTTPS)");
    let launch_body = serde_json::json!({
        "product_id": "gakumas", "game_type": "GCL", "game_os": "win", "launch_type": "LIB",
        "mac_address": device["mac_address"], "hdd_serial": device["hdd_serial"],
        "motherboard": device["motherboard"], "user_os": "win"
    })
    .to_string();
    for (name, path, body) in [
        ("userinfo", "/v5/userinfo", "{}".to_string()),
        ("launch/cl", "/v5/r2/launch/cl", launch_body),
    ] {
        let t1 = Instant::now();
        let req = http::dmm_post(path, &body, Some(&tok));
        match stack.request(
            http::DMM_HOST,
            443,
            Some(http::dmm_tls_config()),
            &req,
            Duration::from_secs(30),
        ) {
            Ok(r) => {
                let (status, body) = http::parse_response(&r)?;
                let v: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                println!(
                    "    {name}: HTTP {status}, result_code={} ({} ms)",
                    v["result_code"],
                    t1.elapsed().as_millis()
                );
            }
            Err(e) => println!("    {name}: 실패: {e}"),
        }
    }
    Ok(())
}
