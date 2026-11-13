//! UI 없이 런처 핵심 흐름을 시험하는 개발용 프로그램
//!
//! 사용법: launcher_cli --data-dir <폴더> [--import-ps-token <dmm_login.dat>] [--mode vpngate|direct] [--launch]
//! --launch 가 없으면 게임을 실행하지 않고 업데이트도 목록만 확인합니다. 로그인이 필요하면 실패로 끝납니다.

use std::path::PathBuf;
use std::time::Instant;

use gakumas_launcher::{dpapi, launcher};

fn main() {
    let mut data_dir: Option<PathBuf> = None;
    let mut import: Option<PathBuf> = None;
    let mut mode: Option<String> = None;
    let mut launch = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--data-dir" => data_dir = args.next().map(PathBuf::from),
            "--import-ps-token" => import = args.next().map(PathBuf::from),
            "--mode" => mode = args.next(),
            "--launch" => launch = true,
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    let store = launcher::Store::new(data_dir.expect("--data-dir is required")).expect("store");
    if let Some(p) = import {
        let text = std::fs::read_to_string(&p).expect("read token file");
        let token = dpapi::unprotect_powershell_secure_string(&text).expect("decrypt token");
        store.save_token(&token).expect("save token");
        println!("로그인 토큰을 가져왔습니다 (값은 표시하지 않음)");
    }
    if let Some(m) = mode {
        let mut s = store.settings();
        s.mode = m;
        store.save_settings(&s).expect("save settings");
    }
    println!("상태: {:?}", store.status());
    let t0 = Instant::now();
    let progress = |m: &str, p: Option<f32>| match p {
        Some(p) => println!("{:>6} ms  [{p:5.1}%] {m}", t0.elapsed().as_millis()),
        None => println!("{:>6} ms  {m}", t0.elapsed().as_millis()),
    };
    let no_login = |_: &str| -> Result<String, String> {
        Err("이 시험 프로그램은 로그인 창을 띄울 수 없습니다".into())
    };
    match launcher::start_game(&store, &no_login, &progress, launch) {
        Ok(m) => println!("\n결과: {m}"),
        Err(e) => {
            println!("\n오류: {e}");
            std::process::exit(1);
        }
    }
}
