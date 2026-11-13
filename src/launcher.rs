//! 런처 핵심 흐름 (UI 와 무관)
//!
//! 로그인 토큰 확인 → 일본 연결(VPN Gate 내장 터널 또는 사용자의 VPN) → 실행 토큰 발급 →
//! 업데이트(바뀐 파일만, 일반 회선) → 게임 실행

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::http::{self, CLIENT_VERSION, DMM_HOST};
use crate::netstack::TunnelStack;
use crate::openvpn::Tunnel;
use crate::{dpapi, vpngate, winutil};

pub const PRODUCT_ID: &str = "gakumas";
const USER_AGENT: &str = "DMMGamePlayer5-Win/5.5.22 Electron/34.3.0";
/// 이보다 최근에 받은 목록이면 "갱신" 때 다시 받지 않음 (시작할 때 받은 목록을 그대로 씀)
const VPNGATE_RECENT: Duration = Duration::from_secs(10 * 60);
const VPNGATE_OFFICIAL_TRIES: usize = 3;
const VPNGATE_MORE_TRIES: usize = 5;
/// DMM 이 VPN 서버를 거부할 때 다른 서버로 바꿔 시도하는 최대 횟수
const VPNGATE_LAUNCH_ATTEMPTS: usize = 4;

/// 진행 상황 알림 (메시지, 진행률 0~100)
pub type ProgressFn<'a> = &'a dyn Fn(&str, Option<f32>);
/// 로그인 주소를 받아 로그인 완료 후의 code 를 돌려주는 함수 (UI 가 로그인 창으로 구현)
pub type CodeFn<'a> = &'a dyn Fn(&str) -> Result<String, String>;

pub const MODE_VPNGATE: &str = "vpngate";
pub const MODE_DIRECT: &str = "direct";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Settings {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub game_path: Option<String>,
    #[serde(default)]
    pub game_type: Option<String>,
    #[serde(default)]
    pub installed_version: Option<String>,
    /// 프로그램을 켜면 바로 게임 시작
    #[serde(default)]
    pub auto_start: bool,
    /// 게임을 실행하고 나면 런처를 닫음
    #[serde(default)]
    pub close_after_launch: bool,
}

fn default_mode() -> String {
    MODE_VPNGATE.to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            mode: default_mode(),
            game_path: None,
            game_type: None,
            installed_version: None,
            auto_start: false,
            close_after_launch: false,
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Status {
    pub logged_in: bool,
    pub game_path: Option<String>,
    pub game_found: bool,
    pub installed_version: Option<String>,
    pub mode: String,
    pub auto_start: bool,
    pub close_after_launch: bool,
}

/// 프로그램 데이터 (설정, 암호화된 로그인 토큰, 기기 ID, VPN Gate 목록 캐시)
pub struct Store {
    dir: PathBuf,
    vpngate_lock: Mutex<()>,
}

fn file_age(p: &Path) -> Option<Duration> {
    fs::metadata(p).ok()?.modified().ok()?.elapsed().ok()
}

impl Store {
    pub fn new(dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&dir).map_err(|e| format!("데이터 폴더를 만들지 못했습니다: {e}"))?;
        Ok(Self {
            dir,
            vpngate_lock: Mutex::new(()),
        })
    }

    /// 저장해 둔 VPN Gate 서버 목록 (없으면 None)
    pub fn cached_vpngate_list(&self) -> Option<String> {
        fs::read_to_string(self.file("vpngate.csv")).ok()
    }

    /// VPN Gate 서버 목록을 새로 받아 저장. `max_age` 보다 최근 목록이 있으면 그것을 씀.
    /// 동시에 불리면(시작할 때 받는 중에 연결 시도 등) 먼저 받는 쪽이 끝날 때까지 기다림
    pub fn refresh_vpngate_list(&self, max_age: Duration) -> Result<String, String> {
        let _guard = self.vpngate_lock.lock().unwrap_or_else(|e| e.into_inner());
        let cache = self.file("vpngate.csv");
        if file_age(&cache).is_some_and(|age| age < max_age) {
            if let Ok(body) = fs::read_to_string(&cache) {
                return Ok(body);
            }
        }
        let body = vpngate::fetch_server_list_raw()
            .map_err(|e| format!("VPN Gate 서버 목록을 받지 못했습니다: {e}"))?;
        let tmp = self.file("vpngate.csv.tmp");
        fs::write(&tmp, &body).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &cache).map_err(|e| e.to_string())?;
        Ok(body)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// 설정. 게임 폴더를 모르면 DMM 플레이어 설정에서 한 번 가져옴
    pub fn settings(&self) -> Settings {
        let path = self.file("settings.json");
        let mut s: Settings = match fs::read_to_string(&path) {
            Ok(t) => match serde_json::from_str(t.trim_start_matches('\u{feff}')) {
                Ok(s) => s,
                Err(_) => {
                    // 깨진 설정은 덮어쓰기 전에 옆에 남겨 둠
                    let _ = fs::rename(&path, self.file("settings.json.bad"));
                    Settings::default()
                }
            },
            Err(_) => Settings::default(),
        };
        if s.game_path.is_none() {
            if let Some((path, version, game_type)) = dmm_player_install() {
                s.game_path = Some(path);
                s.installed_version = s.installed_version.or(version);
                s.game_type = game_type;
                let _ = self.save_settings(&s);
            }
        }
        s
    }

    pub fn save_settings(&self, s: &Settings) -> Result<(), String> {
        let text = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
        let tmp = self.file("settings.json.tmp");
        fs::write(&tmp, text).map_err(|e| format!("설정 저장 실패: {e}"))?;
        fs::rename(&tmp, self.file("settings.json")).map_err(|e| format!("설정 저장 실패: {e}"))
    }

    pub fn token(&self) -> Option<String> {
        let blob = fs::read(self.file("login.dat")).ok()?;
        String::from_utf8(dpapi::unprotect(&blob).ok()?).ok()
    }

    pub fn save_token(&self, token: &str) -> Result<(), String> {
        let blob = dpapi::protect(token.as_bytes())?;
        fs::write(self.file("login.dat"), blob).map_err(|e| format!("로그인 토큰 저장 실패: {e}"))
    }

    /// 저장된 토큰이 아직 `token` 일 때만 삭제 (그사이 새로 로그인했으면 그대로 둠)
    pub fn clear_token_if(&self, token: &str) -> Result<(), String> {
        if self.token().as_deref() == Some(token) {
            self.clear_token()
        } else {
            Ok(())
        }
    }

    /// 저장된 로그인 토큰 삭제. 백신 검사 등으로 잠깐 잠겨 있을 수 있어 몇 번 다시 시도
    pub fn clear_token(&self) -> Result<(), String> {
        let path = self.file("login.dat");
        let mut last = None;
        for _ in 0..10 {
            match fs::remove_file(&path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => last = Some(e),
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        if !path.exists() {
            return Ok(());
        }
        Err(format!(
            "로그인 정보를 지우지 못했습니다: {}",
            last.map(|e| e.to_string()).unwrap_or_default()
        ))
    }

    /// DMM 에 보내는 기기 식별값. 실제 하드웨어 정보 대신 처음 한 번 만든 임의 값을 계속 씀
    pub fn device(&self) -> Value {
        if let Some(v) = fs::read_to_string(self.file("device.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        {
            if v["mac_address"].is_string() {
                return v;
            }
        }
        let mut b = [0u8; 70];
        getrandom::getrandom(&mut b).expect("OS random generator");
        let hex = |s: &[u8]| s.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mac = b[..6]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let v = json!({ "mac_address": mac, "hdd_serial": hex(&b[6..38]), "motherboard": hex(&b[38..70]) });
        let _ = fs::write(self.file("device.json"), v.to_string());
        v
    }

    pub fn status(&self) -> Status {
        let s = self.settings();
        let game_found = s
            .game_path
            .as_ref()
            .map(|p| Path::new(p).join("gakumas.exe").is_file())
            .unwrap_or(false);
        Status {
            logged_in: self.token().is_some(),
            game_path: s.game_path,
            game_found,
            installed_version: s.installed_version,
            mode: s.mode,
            auto_start: s.auto_start,
            close_after_launch: s.close_after_launch,
        }
    }
}

/// DMM 플레이어 설정 파일에서 게임 설치 정보 (경로, 버전, 종류)
fn dmm_player_install() -> Option<(String, Option<String>, Option<String>)> {
    let p = PathBuf::from(std::env::var("APPDATA").ok()?)
        .join("dmmgameplayer5")
        .join("dmmgame.cnf");
    let text = fs::read_to_string(p).ok()?;
    let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let g = v["contents"]
        .as_array()?
        .iter()
        .find(|c| c["productId"] == PRODUCT_ID)?;
    Some((
        g["detail"]["path"].as_str()?.to_string(),
        g["detail"]["version"].as_str().map(String::from),
        g["gameType"].as_str().map(String::from),
    ))
}

// ---------------------------------------------------------------------------
// DMM API
// ---------------------------------------------------------------------------

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(60))
        .timeout_write(Duration::from_secs(30))
        .build()
}

/// ureq 오류를 짧게 설명. ureq 의 기본 메시지에는 요청 주소 전체가 들어가는데,
/// 게임 파일 주소에는 다운로드 서명이 붙어 있어 화면·기록에 남기지 않음
fn describe(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("HTTP {code}"),
        ureq::Error::Transport(t) => format!("{:?}", t.kind()),
    }
}

/// 문자열에 섞인 서명된 주소의 쿼리 부분(?Policy=...)을 지움
fn redact(s: String) -> String {
    match s.find("?Policy=") {
        Some(i) => {
            let end = s[i..].find(char::is_whitespace).map_or(s.len(), |j| i + j);
            format!("{}{}", &s[..i], &s[end..])
        }
        None => s,
    }
}

/// 일반 회선으로 DMM API 호출 (로그인 관련 API 는 한국 IP 로도 됨)
fn direct_post(path: &str, body: &Value, token: Option<&str>) -> Result<Value, String> {
    let mut req = agent()
        .post(&format!("https://{DMM_HOST}{path}"))
        .set("User-Agent", USER_AGENT)
        .set("Client-App", "DMMGamePlayer5")
        .set("Client-version", CLIENT_VERSION)
        .set("Accept-Language", "ja")
        .set("Content-Type", "application/json");
    if let Some(t) = token {
        req = req.set("actauth", t);
    }
    let resp = req
        .send_string(&body.to_string())
        .map_err(|e| format!("DMM 서버 연결 실패 ({})", describe(&e)))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("DMM 응답 수신 실패: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("DMM 응답 해석 실패: {e}"))
}

fn direct_get_json(url: &str) -> Result<Value, String> {
    let resp = agent()
        .get(url)
        .set("User-Agent", USER_AGENT)
        .set("Client-App", "DMMGamePlayer5")
        .set("Client-version", CLIENT_VERSION)
        .call()
        .map_err(|e| format!("DMM 서버 연결 실패 ({})", describe(&e)))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("DMM 응답 수신 실패: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("DMM 응답 해석 실패: {e}"))
}

/// 일본 IP 가 필요한 API 를 부르는 경로
enum JapanLink {
    /// 사용자가 직접 켠 VPN 등 (일반 회선 그대로)
    Direct,
    /// 프로그램 안의 VPN Gate 터널
    Tunnel(Box<TunnelStack>),
}

impl JapanLink {
    fn post(&mut self, path: &str, body: &Value, token: &str) -> Result<Value, String> {
        match self {
            JapanLink::Direct => direct_post(path, body, Some(token)),
            JapanLink::Tunnel(stack) => {
                let req = http::dmm_post(path, &body.to_string(), Some(token));
                let raw = stack.request(
                    DMM_HOST,
                    443,
                    Some(http::dmm_tls_config()),
                    &req,
                    Duration::from_secs(30),
                )?;
                let (status, b) = http::parse_response(&raw)?;
                match serde_json::from_slice(&b) {
                    Ok(v) => Ok(v),
                    Err(_) if status != 200 => Err(format!("DMM 서버 응답 오류 (HTTP {status})")),
                    Err(e) => Err(format!("DMM 응답 해석 실패: {e}")),
                }
            }
        }
    }
}

/// 일본 연결을 엶. VPN Gate 면 `tried` 에 없는 서버 중에서 고르고, 고른 서버 이름을 함께 돌려줌
fn open_japan_link(
    store: &Store,
    mode: &str,
    progress: ProgressFn,
    tried: &mut HashSet<String>,
) -> Result<(JapanLink, Option<String>), String> {
    if mode == MODE_DIRECT {
        return Ok((JapanLink::Direct, None));
    }
    let (stack, host) = open_vpngate(store, progress, tried)?;
    Ok((JapanLink::Tunnel(Box::new(stack)), Some(host)))
}

fn try_servers(
    list: &[(vpngate::Server, vpngate::OvpnConfig)],
    tried: &mut HashSet<String>,
    progress: ProgressFn,
) -> Option<(TunnelStack, String)> {
    for (server, cfg) in list {
        if !tried.insert(server.host_name.clone()) {
            continue;
        }
        progress(&format!("VPN 연결 중 · {}", server.host_name), None);
        match Tunnel::connect(cfg, &server.tls_name(), &mut |_| {}).and_then(TunnelStack::new) {
            Ok(stack) => return Some((stack, server.host_name.clone())),
            Err(e) => progress(&format!("{} 연결 실패: {e}", server.host_name), None),
        }
    }
    None
}

/// VPN Gate 일본 서버에 터널을 염. `tried` 에 든 서버(이미 실패했거나 DMM 이 거부한 서버)는 건너뜀.
/// 저장된 목록의 쓰쿠바대 서버부터 시도하고, 안 되면 목록을 갱신해 나머지 서버를 시도
fn open_vpngate(
    store: &Store,
    progress: ProgressFn,
    tried: &mut HashSet<String>,
) -> Result<(TunnelStack, String), String> {
    if let Some(body) = store.cached_vpngate_list() {
        let official: Vec<_> = vpngate::japan_tcp_candidates(&body)
            .into_iter()
            .filter(|(s, _)| s.is_official() && !tried.contains(&s.host_name))
            .take(VPNGATE_OFFICIAL_TRIES)
            .collect();
        if let Some(found) = try_servers(&official, tried, progress) {
            return Ok(found);
        }
    }
    progress("서버 목록 갱신 중", None);
    let body = store.refresh_vpngate_list(VPNGATE_RECENT)?;
    let all: Vec<_> = vpngate::japan_tcp_candidates(&body)
        .into_iter()
        .filter(|(s, _)| !tried.contains(&s.host_name))
        .take(VPNGATE_MORE_TRIES)
        .collect();
    try_servers(&all, tried, progress).ok_or_else(|| {
        "VPN Gate 서버에 연결하지 못했습니다. 잠시 후 다시 시도해 주세요.".to_string()
    })
}

// ---------------------------------------------------------------------------
// 로그인
// ---------------------------------------------------------------------------

/// DMM 로그인. 로그인 창은 `get_code` 가 담당 (비밀번호는 이 코드가 다루지 않음)
pub fn login(store: &Store, get_code: CodeFn, progress: ProgressFn) -> Result<String, String> {
    progress("로그인 확인 중", None);
    let r = direct_post("/v5/auth/login/url", &json!({ "prompt": "" }), None)?;
    let url = r["data"]["url"]
        .as_str()
        .ok_or_else(|| {
            format!(
                "로그인 주소를 받지 못했습니다 (result_code {})",
                r["result_code"]
            )
        })?
        .to_string();
    let code = get_code(&url)?;
    let r = direct_post("/v5/auth/accesstoken/issue", &json!({ "code": code }), None)?;
    if r["result_code"] != 100 {
        return Err(format!(
            "로그인 토큰 발급 실패 (result_code {})",
            r["result_code"]
        ));
    }
    let token = r["data"]["access_token"]
        .as_str()
        .ok_or("로그인 토큰이 응답에 없습니다")?
        .to_string();
    store.save_token(&token)?;
    progress("로그인했습니다", None);
    Ok(token)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenCheck {
    Valid,
    Expired,
    /// 연결 실패 등으로 확인하지 못함
    Unknown,
}

/// 토큰이 아직 유효한지 DMM 에 확인. DMM 은 지역보다 인증을 먼저 보므로 VPN 없이 일반 회선으로 됨
/// (만료·무효: 203 / 유효: 100, 일본 밖이면 지역 차단 801·803)
pub fn check_token(token: &str) -> TokenCheck {
    match direct_post("/v5/userinfo", &json!({}), Some(token)) {
        Ok(r) => match r["result_code"].as_i64() {
            Some(203) => TokenCheck::Expired,
            Some(100 | 801 | 803) => TokenCheck::Valid,
            _ => TokenCheck::Unknown,
        },
        Err(_) => TokenCheck::Unknown,
    }
}

/// 저장된 토큰을 검사해 만료됐으면 지움. 확인하지 못하면 그대로 둠
pub fn verify_saved_token(store: &Store) -> Result<TokenCheck, String> {
    let Some(token) = store.token() else {
        return Ok(TokenCheck::Expired);
    };
    let c = check_token(&token);
    if c == TokenCheck::Expired {
        store.clear_token_if(&token)?;
    }
    Ok(c)
}

// ---------------------------------------------------------------------------
// 실행
// ---------------------------------------------------------------------------

fn region_error(mode: &str) -> String {
    if mode == MODE_DIRECT {
        "일본 VPN 이 연결되어 있지 않습니다".into()
    } else {
        "DMM 이 VPN 서버를 거부했습니다. 잠시 후 다시 시도해 주세요.".into()
    }
}

/// 실행 토큰을 받아 (필요하면 업데이트 후) 게임 실행. launch 가 false 면 실행 직전까지만
pub fn start_game(
    store: &Store,
    get_code: CodeFn,
    progress: ProgressFn,
    launch: bool,
) -> Result<String, String> {
    let mut settings = store.settings();
    let game_dir = PathBuf::from(
        settings
            .game_path
            .clone()
            .ok_or("게임 폴더를 지정해 주세요")?,
    );
    if !game_dir.is_dir() {
        return Err(format!(
            "게임 폴더를 찾을 수 없습니다: {}",
            game_dir.display()
        ));
    }
    let game_type = settings.game_type.clone().unwrap_or_else(|| "GCL".into());

    // 저장된 토큰이 유효하면 그대로 쓰고, 만료됐으면 VPN 을 열기 전에 다시 로그인
    progress("로그인 확인 중", None);
    let mut token = match store.token() {
        Some(t) if check_token(&t) != TokenCheck::Expired => t,
        Some(t) => {
            progress("로그인이 만료되어 다시 로그인합니다", None);
            store.clear_token_if(&t)?;
            login(store, get_code, progress)?
        }
        None => login(store, get_code, progress)?,
    };

    let device = store.device();
    let body = json!({
        "product_id": PRODUCT_ID, "game_type": game_type, "game_os": "win", "launch_type": "LIB",
        "mac_address": device["mac_address"], "hdd_serial": device["hdd_serial"],
        "motherboard": device["motherboard"], "user_os": "win"
    });

    let mut relogged = false;
    let mut tried: HashSet<String> = HashSet::new();
    let mut attempts = 0;
    let data = loop {
        attempts += 1;
        // VPN Gate 서버가 DMM 에 거부당하거나 연결이 끊기면 다른 서버로 다시 시도
        let can_retry = settings.mode != MODE_DIRECT && attempts < VPNGATE_LAUNCH_ATTEMPTS;
        let (mut link, host) = open_japan_link(store, &settings.mode, progress, &mut tried)?;
        progress("실행 준비 중", None);
        let result = link.post("/v5/r2/launch/cl", &body, &token);
        drop(link); // 일본 IP 는 여기까지만 필요
        let r = match result {
            Ok(r) => r,
            Err(e) if can_retry => {
                progress(&format!("{e} · 다른 서버로 다시 시도"), None);
                continue;
            }
            Err(e) => return Err(e),
        };
        match r["result_code"].as_i64().unwrap_or(-1) {
            100 => break r["data"].clone(),
            203 if !relogged => {
                progress("다시 로그인이 필요합니다", None);
                store.clear_token()?;
                token = login(store, get_code, progress)?;
                relogged = true;
                if let Some(h) = host {
                    tried.remove(&h); // 서버 문제는 아니었으므로 다시 써도 됨
                }
            }
            801 | 803 if can_retry => {
                progress("DMM 이 VPN 서버를 거부해 다른 서버로 다시 시도", None);
            }
            801 | 803 => return Err(region_error(&settings.mode)),
            c => return Err(format!("실행 준비 실패 (result_code {c}, {})", r["error"])),
        }
    };

    let latest = data["latest_version"].as_str().unwrap_or("").to_string();
    if !latest.is_empty() && settings.installed_version.as_deref() != Some(latest.as_str()) {
        update_game(&game_dir, &data, progress, !launch)?;
        if launch {
            settings.installed_version = Some(latest.clone());
            store.save_settings(&settings)?;
        }
    }

    // DMM 플레이어와 같이, DRM 인증 정보가 오면 정해진 위치에 저장
    if let (Some(drm), true) = (data["drm_auth_token"].as_str(), launch) {
        let dir = PathBuf::from(std::env::var("USERPROFILE").map_err(|e| e.to_string())?)
            .join(".DMMGamePlayer");
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        use base64::Engine;
        let name = base64::engine::general_purpose::STANDARD.encode(PRODUCT_ID);
        fs::write(dir.join(name), drm).map_err(|e| e.to_string())?;
    }

    let exe_name = data["exec_file_name"]
        .as_str()
        .ok_or("응답에 실행 파일 이름이 없습니다")?;
    let exe = game_dir.join(exe_name);
    if !exe.is_file() {
        return Err(format!(
            "게임 실행 파일을 찾지 못했습니다: {}",
            exe.display()
        ));
    }
    let args = data["execute_args"]
        .as_str()
        .ok_or("응답에 실행 인자가 없습니다")?;
    if !launch {
        return Ok(format!(
            "[모의 실행] 실행 직전까지 확인했습니다 ({})",
            exe.display()
        ));
    }
    let elevated = data["is_administrator"].as_bool().unwrap_or(true);
    progress("게임 실행 중", None);
    winutil::launch(&exe, args, &game_dir, elevated, Duration::from_secs(8))?;
    Ok("게임을 실행했습니다".into())
}

// ---------------------------------------------------------------------------
// 업데이트 (DMM 플레이어와 같은 방식: 파일 목록의 MD5 와 다른 파일만 받음)
// ---------------------------------------------------------------------------

/// 파일 목록 경로를 게임 폴더 안의 경로로. 폴더 밖을 가리키면 None
fn resolve_game_path(game_dir: &Path, local_path: &str) -> Option<PathBuf> {
    let rel = PathBuf::from(local_path.replace('/', "\\").trim_start_matches('\\'));
    if rel.as_os_str().is_empty() || rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    Some(game_dir.join(rel))
}

/// 받는 중인 파일의 임시 확장자
const TMP_EXT: &str = "dmmtmp";

/// 게임 폴더 아래의 임시 파일(*.dmmtmp)을 지움 (깊이 제한)
fn remove_stale_tmp(dir: &Path, depth: u32) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => remove_stale_tmp(&path, depth + 1),
            Ok(t) if t.is_file() && path.extension().and_then(|e| e.to_str()) == Some(TMP_EXT) => {
                let _ = fs::remove_file(&path);
            }
            _ => {}
        }
    }
}

fn md5_file(path: &Path) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn update_game(
    game_dir: &Path,
    data: &Value,
    progress: ProgressFn,
    dry_run: bool,
) -> Result<(), String> {
    let list_url = data["file_list_url"]
        .as_str()
        .ok_or("응답에 업데이트 정보가 없습니다")?;
    let sign = data["sign"]
        .as_str()
        .ok_or("응답에 다운로드 서명이 없습니다")?;
    progress("업데이트 확인 중", None);
    let first = direct_get_json(&format!("https://{DMM_HOST}{list_url}"))?;
    let domain = first["data"]["domain"]
        .as_str()
        .ok_or("파일 목록에 서버 주소가 없습니다")?
        .to_string();
    let mut files: Vec<Value> = first["data"]["file_list"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let pages = first["data"]["page"].as_u64().unwrap_or(1);
    for p in 2..=pages {
        let more = direct_get_json(&format!("https://{DMM_HOST}{list_url}?page={p}"))?;
        files.extend(
            more["data"]["file_list"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
    }

    let mut todo: Vec<(&Value, PathBuf)> = Vec::new();
    let mut delete: Vec<PathBuf> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        if i % 10 == 0 {
            progress(
                &format!("파일 검사 중 {}/{}", i, files.len()),
                Some(i as f32 * 100.0 / files.len().max(1) as f32),
            );
        }
        let Some(full) = resolve_game_path(game_dir, f["local_path"].as_str().unwrap_or("")) else {
            continue;
        };
        let exists = full.is_file();
        if f["force_delete_flg"].as_bool() == Some(true) {
            if exists {
                delete.push(full);
            }
            continue;
        }
        if !exists {
            todo.push((f, full));
            continue;
        }
        if f["check_hash_flg"].as_bool() != Some(true) {
            continue;
        }
        if md5_file(&full)? != f["hash"].as_str().unwrap_or("").to_ascii_lowercase() {
            todo.push((f, full));
        }
    }
    if todo.is_empty() && delete.is_empty() {
        progress("최신 버전입니다", Some(100.0));
        return Ok(());
    }
    if todo
        .iter()
        .any(|(f, _)| f["protected_flg"].as_bool() == Some(true))
    {
        return Err("보호된 파일이 포함된 업데이트라 이 런처로는 받을 수 없습니다. DMM GAME PLAYER 로 업데이트해 주세요.".into());
    }
    let total: u64 = todo
        .iter()
        .map(|(f, _)| f["size"].as_u64().unwrap_or(0))
        .sum();
    progress(
        &format!(
            "업데이트 · 파일 {}개, {:.0} MB",
            todo.len(),
            total as f64 / 1_048_576.0
        ),
        None,
    );
    if dry_run {
        for (f, _) in &todo {
            progress(
                &format!("  받을 파일: {}", f["local_path"].as_str().unwrap_or("")),
                None,
            );
        }
        return Ok(());
    }

    // 이전에 중간에 끊긴 업데이트가 남긴 임시 파일 정리
    remove_stale_tmp(game_dir, 0);

    // CloudFront 서명: "CloudFront-Policy=..;CloudFront-Signature=..;CloudFront-Key-Pair-Id=.."
    let mut policy = "";
    let mut signature = "";
    let mut key_pair = "";
    for kv in sign.split(';') {
        if let Some((k, v)) = kv.trim().split_once('=') {
            match k {
                "CloudFront-Policy" => policy = v,
                "CloudFront-Signature" => signature = v,
                "CloudFront-Key-Pair-Id" => key_pair = v,
                _ => {}
            }
        }
    }
    let query = format!(
        "Policy={}&Signature={}&Key-Pair-Id={}",
        percent_encode(policy),
        percent_encode(signature),
        percent_encode(key_pair)
    );

    let agent = agent();
    let mut done: u64 = 0;
    let mut buf = vec![0u8; 256 * 1024];
    for (n, (f, full)) in todo.iter().enumerate() {
        let local = f["local_path"].as_str().unwrap_or("");
        let url = format!(
            "{}/{}?{}",
            domain.trim_end_matches('/'),
            f["path"].as_str().unwrap_or("").trim_start_matches('/'),
            query
        );
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let tmp = full.with_extension(format!(
            "{}.{TMP_EXT}",
            full.extension().and_then(|e| e.to_str()).unwrap_or("")
        ));
        let mut fetch = || -> Result<(), String> {
            let resp = agent
                .get(&url)
                .set("User-Agent", USER_AGENT)
                .call()
                .map_err(|e| format!("{local} 다운로드 실패 ({})", describe(&e)))?;
            let mut reader = resp.into_reader();
            let mut out = fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
            let mut last_report = 0u64;
            loop {
                let k = reader
                    .read(&mut buf)
                    .map_err(|e| redact(format!("{local} 다운로드 실패: {e}")))?;
                if k == 0 {
                    break;
                }
                out.write_all(&buf[..k])
                    .map_err(|e| format!("{}: {e}", tmp.display()))?;
                done += k as u64;
                if done - last_report >= 2 * 1_048_576 {
                    last_report = done;
                    progress(
                        &format!("업데이트 중 {}/{}", n + 1, todo.len()),
                        Some(done as f32 * 100.0 / total.max(1) as f32),
                    );
                }
            }
            drop(out);
            if f["check_hash_flg"].as_bool() == Some(true)
                && md5_file(&tmp)? != f["hash"].as_str().unwrap_or("").to_ascii_lowercase()
            {
                return Err(format!("{local}: 받은 파일의 검증값이 맞지 않습니다"));
            }
            fs::rename(&tmp, full)
                .map_err(|e| format!("{local} 교체 실패 (게임이 실행 중인가요?): {e}"))
        };
        if let Err(e) = fetch() {
            let _ = fs::remove_file(&tmp); // 받다 만 파일을 남기지 않음
            return Err(e);
        }
        progress(
            &format!("업데이트 중 {}/{}", n + 1, todo.len()),
            Some(done as f32 * 100.0 / total.max(1) as f32),
        );
    }
    for d in &delete {
        fs::remove_file(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    progress("업데이트 완료", Some(100.0));
    Ok(())
}
