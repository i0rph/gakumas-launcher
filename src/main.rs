//! 학원 아이돌마스터 런처 (UI)
//!
//! 로그인은 프로그램 안의 WebView2 창에서 사용자가 직접 합니다. 로그인 상태와(사용자가 저장을 고르면)
//! 비밀번호는 WebView2 가 이 프로그램 전용 데이터 폴더에 보관하므로, 보통은 창 없이 자동으로 지나갑니다.
//! 이 코드는 비밀번호를 읽거나 대신 입력·제출하지 않습니다.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use gakumas_launcher::launcher::{self, Status, Store};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;

struct AppState {
    store: Store,
    busy: Mutex<bool>,
    /// 이번 실행에서 아직 자동 시작을 하지 않았는지 (프로그램을 켤 때 한 번만)
    auto_start_pending: Mutex<bool>,
    /// 진행 중에도 닫겠다고 확인했는지
    force_close: AtomicBool,
}

#[derive(Clone, Serialize)]
struct ProgressEvent {
    message: String,
    percent: Option<f32>,
}

fn emit_progress(app: &AppHandle, message: &str, percent: Option<f32>) {
    let _ = app.emit(
        "progress",
        ProgressEvent {
            message: message.to_string(),
            percent,
        },
    );
}

static LOGIN_SEQ: AtomicUsize = AtomicUsize::new(0);
/// 로그인이 끝나면 이 주소로 넘어가며 code 를 넘겨줌 (원래는 DMM 플레이어를 여는 페이지)
const LOGIN_SUCCESS_HOST: &str = "webdgp-gameplayer.games.dmm.com";

/// 로그인 창을 띄워 로그인 완료 주소의 code 를 받아 옴.
/// 저장된 로그인 상태로 바로 지나가면 창을 보이지 않은 채로 끝남
fn login_window(app: &AppHandle, url: &str) -> Result<String, String> {
    let target: tauri::Url = url.parse().map_err(|e| format!("로그인 주소 오류: {e}"))?;
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let tx_nav = tx.clone();
    let label = format!("login{}", LOGIN_SEQ.fetch_add(1, Ordering::SeqCst));
    let win = WebviewWindowBuilder::new(app, &label, WebviewUrl::External(target))
        .title("DMM 로그인")
        .inner_size(480.0, 760.0)
        .center()
        .visible(false)
        .initialization_script(include_str!("keep_login.js"))
        .on_navigation(move |u| {
            if u.host_str() == Some(LOGIN_SUCCESS_HOST) && u.path().starts_with("/login/success") {
                let code = u
                    .query_pairs()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.into_owned());
                let _ = tx_nav.send(code);
                return false; // 완료 페이지는 열지 않음 (DMM 플레이어 호출 방지)
            }
            true
        })
        .build()
        .map_err(|e| format!("로그인 창을 열지 못했습니다: {e}"))?;
    enable_password_autosave(&win);
    let tx_close = tx.clone();
    win.on_window_event(move |e| {
        if let tauri::WindowEvent::Destroyed = e {
            let _ = tx_close.send(None);
        }
    });
    drop(tx);

    let code = match rx.recv_timeout(Duration::from_secs(6)) {
        Ok(c) => c,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            emit_progress(app, "로그인 창에서 로그인하세요", None);
            let _ = win.show();
            let _ = win.set_focus();
            rx.recv_timeout(Duration::from_secs(900)).ok().flatten()
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => None,
    };
    let _ = win.close();
    code.ok_or_else(|| "로그인이 취소되었습니다".to_string())
}

/// 로그인 창에서 브라우저 기본 비밀번호 저장/자동 채우기를 켬 (WebView2 기본값은 꺼짐).
/// 저장 여부는 사용자가 WebView2 의 저장 안내에서 고름
fn enable_password_autosave(win: &tauri::WebviewWindow) {
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings4;
    use windows_core::Interface;
    let _ = win.with_webview(|wv| unsafe {
        let Ok(core) = wv.controller().CoreWebView2() else {
            return;
        };
        let Ok(settings) = core.Settings() else {
            return;
        };
        if let Ok(s4) = settings.cast::<ICoreWebView2Settings4>() {
            let _ = s4.SetIsPasswordAutosaveEnabled(true);
            let _ = s4.SetIsGeneralAutofillEnabled(true);
        }
    });
}

async fn run_busy<F>(app: AppHandle, f: F) -> Result<String, String>
where
    F: FnOnce(&AppHandle, &Store) -> Result<String, String> + Send + 'static,
{
    {
        let state = app.state::<AppState>();
        let mut busy = state.busy.lock().unwrap();
        if *busy {
            return Err("이미 진행 중입니다".into());
        }
        *busy = true;
    }
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<AppState>();
        f(&worker, &state.store)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    *app.state::<AppState>().busy.lock().unwrap() = false;
    result
}

#[tauri::command]
fn get_status(state: tauri::State<'_, AppState>) -> Status {
    state.store.status()
}

#[tauri::command]
fn set_mode(state: tauri::State<'_, AppState>, mode: String) -> Result<Status, String> {
    if mode != launcher::MODE_VPNGATE && mode != launcher::MODE_DIRECT {
        return Err("알 수 없는 연결 방식입니다".into());
    }
    let mut s = state.store.settings();
    s.mode = mode;
    state.store.save_settings(&s)?;
    Ok(state.store.status())
}

#[tauri::command]
fn set_auto_start(state: tauri::State<'_, AppState>, enabled: bool) -> Result<Status, String> {
    let mut s = state.store.settings();
    s.auto_start = enabled;
    state.store.save_settings(&s)?;
    Ok(state.store.status())
}

#[tauri::command]
fn set_close_after_launch(
    state: tauri::State<'_, AppState>,
    enabled: bool,
) -> Result<Status, String> {
    let mut s = state.store.settings();
    s.close_after_launch = enabled;
    state.store.save_settings(&s)?;
    Ok(state.store.status())
}

/// 자동 시작을 해야 하면 true (프로그램을 켠 뒤 첫 호출에서만)
#[tauri::command]
fn take_auto_start(state: tauri::State<'_, AppState>) -> bool {
    std::mem::take(&mut *state.auto_start_pending.lock().unwrap())
}

/// Windows 폴더 선택 창으로 게임 폴더 지정
#[tauri::command]
async fn pick_game_folder(app: AppHandle, window: tauri::Window) -> Result<Status, String> {
    let current = app.state::<AppState>().store.settings().game_path;
    let dialog_app = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let mut d = dialog_app
            .dialog()
            .file()
            .set_title("게임 폴더 선택")
            .set_parent(&window);
        if let Some(p) = current {
            d = d.set_directory(p);
        }
        d.blocking_pick_folder()
    })
    .await
    .map_err(|e| e.to_string())?;

    let state = app.state::<AppState>();
    let Some(picked) = picked else {
        return Ok(state.store.status());
    };
    let path: PathBuf = picked.into_path().map_err(|e| e.to_string())?;
    if !path.join("gakumas.exe").is_file() {
        return Err("이 폴더에 gakumas.exe 가 없습니다".into());
    }
    let mut s = state.store.settings();
    let path = path.to_string_lossy().into_owned();
    if s.game_path.as_deref() != Some(path.as_str()) {
        s.game_path = Some(path);
        s.installed_version = None; // 새 폴더는 버전을 모르므로 다음 실행 때 파일 전체 검사
        state.store.save_settings(&s)?;
    }
    Ok(state.store.status())
}

#[tauri::command]
async fn start_game(app: AppHandle) -> Result<String, String> {
    let result = run_busy(app.clone(), |app, store| {
        let progress = |m: &str, p: Option<f32>| emit_progress(app, m, p);
        let get_code = |url: &str| login_window(app, url);
        launcher::start_game(store, &get_code, &progress, true)
    })
    .await;
    // 게임이 실행됐고 '게임 실행 후 런처 종료'가 켜져 있으면 런처를 닫음
    if result.is_ok() && app.state::<AppState>().store.settings().close_after_launch {
        app.exit(0);
    }
    result
}

#[tauri::command]
async fn login(app: AppHandle) -> Result<String, String> {
    run_busy(app, |app, store| {
        let progress = |m: &str, p: Option<f32>| emit_progress(app, m, p);
        let get_code = |url: &str| login_window(app, url);
        launcher::login(store, &get_code, &progress).map(|_| "로그인했습니다".to_string())
    })
    .await
}

#[tauri::command]
fn logout(app: AppHandle, state: tauri::State<'_, AppState>) -> Result<Status, String> {
    if *state.busy.lock().unwrap() {
        return Err("진행 중에는 로그아웃할 수 없습니다".into());
    }
    state.store.clear_token()?;
    if let Some(w) = app.get_webview_window("main") {
        // 로그인 창과 같은 저장소를 쓰므로 DMM 로그인 상태와 저장된 비밀번호도 함께 지워짐
        w.clear_all_browsing_data()
            .map_err(|e| format!("로그인 정보를 지우지 못했습니다: {e}"))?;
    }
    Ok(state.store.status())
}

/// 진행 중 닫기 확인 후 종료
#[tauri::command]
fn force_close(app: AppHandle, state: tauri::State<'_, AppState>) {
    state.force_close.store(true, Ordering::SeqCst);
    app.exit(0);
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .on_window_event(|window, event| {
            // 업데이트 등이 진행 중이면 바로 닫지 않고 화면에서 확인을 받음
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    if let Some(state) = window.try_state::<AppState>() {
                        if *state.busy.lock().unwrap() && !state.force_close.load(Ordering::SeqCst)
                        {
                            api.prevent_close();
                            let _ = window.emit("close-blocked", ());
                        }
                    }
                }
            }
        })
        .setup(|app| {
            let dir = app.path().app_local_data_dir()?;
            let store = Store::new(dir.join("data"))?;
            let settings = store.settings();
            let vpngate_mode = settings.mode == launcher::MODE_VPNGATE;
            app.manage(AppState {
                store,
                busy: Mutex::new(false),
                auto_start_pending: Mutex::new(settings.auto_start),
                force_close: AtomicBool::new(false),
            });
            // 시작하자마자 VPN Gate 서버 목록을 새로 받아 둠 (게임 시작은 받는 동안에도 쓰쿠바대 서버로 먼저 시도)
            if vpngate_mode {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    let _ = handle
                        .state::<AppState>()
                        .store
                        .refresh_vpngate_list(Duration::ZERO);
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            set_mode,
            set_auto_start,
            set_close_after_launch,
            take_auto_start,
            pick_game_folder,
            start_game,
            login,
            logout,
            force_close
        ])
        .run(tauri::generate_context!())
        .expect("error while running application");
}
