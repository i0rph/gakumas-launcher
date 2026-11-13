//! Windows 전용 보조 기능: 게임 실행 (필요하면 관리자 권한)

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// 이름이 같은 프로세스가 떠 있는지 (관리자 권한으로 실행된 프로세스도 이름은 보임)
pub fn is_process_running(exe_name: &str) -> bool {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = false;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
                if String::from_utf16_lossy(&e.szExeFile[..len]).eq_ignore_ascii_case(exe_name) {
                    found = true;
                    break;
                }
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        found
    }
}

/// 프로그램을 실행하고 `watch` 동안 지켜봄. 그 안에 오류 코드로 끝나고 게임 프로세스도 없으면 오류로 알림.
/// (gakumas.exe 는 실제 게임을 다시 띄우고 자신은 코드 0 으로 바로 끝나는 경우가 있음)
/// elevated 이면 UAC 확인 창을 거쳐 관리자 권한으로 실행 (DMM 플레이어와 같은 방식)
pub fn launch(exe: &Path, args: &str, dir: &Path, elevated: bool, watch: Duration) -> Result<(), String> {
    let verb = wide(OsStr::new(if elevated { "runas" } else { "open" }));
    let file = wide(exe.as_os_str());
    let params = wide(OsStr::new(args));
    let dirw = wide(dir.as_os_str());
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.lpDirectory = dirw.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) == 0 {
            let e = GetLastError();
            return Err(if e == 1223 {
                "관리자 권한 확인 창에서 취소했습니다".to_string()
            } else {
                format!("게임을 실행하지 못했습니다 (Windows 오류 {e})")
            });
        }
        if info.hProcess.is_null() {
            return Ok(());
        }
        let result = if WaitForSingleObject(info.hProcess, watch.as_millis() as u32) == WAIT_OBJECT_0 {
            let mut code = 0u32;
            GetExitCodeProcess(info.hProcess, &mut code);
            std::thread::sleep(Duration::from_millis(1500));
            let name = exe.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if code == 0 || is_process_running(name) {
                Ok(())
            } else {
                Err(format!("게임이 바로 종료되었습니다 (코드 0x{code:08X})"))
            }
        } else {
            Ok(())
        };
        CloseHandle(info.hProcess);
        result
    }
}
