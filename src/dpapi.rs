//! Windows DPAPI: 현재 Windows 사용자만 풀 수 있게 암호화

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB};

unsafe fn take_blob(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let v = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec();
    LocalFree(blob.pbData as _);
    v
}

pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        if CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut output) == 0 {
            return Err("CryptProtectData failed".into());
        }
        Ok(take_blob(output))
    }
}

pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        if CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut output) == 0 {
            return Err("CryptUnprotectData failed (saved by a different Windows user?)".into());
        }
        Ok(take_blob(output))
    }
}

/// PowerShell 판 런처가 저장한 dmm_login.dat (ConvertFrom-SecureString 결과 = DPAPI 암호문의 16진수, UTF-16 문자열)
pub fn unprotect_powershell_secure_string(text: &str) -> Result<String, String> {
    let hex = text.trim().trim_start_matches('\u{feff}');
    if hex.len() % 2 != 0 || !hex.is_ascii() {
        return Err("not a hex string".into());
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|_| "not a hex string".to_string())?;
    let plain = unprotect(&bytes)?;
    let units: Vec<u16> = plain.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Ok(String::from_utf16_lossy(&units))
}
