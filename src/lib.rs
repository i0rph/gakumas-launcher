//! 학원 아이돌마스터 런처 (Rust 판)
//!
//! - `vpngate`  : VPN Gate 공개 서버 목록과 OpenVPN 설정 파일 해석
//! - `openvpn`  : OpenVPN 클라이언트 (TCP/UDP, tls-auth/tls-crypt, CBC/GCM). 가상 네트워크 장치를 만들지 않음
//! - `wireguard`: WireGuard 클라이언트 (boringtun). 가상 네트워크 장치를 만들지 않음
//! - `netstack` : 터널 위에서 도는 사용자 공간 TCP/IP 스택 (smoltcp) 과 HTTP(S) 요청
//! - `http`     : HTTP 요청/응답 처리와 DMM API 요청 형식
//! - `dpapi`    : PowerShell 판이 저장한 로그인 토큰 읽기 (Windows DPAPI)

pub mod dpapi;
pub mod http;
pub mod launcher;
pub mod netstack;
pub mod openvpn;
pub mod vpngate;
pub mod winutil;
pub mod wireguard;
