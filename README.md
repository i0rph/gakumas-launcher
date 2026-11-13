# 학원 아이돌마스터 런처

DMM GAME PLAYER와 VPN 없이 학원 아이돌마스터(DMM판)를 실행하는 Windows 런처입니다.

[Releases](../../releases)에서 `GakumasLauncher.exe`를 받아 실행하세요. 게임은 DMM GAME PLAYER로 한 번 설치되어 있어야 합니다.

## 일본 연결 방식

| 방식 | 설명 |
|---|---|
| VPN Gate | 기본값. 쓰쿠바대 VPN Gate 공개 서버에 런처 안에서만 연결합니다. 따로 설정할 것이 없습니다. |
| VPN 파일 | 사용 중인 VPN 서비스의 설정 파일로 런처 안에서 연결합니다. OpenVPN(`.ovpn`)과 WireGuard(`.conf`)를 지원합니다. |
| 일반 연결 | VPN 없이 PC 인터넷을 그대로 씁니다. 일본 밖이라면 VPN 앱으로 일본에 먼저 연결하세요. |

VPN Gate와 VPN 파일은 Windows 네트워크 설정을 바꾸지 않고, 런처의 통신만 VPN을 거칩니다.

### VPN 파일 사용법

1. VPN 서비스의 계정 페이지에서 **일본 서버**의 수동 설정 파일(OpenVPN 또는 WireGuard)을 받습니다.
2. 런처에서 **VPN 파일** → **파일 선택**으로 받은 파일을 고릅니다.
3. 아이디와 비밀번호가 필요한 OpenVPN 파일이면 **계정**에 입력합니다. 서비스 로그인 비밀번호가 아니라 수동 설정용(OpenVPN) 계정인 경우가 많습니다.

설정 파일과 계정은 이 PC의 Windows 계정에서만 풀 수 있게 암호화해 저장합니다.

## 빌드

```
cargo build --release --bin GakumasLauncher
```

## 주의

DMM은 일본 외 지역 이용을 지원하지 않습니다. 사용에 따른 책임은 사용자에게 있습니다.
