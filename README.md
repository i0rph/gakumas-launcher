# 학원 아이돌마스터 런처

DMM GAME PLAYER와 VPN 없이 학원 아이돌마스터(DMM판)를 실행하는 Windows 런처입니다.

## 기능

- **일본 연결 내장**: DMM 실행 토큰을 받을 때만 프로그램 안에서 VPN Gate 일본 서버에 연결합니다. Windows 네트워크 설정은 바꾸지 않습니다. 직접 켠 VPN을 쓰는 모드도 있습니다.
- **업데이트**: 바뀐 게임 파일만 DMM 서버에서 받아 교체합니다.
- **로그인**: 프로그램 안의 로그인 창에서 로그인하며, 로그인 상태를 유지합니다.
- **편의 설정**: 실행 시 자동 시작, 게임 실행 후 런처 종료.

## 내려받기

- 태그(`v*`)를 올리면 [Releases](../../releases)에 `GakumasLauncher.exe`가 올라갑니다.
- `main` 브랜치의 최신 빌드는 [Actions](../../actions)의 각 실행 결과에서 받을 수 있습니다.

실행 파일 하나로 동작합니다. Windows 10/11에 기본으로 들어 있는 WebView2 런타임이 필요하고, 게임은 DMM GAME PLAYER로 한 번 설치되어 있어야 합니다.

## 빌드

Rust(stable, MSVC)가 필요합니다.

```
cargo build --release --bin GakumasLauncher
```

결과물은 `target/release/GakumasLauncher.exe`입니다.

## 주의

- DMM은 일본 외 지역 이용을 지원하지 않습니다. 사용에 따른 책임은 사용자에게 있습니다.
- VPN Gate는 쓰쿠바대학의 학술 실험 프로젝트입니다.
- 글꼴(나눔스퀘어 라운드, SIL OFL 1.1)과 아이콘의 하츠보시학원 문장은 MIT 라이선스에 포함되지 않습니다. [LICENSE](LICENSE)를 참고하세요.
