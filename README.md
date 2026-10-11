# MyPgpDecrypt

Windows 전용 PGP 복호화 도구 (Rust, native-windows-gui + rPGP)

## 요구 사항
- **Windows 10 이상 (64비트)**: 최신 Rust 표준 라이브러리가 Windows 10 이상에만 있는 시스템 함수(`WaitOnAddress`, `ProcessPrng`)를 쓰기 때문에, Windows 7/8 에서는 정상적으로 실행되지 않는다.

## 사용
- `MyPgpDecrypt.exe` **GUI**
  - "PGP 파일 선택" 버튼으로 1개 이상의 PGP 파일을 선택하면 복호화한다.
  - 탐색기에서 1개 이상의 PGP 파일을 끌어다 놓으면 복호화한다.
  - "설정" 창에서는 개인키와 암호를 입력/저장할 수 있고, 탐색기에서 마우스 우클릭 메뉴를 등록/해제할 수 있다. (우클릭을 등록시켜 놓으면 MyPgpDecrypt를 실행시키지 않고 탐색기에서 바로 복호화시킬 수 있으므로 편리함)
  - 메인 창의 위치는 종료 시 `window.ini` 파일에 저장되고 다음 실행 때 복원된다. (단, 연결이 끊긴 모니터 등 화면 밖 위치일 때는 무시되고 기본 위치가 사용됨)
- `MyPgpDecrypt.exe` **CLI**
  - `-h`, `--help`: 도움말 출력
  - `-f, --force`: 기존 복호화 파일 덮어쓰기
  - GUI 서브시스템 실행 파일이라서 cmd/PowerShell은 실행 중에도 프롬프트가 얻어진다. 만약 실행이 완료될 때까지 프롬프트가 뜨지 않게 하려면 아래와 같이 `start /wait`를 사용하면 된다.
    ```batch
    start "" /wait MyPgpDecrypt.exe {PGP files}
    ```
    또는 아래와 같이 MyPgpDecrypt.cmd 파일을 이용하면 된다.
    ```batch
    MyPgpDecrypt.cmd {PGP files}
    ```
- 설정 창은 개인키와 암호의 저장 상태를 표시한다.
  - 개인키/암호가 저장된 상태이면 제목에 "키/암호 저장됨"으로 표시되고, 키 칸에 Fingerprint·사용자 ID(비밀 값은 표시 안 함) 정보가 표시되고, 암호 칸에 "저장됨"으로 표시된다.
  - 암호만 바꾸려면 새 암호만 입력하고 저장 버튼을 누르면 된다.
  - CLI로 실행시킬 때도 이 저장값을 쓰므로, 먼저 GUI 설정에서 개인키와 암호를 입력해야 한다.
- 복호화한 파일은 입력 PGP 파일과 같은 폴더에 저장되고, 파일의 이름은 확장자 .pgp/.gpg 확장자를 뺀 이름으로 한다.
- 복호화시 동일 파일이 이미 있으면 GUI는 덮어쓸지 확인하는 팝업이 뜨고 ("아니오"를 고른 파일은 처리 목록에서 제외), CLI 는 `-f` 또는 `--force` 옵션이 있어야 덮어쓴다.
- 탐색기 우클릭 메뉴 "내 PGP key로 복호화"는 설정 창의 "우클릭 메뉴 등록/해제" 버튼으로 등록 또는 해제시킬 수 있다.
- 복호화 창의 "취소"(또는 창 닫기)는 진행 중인 복호화를 즉시 중단하고 창을 닫는다. (끝난 파일은 유지, 중단된 파일의 중간 파일은 삭제됨)

## 설정 파일
설정 파일은 `%APPDATA%\MyPgpDecrypt\` (즉, `C:\Users\<사용자>\AppData\Roaming\MyPgpDecrypt\`)폴더에 저장된다. 다음 2가지 파일이 있다.
- `%APPDATA%\MyPgpDecrypt\key.bin`: PGP 개인키와 키 암호를 Windows DPAPI로 암호화하여 저장한다. 설정 창의 "키/암호 저장"으로 생성된다. 이 파일을 지우면 저장된 개인키/암호가 사라지므로, 다시 입력해야 한다.
- `%APPDATA%\MyPgpDecrypt\window.ini`: 메인 창의 위치 등이 저장된다. 이 파일을 지우면 디폴트 위치로 시작된다.

추가로 탐색기 우클릭 메뉴를 등록하면 레지스트리 `HKCU\Software\Classes\SystemFileAssociations\.pgp\shell\MyPgpDecrypt` 항목으로 설정된다.

## 빌드 방법
- 이 프로그램은 Windows 전용이므로, 편의상 `.cargo/config.toml` 파일을 아래와 같이 작성하였다.
  ```toml
  [build]
  target = "x86_64-pc-windows-gnu"
  ```
- 따라서 Linux 환경에서 아래와 같이 실행시키면 Windows 용으로 빌드된다.
  ```sh
  cargo build --release
  ```
