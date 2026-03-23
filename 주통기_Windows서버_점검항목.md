# 주요정보통신기반시설 - Windows 서버 취약점 점검 항목

> 출처: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (과학기술정보통신부, KISA)
> 참고: Windows 10/11 데스크톱에서도 대부분 항목 점검 가능 (서버 전용 항목 제외)

---

## 1. 계정 관리 (12개 항목)

| 항목코드 | 항목명 | 중요도 | 점검 내용 | PC 적용 |
|---------|--------|--------|----------|---------|
| W-01 | Administrator 계정 이름 바꾸기 | 상 | 기본 Administrator 계정명 변경 여부 | O |
| W-02 | Guest 계정 상태 | 상 | Guest 계정 비활성화 여부 | O |
| W-03 | 불필요한 계정 제거 | 상 | 미사용 계정 삭제 여부 | O |
| W-04 | 계정 잠금 임계값 설정 | 상 | 로그인 실패 시 계정 잠금 횟수 설정 (5회 이하) | O |
| W-05 | 해독 가능한 암호화를 사용하여 암호 저장 해제 | 상 | 해독 가능 암호 저장 비활성화 | O |
| W-06 | 관리자 그룹에 최소한의 사용자 포함 | 상 | Administrators 그룹 최소 인원 | O |
| W-07 | Everyone 사용 권한을 익명 사용자에게 적용 해제 | 상 | 익명 접근 제한 | O |
| W-08 | 계정 잠금 기간 설정 | 중 | 잠금 해제까지 대기 시간 설정 (60분 이상) | O |
| W-09 | 패스워드 복잡성 설정 | 상 | 영문/숫자/특수문자 혼합 필수 | O |
| W-10 | 패스워드 최소 암호 길이 | 상 | 8자 이상 설정 | O |
| W-11 | 패스워드 최대 사용 기간 | 상 | 90일 이하 설정 | O |
| W-12 | 패스워드 최소 사용 기간 | 중 | 1일 이상 설정 | O |

**점검 방법 (PowerShell/CMD):**
```powershell
# 계정 목록 확인
net user

# 패스워드 정책 확인
net accounts

# 로컬 보안 정책 내보내기
secedit /export /cfg C:\secpol.cfg
type C:\secpol.cfg

# 관리자 그룹 확인
net localgroup Administrators

# Guest 계정 상태
net user Guest
```

---

## 2. 서비스 관리 (19개 항목)

| 항목코드 | 항목명 | 중요도 | 점검 내용 | PC 적용 |
|---------|--------|--------|----------|---------|
| W-13 | 공유 권한 및 사용자 그룹 설정 | 상 | 공유 폴더 권한에 Everyone 제거 | O |
| W-14 | 하드디스크 기본 공유 제거 | 상 | C$, D$, ADMIN$ 기본 공유 제거 | O |
| W-15 | 불필요한 서비스 제거 | 상 | Alerter, Clipbook, Messenger 등 제거 | O |
| W-16 | NetBIOS 바인딩 서비스 구동 점검 | 상 | NetBIOS over TCP/IP 비활성화 | O |
| W-17 | FTP 서비스 구동 점검 | 상 | 불필요 시 FTP 비활성화 | O |
| W-18 | FTP 디렉토리 접근 권한 설정 | 상 | FTP 홈 디렉토리 Everyone 쓰기 제거 | 서버 |
| W-19 | Anonymous FTP 금지 | 상 | 익명 FTP 접속 비활성화 | 서버 |
| W-20 | FTP 접근 제어 설정 | 중 | IP 기반 접근 제어 설정 | 서버 |
| W-21 | DNS Zone Transfer 설정 | 상 | 특정 서버만 zone transfer 허용 | 서버 |
| W-22 | RDS(Remote Data Services) 제거 | 상 | IIS RDS 제거 | 서버 |
| W-23 | 최신 서비스팩 적용 | 상 | 최신 서비스팩 설치 여부 | O |
| W-24 | 최신 HOT FIX 적용 | 상 | 최신 핫픽스 적용 여부 | O |
| W-25 | 백신 프로그램 업데이트 | 상 | 백신 엔진 최신 업데이트 | O |
| W-26 | 로그의 정기적 검토 및 보고 | 중 | 이벤트 로그 정기 검토 | O |
| W-27 | 원격으로 액세스할 수 있는 레지스트리 경로 | 상 | 원격 레지스트리 접근 제한 | O |
| W-28 | IIS 웹서비스 정보 숨김 | 중 | HTTP 헤더에서 서버 정보 제거 | 서버 |
| W-29 | IIS 디렉토리 리스팅 제거 | 상 | 디렉토리 검색 비활성화 | 서버 |
| W-30 | IIS 상위 디렉토리 접근 금지 | 상 | 부모 경로 사용 비활성화 | 서버 |
| W-31 | IIS 불필요한 파일 제거 | 중 | 샘플 애플리케이션, 도움말 파일 삭제 | 서버 |

**점검 방법 (PowerShell):**
```powershell
# 공유 폴더 확인
net share

# 서비스 목록 확인
Get-Service | Where-Object {$_.Status -eq 'Running'}

# 방화벽 규칙 확인
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'}

# NetBIOS 설정 확인
Get-WmiObject Win32_NetworkAdapterConfiguration | Select-Object Description, TcpipNetbiosOptions

# 설치된 핫픽스 확인
Get-HotFix | Sort-Object InstalledOn -Descending
```

---

## 3. 보안 관리 (16개 항목)

| 항목코드 | 항목명 | 중요도 | 점검 내용 | PC 적용 |
|---------|--------|--------|----------|---------|
| W-32 | 백신 프로그램 설치 | 상 | 바이러스 백신 설치 여부 | O |
| W-33 | SAM 파일 접근 통제 설정 | 상 | SAM 파일 (계정 DB) 접근 권한 제한 | O |
| W-34 | 화면 보호기 설정 | 상 | 10분 이하 대기시간, 암호 보호 설정 | O |
| W-35 | 로그온하지 않고 시스템 종료 허용 해제 | 중 | 로그온 없이 시스템 종료 비활성화 | O |
| W-36 | 원격 시스템에서 강제로 시스템 종료 제한 | 상 | 원격 종료 권한 제한 | O |
| W-37 | 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 해제 | 중 | 감사 실패 시 강제 종료 비활성화 | O |
| W-38 | SAM 계정과 공유의 익명 열거 허용 안 함 | 상 | 익명 사용자의 계정/공유 열거 차단 | O |
| W-39 | Autologon 기능 제어 | 상 | 자동 로그온 비활성화 | O |
| W-40 | 이동식 미디어 포맷 및 꺼내기 허용 | 중 | Administrators만 이동식 미디어 관리 | O |
| W-41 | 마지막 사용자 이름 표시 안 함 | 중 | 로그온 화면에서 마지막 사용자명 숨김 | O |
| W-42 | 보안 감사 정책 설정 | 상 | 로그온, 계정 관리, 정책 변경 등 감사 | O |
| W-43 | 원격 터미널 접속 설정 (RDP) | 상 | 불필요 시 RDP 비활성화 또는 접근 제한 | O |
| W-44 | NTFS 파일 시스템 사용 | 상 | FAT32 대신 NTFS 사용 | O |
| W-45 | 이벤트 로그 관리 설정 | 중 | 로그 최대 크기, 보존 정책 설정 | O |
| W-46 | 원격 레지스트리 서비스 비활성화 | 상 | RemoteRegistry 서비스 중지 | O |
| W-47 | 익명 SID/이름 변환 허용 안 함 | 중 | 익명 사용자의 SID 변환 차단 | O |

**점검 방법 (PowerShell/CMD):**
```powershell
# 화면 보호기 설정 확인 (레지스트리)
Get-ItemProperty "HKCU:\Control Panel\Desktop" | Select-Object ScreenSaveActive, ScreenSaverIsSecure, ScreenSaveTimeOut

# 감사 정책 확인
auditpol /get /category:*

# 자동 로그온 확인
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object AutoAdminLogon, DefaultUserName

# RDP 설정 확인
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | Select-Object fDenyTSConnections

# 원격 레지스트리 서비스 상태
Get-Service RemoteRegistry | Select-Object Status, StartType

# NTFS 확인
Get-Volume | Select-Object DriveLetter, FileSystemType
```

---

## 4. 패치 관리 (W-23, W-24에 포함)

> 서비스 관리 섹션의 W-23(최신 서비스팩), W-24(최신 HOT FIX) 항목 참고

---

## 5. 로그 관리 (W-26, W-42, W-45에 포함)

> 서비스 관리의 W-26, 보안 관리의 W-42, W-45 항목 참고

---

## Windows PC 전용 점검 항목 (참고)

주통기에서는 PC를 별도 카테고리로 분류합니다 (PC-01 ~ PC-13). 항목이 적고 단순하여, 본 프로젝트에서는 Windows 서버 항목(W) 기준으로 점검하되 Windows 10/11 PC에서 테스트합니다.

| 항목코드 | 항목명 | 점검 내용 |
|---------|--------|----------|
| PC-01 | 패스워드 주기적 변경 | 패스워드 정기 변경 여부 |
| PC-02 | 패스워드 정책 설정 | 조직 보안 정책에 맞는 패스워드 설정 |
| PC-03 | 공유 폴더 제거 | 불필요한 공유 폴더 제거 |
| PC-04 | 불필요한 서비스 제거 | 사용하지 않는 서비스 비활성화 |
| PC-05 | 메신저 사용 금지 | Windows Messenger 등 비활성화 |
| PC-06 | HOT FIX 등 최신 보안패치 | 최신 보안 업데이트 적용 |
| PC-07 | 최신 서비스팩 적용 | 최신 서비스팩 설치 |
| PC-08 | 바이러스 백신 설치 및 업데이트 | 백신 설치 및 정기 업데이트 |
| PC-09 | 백신 실시간 감시 활성화 | 실시간 보호 기능 활성화 |
| PC-10 | OS 침입 차단 기능 활성화 | Windows 방화벽 활성화 |
| PC-11 | 화면 보호기 설정 | 대기시간 및 암호 보호 설정 |
| PC-12 | 이동식 미디어 보안 대책 | USB 자동실행 비활성화 |
| PC-13 | 비인가 무선 랜 사용 제한 | 승인되지 않은 Wi-Fi 차단 |

---

## 분류별 요약

| 분류 | 항목 수 | PC 적용 가능 |
|------|---------|-------------|
| 계정 관리 | 12 | 12 |
| 서비스 관리 | 19 | 12 (IIS/FTP 서버 전용 7개 제외) |
| 보안 관리 | 16 | 16 |
| **합계** | **47** | **40** |

> 참고: 위 항목은 웹 검색 기반 정리이며, 실제 KISA 가이드라인 원본(W-01~W-84)에는 IIS 관련 세부 항목 등이 더 포함되어 있습니다. 정확한 전체 목록은 KISA 원본 PDF를 반드시 확인하세요.
