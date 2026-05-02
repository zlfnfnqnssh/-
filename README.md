# AI 기반 취약점 자동 점검 및 자가 조치 웹 플랫폼

> 주요정보통신기반시설(주통기) 보안 가이드라인 기반, LLM(Gemini)을 활용한 자동 취약점 판정 및 맞춤형 조치 스크립트 제공 웹 플랫폼
> 중부대학교 정보보호학과 2026-1 캡스톤디자인

---

## 프로젝트 개요

점검 대상 시스템(Linux/Windows)의 구성 정보를 파악하고, KISA 주통기 가이드라인 기반으로 컴플라이언스를 점검하는 전 과정을 자동화합니다.
관리자(Admin) 권한에서는 가이드라인 변경에 따른 점검 스크립트의 자동 업데이트를 수행하며,
사용자(Users) 권한에서는 클릭 한 번으로 시스템 진단부터 LLM(Gemini) 기반 맞춤형 조치 스크립트 및 설명 생성까지 원스톱으로 제공합니다.

> **판정 방식**: 가이드라인을 사전 임베딩하는 RAG 방식이 아니라, **PostgreSQL `vs_guideline_items` 테이블에서 항목별 `criteria + remediation_guide + check_examples`를 LLM 프롬프트에 직접 주입**하는 방식입니다. 항목코드(item_code)로 1:1 직접 조회 가능하므로 벡터 검색이 불필요하고, 토큰 효율과 정확성이 더 높습니다.

---

## 4인 통합 아키텍처

4명의 팀원이 각자 다른 영역을 담당하며, **`integration/` 디렉토리의 어댑터 4개**가 PostgreSQL `forensic_db`를 허브로 모든 흐름을 연결합니다. 각자 본인 코드는 거의 0줄 변경으로 통합됨.

| 사람 | 영역 | 코드 위치 |
|---|---|---|
| **은이 (euni)** | 가이드라인 입력 + PDF 비교 + 변경 이력 | `tools/jutonggi_parser/` (PDF 파서 + sync_items)<br>`tools/mcp_server/` (MCP 인터페이스) |
| **서연 (syeon)** | Linux 점검·판정 (자체 파이프라인) | `vulnerability-scanner/scripts/linux/U-01~U-72.py`<br>`tools/syeon_engine/` (runner/collector/batch_judge/main 등 8파일) |
| **본인 (riri)** | Windows 점검 + 백엔드 + 패치 | `vulnerability-scanner/scripts/{windows,pc}/`<br>`vulnerability-scanner/{engine,database,web/routes/scan,patch}` |
| **서진 (seojin)** | 웹 UI + 사용자 관리 + 감사 | `vulnerability-scanner/web/templates/*` (Tailwind)<br>`web/routes/admin.py` (사용자관리·patch_history) |

데이터 흐름: PDF → 은이 native 테이블 → `vs_guideline_items` → SQLite 미러 (서연) / 본인 LLM 판정 → `vs_judgments` → 서진 UI 표시 → 본인 패치 실행 → `vs_patch_executions`. 자세한 통합 내역은 [INTEGRATION_FIXES.md](INTEGRATION_FIXES.md) 참조.

---

## 핵심 기능

### 1. 보안 가이드라인(PDF) 변경 자동 반영 (Admin)
- 새 KISA 가이드라인 PDF 업로드 → 은이 파서로 파싱 → forensic_db 적재
- **PDF 한 명령으로 4단계 자동**: vulnerabilities (은이 native) → vulnerabilities_history → item_changelog → vs_guideline_items → SQLite guidelines.db
- 기존 DB 버전과 변경점 자동 도출 (added/modified/removed)

### 2. 사용자 맞춤형 시스템 점검 (Users)
- **machine_id 기반 scan_id**: Windows `wmic csproduct UUID` / Linux `/etc/machine-id` 활용
  - 같은 PC·사용자·OS는 prefix 공유 → 이력 추적 가능
  - 형식: `{os}_{machine_id}_{user_short}_{timestamp}`
- '점검 시작' 클릭 시 OS 자동 판단 → 점검 스크립트 5개씩 병렬 실행 → JSON 반환 → DB 적재 → LLM 판정
- Linux 일 때는 서연 `tools.syeon_engine.main.run_pipeline` 으로 위임 (`integration/syeon_db_adapter.py`가 결과를 PostgreSQL로 통합)

### 3. LLM (Gemini) 지능형 판정 파이프라인
- **양호(규칙 기반):** 여러 항목 묶어 일괄 LLM 검증 (Batch)
- **취약/판정불가:** 개별 병렬 전송 (Parallel)
- **판정 정책**: "판정불가" 차단 → 항상 양호/취약 / 불확실 시 보수적으로 취약
- **가이드라인 DB 직접 주입** (RAG 아님): `vs_guideline_items`에서 항목별 데이터 프롬프트에 포함

### 4. UAC 패치 자동 실행 + Gemini 재작성 루프
- 판정 결과의 `patch_script`를 **UAC 자동 승격**(`Start-Process -Verb RunAs`) 으로 실행
- 실행 실패 시 Gemini가 stderr 보고 **자동 재작성** (최대 3회)
- 안전장치 [_safety_check](vulnerability-scanner/web/routes/patch.py#L69) — 위험 패턴 차단
- **AI 패치 재시도** — patch_script 비어있는 항목에 detail 페이지 버튼 제공, LLM 재호출

### 5. PDF 보고서 자동 생성 & 다운로드
- 스캔 완료 시 ReportLab + matplotlib로 PDF 자동 생성
- 표지 / 양호·취약 비율 차트 / 항목별 상세 / 조치 방법 / 부록 구성

### 6. 시계열 점검 비교 시각화
- 과거 이력과 자동 대조 — "여전히 취약 / 새로 취약 / 양호 전환" 상태 시각화

### 7. 통합 진행률 표시
- UAC 대기 → 스크립트 실행 중 → LLM 판정(0~100%)

---

## 점검 항목 현황 (2021 KISA 기준)

| OS | 항목 범위 | 스크립트 수 |
|----|-----------|------------|
| Linux (Unix) | U-01 ~ U-72 | **72개** |
| Windows Server | W-01 ~ W-82 (W-07/08/09 빠짐) | **79개** |
| Windows PC | PC-01 ~ PC-19 | **19개** |
| **합계** | | **170개** |

기존 2026 가이드라인 기준 스크립트는 `scripts/{windows,pc,linux}_2026/`에 보관 (총 154개).

LLM 판정 분포 (Windows 79개 실측, 2026-05-03):
- 🟢 양호 47개 (60%) / 🔴 취약 32개 (40%) — LLM이 모두 판정 (규칙불가 0)
- 취약 32개 중 자동 패치 가능 20 / 정책 판단 필요 12 (수동 안내)

---

## 설치 및 실행 방법

### 🚀 원클릭 런처 (Windows 추천)

```cmd
start_server.bat
```

루트의 [start_server.bat](start_server.bat) 더블클릭 또는 cmd 실행. 다음을 자동 처리:
- Python 3.10+ 확인
- `pip install -r requirements.txt` (`.deps_installed` 마커로 한 번만)
- Docker `postgres-db` 자동 기동 (`docker compose v2` + `docker-compose v1` fallback)
- `.env` 자동 생성 (`.env.example` → `.env`)
- 서버 기동 + 브라우저 자동 오픈 (http://localhost:8081/login)

### 수동 설치

#### 사전 요구사항
| 구분 | 버전 | 비고 |
|------|------|------|
| Python | 3.10 이상 | |
| Node.js | 18 이상 | Gemini CLI (npx) 실행용 |
| PostgreSQL | 14 이상 | Docker 컨테이너 권장 |
| Docker | 최신 | PostgreSQL 실행용 |

#### 1. 저장소 클론
```bash
git clone https://github.com/zlfnfnqnssh/-.git
cd 취약점진단
```

#### 2. Python 패키지 + Node 패키지
```bash
cd vulnerability-scanner
pip install -r requirements.txt
npm install -g @google/gemini-cli   # 또는 npx 자동 설치
```

#### 3. PostgreSQL 기동 (Docker)
```bash
docker compose up -d   # 루트의 docker-compose.yml 사용
```

#### 4. 환경변수 (`.env`)
```bash
cp vulnerability-scanner/.env.example vulnerability-scanner/.env
# 필요 시 PG_PASSWORD, GEMINI_MODEL 등 수정
```

#### 5. (옵션) 가이드라인 PDF 적재
```bash
cd vulnerability-scanner
python -m integration.euni_adapter --pdf "../docs/reference/2021_*.pdf" --label "2021 KISA"
# → vulnerabilities + history + changelog + vs_guideline_items + SQLite guidelines.db 모두 갱신
```

#### 6. 서버 실행
```bash
python main.py    # 포트 8081
```

#### 7. 웹 접속
- 대시보드: http://localhost:8081
- 관리자 페이지: http://localhost:8081/admin
- 기본 관리자 계정: `admin` / `admin1234`

---

## 기술 스택

| 구분 | 기술 |
|------|------|
| 언어 | Python 3.10+ |
| LLM | Gemini CLI (`npx @google/gemini-cli`, `gemini-2.0-flash`) |
| RDB | PostgreSQL (Docker, DB: `forensic_db`, `vs_*` 11개 테이블 + 은이 native 3개) |
| SQLite | 서연 batch_judge 가이드라인 미러 (`tools/syeon_engine/db/guidelines.db`) |
| 웹 프레임워크 | FastAPI + Jinja2 (SSR) |
| ASGI 서버 | uvicorn (포트 8081) |
| UI | Tailwind CSS (서진 디자인) |
| PDF 파싱 | pdfplumber (은이 어댑터) / PyMuPDF |
| PDF 보고서 | ReportLab + matplotlib |
| 비동기 | asyncio + SQLAlchemy async + asyncpg + psycopg |
| 인증 | bcrypt + 세션 기반 |
| 수집 스크립트 | PowerShell (Windows) / Bash (Linux) |
| 권한 상승 | UAC (`Start-Process -Verb RunAs` + Base64 인코딩) / sudo |

> 🚫 **사용 안 하는 기술**
> - Vector DB (Milvus 등) — 가이드라인은 PostgreSQL에 직접 저장
> - 임베딩 모델 — 항목코드 1:1 매핑이라 불필요
> - RAG 검색 — 프롬프트에 가이드라인을 직접 주입

---

## 디렉토리 구조

```
취약점진단/
├── start_server.bat              # 🚀 Windows 원클릭 런처 (자동 설치 + 서버 + 브라우저)
├── docker-compose.yml            # PostgreSQL 컨테이너 정의
├── README.md / INTEGRATION_FIXES.md
├── docs/                         # 가이드라인 PDF, 발표 자료, 참조 데이터
│   └── reference/2021_*.pdf
├── tools/                        # 4인 중 은이/서연 코드
│   ├── jutonggi_parser/          # 은이 PDF 파서 + DB sync (forensic_db.vulnerabilities)
│   ├── mcp_server/               # 은이 MCP 서버
│   └── syeon_engine/             # 서연 Linux 파이프라인 (8 .py)
└── vulnerability-scanner/        # 본인(riri) + 서진(seojin) 코드
    ├── main.py                   # FastAPI 앱 (포트 8081)
    ├── .env / .env.example
    ├── requirements.txt
    ├── config/                   # settings + machine_id
    ├── auth/                     # 세션 기반 인증
    ├── integration/              # ★ 4인 통합 어댑터 (4개)
    │   ├── euni_adapter.py       #   은이 PDF → forensic_db (vulnerabilities + vs_guideline_items + SQLite ETL)
    │   ├── syeon_db_adapter.py   #   서연 DBWriter 호환 PostgreSQL 어댑터
    │   ├── syeon_guideline_sync.py #  vs_guideline_items → SQLite 미러
    │   └── legacy_linux_adapter.py # 비상용 fallback
    ├── scripts/
    │   ├── windows/, pc/, linux/         # 2021 신규 (170개)
    │   └── windows_2026/, pc_2026/, linux_2026/  # 2026 보관
    ├── engine/
    │   ├── llm_judge.py          # Gemini CLI 판정
    │   └── pipeline.py           # 스마트 3분류 파이프라인
    ├── database/
    │   ├── models.py             # SQLAlchemy (vs_* 11 테이블)
    │   └── repository.py         # 비동기 CRUD
    ├── report/                   # ReportLab PDF + 비교
    └── web/
        ├── routes/{scan,patch,admin,auth,pages,report}.py
        ├── templates/            # Jinja2 (Tailwind)
        └── static/               # CSS, JS
```

---

## 데이터베이스 스키마

### `vs_*` 11개 테이블 (본인 정의)
| 테이블 | 역할 |
|---|---|
| `vs_users` | 사용자/관리자 계정 (bcrypt) |
| `vs_login_attempts` | 로그인 시도 감사 로그 |
| `vs_guideline_versions` | 주통기 가이드라인 버전 이력 |
| `vs_guideline_items` | 항목별 criteria/remediation/examples |
| `vs_guideline_diffs` | 버전 간 add/mod/del 차이 |
| `vs_script_registry` | 점검 스크립트 메타정보 |
| `vs_scan_results` | 수집 결과 (item별 collected_value) |
| `vs_judgments` | LLM 판정 결과 (양호/취약, reason, patch_script) |
| `vs_patch_executions` | 패치 실행 감사 (UAC 결과, 재작성 여부, stdout/stderr) |
| `vs_reports` | PDF 보고서 메타 |
| `vs_comparisons` | 이전 진단 비교 (개선/악화/유지/신규) |

### 은이 native 3개 테이블 (`forensic_db` 안에 공존)
| 테이블 | 역할 |
|---|---|
| `vulnerabilities` | 은이 PDF 파서 마스터 (현재 가이드라인) |
| `vulnerabilities_history` | PDF 버전 이력 |
| `item_changelog` | 항목별 변경 로그 (added/modified/removed) |

은이 MCP 서버는 native 테이블을, 본인 LLM 판정은 `vs_*`을 사용. 어댑터가 한 방향 sync.

---

## 향후 확장 과제

- ~~Linux 흐름 통합 (서연 main.run_pipeline)~~ — ✅ `integration/syeon_db_adapter.py`로 완료, WSL 환경 검증 남음
- ~~신규 PDF → 점검 스크립트 자동 생성~~ — ✅ 9-agent 병렬 작성 워크플로 검증됨 (170개)
- ~~UAC 패치 + Gemini 재작성 루프~~ — ✅ 동작 확인
- 한 사용자가 서로 다른 로컬 OS 여러 대를 운용하는 케이스 정식 반영
- LLM 판정 정확도 벤치마크 및 회귀 테스트
- PDF 리포트 ReportLab `LayoutError` 회피 (긴 raw_output 페이지 분할)
- 보호된 작업 (TrustedInstaller 권한 필요) 패치 안내 UI 강화
