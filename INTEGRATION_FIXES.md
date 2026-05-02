# 통합 수정사항 정리 (2026-05-03 갱신)

> riri 브랜치 통합 후 4명의 작품이 한 시스템에서 동작하도록 수정한 내역.
> **원칙: 각자 본인 작품 거의 안 건드림 + integration/ 어댑터로만 연결**

---

## 🗺️ 4명 작품 위치·역할

| 사람 | 영역 | 코드 위치 |
|---|---|---|
| **은이 (euni)** | 가이드라인 입력 + PDF 비교 + 변경 이력 | `tools/jutonggi_parser/` (PDF 파서 + sync_items)<br>`tools/mcp_server/` (MCP 인터페이스)<br>`tools/diagnosis/` `tools/ingest.py` |
| **서연 (syeon)** | Linux 점검·판정 (자체 파이프라인) | `vulnerability-scanner/scripts/linux/U-01~U-72.py` (Linux 점검)<br>`tools/syeon_engine/` (runner/collector/batch_judge/db_writer/main 등 8파일) |
| **본인 (riri)** | Windows 점검 + 백엔드 + 패치 | `vulnerability-scanner/scripts/windows/`<br>`vulnerability-scanner/{engine,database,web/routes/scan,patch}` |
| **서진 (seojin)** | 웹 UI + 사용자 관리 + 감사 | `vulnerability-scanner/web/templates/*` (Tailwind)<br>`web/routes/admin.py` (사용자관리·patch_history) |

---

## 🔌 4가지 어댑터 (integration/)

### 1️⃣ `integration/euni_adapter.py` — 은이 PDF → forensic_db 통합

**흐름**:
```
PDF 파일
   ↓ tools/jutonggi_parser/parser.py (은이 코드 그대로)
dict 리스트
   ↓ tools/jutonggi_parser/db.py:JutonggiRepository.sync_items() (은이 코드 그대로)
[은이 native 테이블] vulnerabilities + vulnerabilities_history + item_changelog
   ↓ 어댑터의 한 방향 sync (transform + filter)
[본인 허브] vs_guideline_items + vs_guideline_versions
```

**기능**:
- PDF → dict (은이 parser)
- dict → forensic_db `vulnerabilities` 등 3 테이블 (은이 db.py — UPSERT + history + changelog 자동)
- `vulnerabilities` → `vs_guideline_items` 한 방향 sync (어댑터)
- 12개 필드 매핑 + OS/prefix 필터 (linux/windows + U/W/PC)

**사용**:
```bash
cd vulnerability-scanner
python -m integration.euni_adapter --pdf "../docs/reference/주요정보통신기반시설_*.pdf"
```

**효과**:
- 은이 MCP 서버 (vulnerabilities 테이블 사용) 와 본인 시스템 (vs_guideline_items 사용) 양쪽 모두 작동
- PDF 버전 비교는 은이 db.py 가 자동 처리 (`vulnerabilities_history` + `item_changelog`)

---

### 2️⃣ `integration/syeon_db_adapter.py` — 서연 DBWriter 호환 PostgreSQL 어댑터

**역할**: 서연 `tools/syeon_engine/db_writer.DBWriter` 와 **완전히 동일한 인터페이스** 제공, 내부만 PostgreSQL 사용.

**테이블 매핑**:
| 서연 SQLite | 본인 PostgreSQL |
|---|---|
| judge_results | vs_judgments |
| patch_results | vs_patch_executions |
| final_records | vs_judgments + vs_comparisons (재구성) |

**status_change 매핑** (서연 → 본인 vs_comparisons):
- "신규" → "신규"
- "유지" → "유지_양호" / "유지_취약" (current 결과에 따라)
- "개선" → "개선"
- "악화" → "악화"

**호출 방식 (서연 main.py 0줄 수정)**: `sys.modules['db_writer']` 스왑

```python
sys.modules["db_writer"] = integration.syeon_db_adapter
from tools.syeon_engine.main import run_pipeline
records = await run_pipeline(sudo_password=...)
# → 서연 main.py 의 'from db_writer import DBWriter' 가 우리 어댑터 import
```

---

### 3️⃣ `integration/syeon_guideline_sync.py` — vs_guideline_items → SQLite ETL

**역할**: 서연 `tools/syeon_engine/batch_judge.py:_DB` 가 SQLite `guidelines.db` 를 읽으므로, PostgreSQL `vs_guideline_items` 데이터를 SQLite 로 한 방향 복사.

**매핑**:
| PostgreSQL vs_guideline_items | SQLite guidelines |
|---|---|
| item_code | item_code (PK) |
| importance | severity |
| criteria | standard |
| remediation_guide | remediation |
| description | check_point + content |

**서연 코드 0줄 변경**. 환경변수 `GUIDELINE_DB_PATH` 가 이 SQLite 파일을 가리키게 설정만 하면 됨.

**사용**:
```bash
cd vulnerability-scanner
python -m integration.syeon_guideline_sync
# → tools/syeon_engine/db/guidelines.db 생성

# 환경변수 (PowerShell)
$env:GUIDELINE_DB_PATH = "tools\syeon_engine\db\guidelines.db"
```

---

### 4️⃣ `integration/legacy_linux_adapter.py` — 비상용 fallback (deprecated)

서연 main.py 호출 흐름이 실패할 경우 본인 scan.py 가 직접 Linux 스크립트 실행하도록 되돌리는 어댑터. 현재는 사용 안 함.

---

## 🛠️ 본인 코드 변경 (web/routes/scan.py — +50줄)

신규 함수 `_run_linux_via_syeon(scan_id, user_id)` 추가:
- `tools.syeon_engine` 패키지 import (sys.path 보정)
- `sys.modules['db_writer']` 를 `integration.syeon_db_adapter` 로 swap
- 서연 `run_pipeline(sudo_password='', generate_patch=False)` 호출
- 결과는 어댑터가 PostgreSQL에 저장

`_run_full_scan` 의 시작부 Linux 분기 추가:
```python
if target_os == "linux":
    ok = await _run_linux_via_syeon(scan_id, user_id)
    _scan_pipelines[scan_id]["status"] = "completed" if ok else "error"
    return
# 이하 Windows 흐름은 기존과 동일
```

---

## 📁 디렉토리 구조 (통합 후 최종)

```
취약점진단/
├── README.md / INTEGRATION_NOTES.md / INTEGRATION_FIXES.md
├── docker-compose.yml / .gitignore
├── vulnerability-scanner/          ★ 메인 FastAPI 시스템
│   ├── scripts/
│   │   ├── windows/                # riri (W-01~W-64 + PC-01~PC-18)
│   │   └── linux/                  # syeon (U-01~U-72) — 서연 main.py 가 사용
│   ├── engine/
│   │   ├── llm_judge.py            # 본인 (Windows 판정용)
│   │   └── pipeline.py             # 본인 (Windows 판정 파이프라인)
│   ├── integration/                ✨ 어댑터 4개
│   │   ├── euni_adapter.py
│   │   ├── syeon_db_adapter.py
│   │   ├── syeon_guideline_sync.py
│   │   └── legacy_linux_adapter.py (비상용)
│   ├── database/                   # vs_* 테이블 11개 + 은이 테이블 3개 공존
│   ├── web/                        # Tailwind UI (seojin)
│   └── ...
├── tools/                          # 별도 도구
│   ├── jutonggi_parser/            # 은이 PDF 파서 + db.py
│   ├── mcp_server/                 # 은이 MCP 서버
│   ├── diagnosis/                  # 은이 진단 모듈
│   ├── ingest.py                   # 은이 CLI
│   └── syeon_engine/               ✨ 서연 core/ + main.py (8파일)
└── docs/                           # 문서·자료
    ├── presentation/, work-log/, reference/, archive/
```

---

## 🗃️ DB 테이블 (forensic_db 안에 모두 공존)

### 본인 `vs_*` 테이블 (11개)
- vs_users, vs_login_attempts (인증)
- vs_guideline_versions, vs_guideline_items, vs_guideline_diffs (가이드라인)
- vs_script_registry, vs_scan_results, vs_judgments (스캔·판정)
- vs_patch_executions (패치 실행)
- vs_comparisons, vs_reports (이력·리포트)

### 은이 native 테이블 (3개) — 같은 forensic_db
- vulnerabilities (현재 가이드라인)
- vulnerabilities_history (PDF 버전 이력)
- item_changelog (변경 로그)

은이 native 3개 테이블 ↔ 본인 vs_guideline_* 3개 테이블이 **공존**. 어댑터가 한 방향 sync.

---

## 🎯 데이터 흐름 — 통합 후

### 가이드라인 등록 (관리자)
```
PDF 업로드 → integration/euni_adapter.py
   ↓ 은이 parser → 은이 sync_items → vulnerabilities/history/changelog
   ↓ 한 방향 sync → vs_guideline_items + vs_guideline_versions
```

### Windows 스캔
```
POST /api/scan/start (target_os=windows)
   ↓ web/routes/scan.py (본인 흐름, 변경 없음)
   ↓ vs_scan_results → engine/pipeline.py LLM 판정 (Gemini CLI)
   ↓ vs_judgments → 웹 UI 표시 (서진 Tailwind)
```

### Linux 스캔 (서연 흐름)
```
POST /api/scan/start (target_os=linux)
   ↓ web/routes/scan.py:_run_linux_via_syeon (신규)
   ↓ sys.modules['db_writer'] = syeon_db_adapter
   ↓ tools/syeon_engine/main.run_pipeline (서연 코드 그대로)
   ↓   ScriptRunner → Collector → BatchJudge (Gemini API 키)
   ↓   DBWriter (←swap된 우리 어댑터)
   ↓ vs_judgments / vs_patch_executions / vs_comparisons
   ↓ 웹 UI 표시 (양쪽 OS 한 화면)
```

### 패치 적용 (본인 흐름 일원화)
```
"패치 적용" → POST /api/patch/{scan_id}/{item_code}
   ↓ web/routes/patch.py (안전장치 + UAC/sudo + Gemini 재작성)
   ↓ vs_patch_executions
   ↓ 서진의 /admin/patch-history 페이지 표시
```

---

## ✅ 검증 결과

| 항목 | 결과 |
|---|:-:|
| `integration/__init__.py` syntax | ✅ |
| `integration/euni_adapter.py` syntax | ✅ |
| `integration/syeon_db_adapter.py` syntax + import | ✅ |
| `integration/syeon_guideline_sync.py` syntax | ✅ |
| `integration/legacy_linux_adapter.py` syntax | ✅ |
| `web/routes/scan.py` 수정 후 syntax + import | ✅ |
| `tools/syeon_engine/__init__.py` import | ✅ |
| `main.py` import + 라우트 42개 등록 | ✅ |
| DBWriter swap 시뮬레이션 (init_schema no-op 출력) | ✅ |

---

## 📌 5/11 통합 테스트 시 할 일

### 환경 준비
1. `pip install pdfplumber psycopg[binary] google-generativeai`
2. `.env` 에 `GEMINI_API_KEY` 추가 (서연 batch_judge 용)
3. Linux 서버: sudoers 에 NOPASSWD 또는 환경변수 `SYEON_SUDO_PASSWORD`

### 흐름 검증
1. `python -m integration.euni_adapter --pdf <PATH>` → vulnerabilities + vs_guideline_items 적재
2. `python -m integration.syeon_guideline_sync` → guidelines.db 생성
3. Windows 스캔 (본인 PC) → vs_judgments 적재
4. Linux 스캔 (Linux 머신) → 서연 흐름으로 vs_judgments 적재
5. 결과 페이지에서 양쪽 OS 표시 확인
6. 패치 실행 후 /admin/patch-history 확인

### 알려진 잠재 이슈
- 서연 batch_judge 가 `GEMINI_API_KEY` 없으면 실패 → API 키 필수
- 서연 ScriptRunner 가 sudo 없이 실패 → NOPASSWD 설정
- 은이 db.py 가 psycopg 필요 → 미설치 시 어댑터 SystemExit

---

## 🛠️ 새로 추가된 파일

| 파일 | 줄 수 | 역할 |
|---|:-:|---|
| `tools/syeon_engine/__init__.py` | 25 | sys.path 보정 |
| `tools/syeon_engine/{8 .py 파일}` | 0 새 작성 | 서연 origin/syeon 에서 통째로 복사 |
| `vulnerability-scanner/integration/__init__.py` | 18 | 디렉토리 정책 docstring |
| `vulnerability-scanner/integration/euni_adapter.py` | 250 | 은이 통합 어댑터 |
| `vulnerability-scanner/integration/syeon_db_adapter.py` | 250 | 서연 DBWriter 호환 PostgreSQL 어댑터 |
| `vulnerability-scanner/integration/syeon_guideline_sync.py` | 130 | vs_guideline_items → SQLite ETL |

## 🛠️ 수정된 파일

| 파일 | 변경 분량 | 내용 |
|---|---|---|
| `vulnerability-scanner/web/routes/scan.py` | +50줄 | `_run_linux_via_syeon` 함수 추가, Linux 분기 변경 |

## 🛠️ 이동된 파일

| 기존 → 신규 |
|---|
| `vulnerability-scanner/engine/linux_adapter.py` → `vulnerability-scanner/integration/legacy_linux_adapter.py` |
| `vulnerability-scanner/knowledge/import_from_euni.py` → `vulnerability-scanner/integration/euni_adapter.py` (재작성, PDF 비교 기능 추가) |

---

# 후속 작업 (2026-05-03 오후 — 2021 PDF 통합 테스트)

> 1차 통합 (`6aba2d6`) 후 실제 데이터로 E2E 테스트. 2026 PDF 는 보관, 2021 PDF로 전체 흐름을 처음부터 굴림.

## 🎯 통합 테스트 목적

- 4인 통합 어댑터 (`integration/`) 가 실제 PDF 적재부터 점검 결과까지 동작하는지 검증
- 향후 새 PDF (2026) 적재 시 `item_changelog` 비교 기능이 동작하는지 사전 확인
- 점검 스크립트가 빠진 경우 어떻게 보강하는지 워크플로 정립

## 🔧 어댑터 보강 (4인 코드 0줄 변경 유지)

### 1. `integration/euni_adapter.py` — 폴백 + 중복 제거 + 자동 ETL
1. **폴백 transform** — 2021 PDF 가 2026 과 표 구조가 달라 은이 parser 가 일부 필드 (`title`, `check_content`, `check_purpose`, `security_threat`) 를 비웠음. 어댑터에서 폴백:
   - `item_name` 빈 값 → `category` 사용
   - `description` 빈 값 → `note` 사용
2. **중복 제거** — 2021 PDF 는 같은 코드가 여러 페이지에 반복 등장 → `vs_guideline_items` 의 `(version_id, item_code)` UNIQUE 제약 충돌. `_dedupe_by_code()` 추가, 본문이 가장 긴 row 만 유지.
3. **4단계 자동 ETL** — `import_pdf()` 끝에 `syeon_guideline_sync.sync()` 자동 호출. PDF 한 명령 적재로 PostgreSQL + SQLite 모두 갱신.

### 2. `integration/syeon_guideline_sync.py` — 잔존 row 정리
- INSERT OR REPLACE 만 했더니 이전 sync 의 코드가 그대로 남음 (2024-v1 의 일부 코드가 2021 sync 후에도 잔존)
- `DELETE FROM guidelines` 추가 → SQLite 가 항상 PostgreSQL `is_current=True` 버전과 정확히 일치

## 📚 2021 PDF 적재 결과

| 단계 | 출력 |
|---|---|
| 은이 parser | 598개 raw item 파싱 |
| `vulnerabilities` (forensic_db) | 313 unique 코드 적재 |
| `vulnerabilities_history` | 598 row (페이지 단위) |
| `item_changelog` | 313 added (첫 적재) |
| `vs_guideline_items` | 170개 (linux 72 + windows 79 + PC 19), 2021 KISA = current |
| `guidelines.db` (SQLite) | 170개 (PostgreSQL 정확 미러) |

## 📂 점검 스크립트 — 2026 보관 + 2021 신규 작성

| 디렉토리 | 내용 | 버전 |
|---|---|---|
| `scripts/windows_2026/` | W-01~W-64 64개 + 메타 파일 | 2026 (보관) |
| `scripts/pc_2026/` | PC-01~PC-18 18개 | 2026 (보관) |
| `scripts/linux_2026/` | U-01~U-72 72개 | 2026 (보관) |
| `scripts/windows/` | W-01~W-82 (W-07/08/09 제외) **79개** | **2021 신규** |
| `scripts/pc/` | PC-01~PC-19 **19개** | **2021 신규** |
| `scripts/linux/` | U-01~U-72 **72개** | **2021 신규** |

170개 신규 스크립트는 9개 agent 병렬로 작성 (각 chunk ~20개). 자동 판정 124개 / LLM 위임 ("규칙불가") 35개. 모두 `py_compile` 통과.

## 🚦 알려진 제한 (테스트 결과)

| 항목 | 상태 | 영향 |
|---|---|---|
| `scripts/pc/PC-XX.py` | scan.py 가 호출 안 함 | Windows 점검 시 W-XX 만 실행, PC 19개는 미사용 (별도 작업 필요) |
| LLM 진행률 UI 표시 | `judge.total = 0` 으로 응답 | 백엔드 정상, 폴링 응답에서 reference 끊김 — 별도 fix |

## 🛠️ 추가 변경 파일

| 파일 | 변경 |
|---|---|
| `vulnerability-scanner/requirements.txt` | `pdfplumber`, `psycopg[binary]` 추가 |
| `.gitignore` | 어댑터 생성물 (`_2021_guidelines.json`, `tools/syeon_engine/db/`) 무시 |
| `start_server.bat` | **신규** — Windows 원클릭 런처 (의존성 자동 설치 + Docker 확인 + 서버 + 브라우저) |

## ✅ E2E 검증

- ✅ PDF 한 명령 적재 → 4단계 모두 자동 (vulnerabilities → history → changelog → vs_guideline_items → guidelines.db)
- ✅ 웹 서버 8081 기동, 로그인 + admin/history/patch-history 페이지 OK
- ✅ Windows 점검 시작 (UAC 승격) → 79개 스크립트 5개 병렬 실행 → vs_scan_results 적재 → LLM 판정 → vs_judgments 적재
- ⚠ Linux 흐름 (서연 main.run_pipeline) — WSL 없어서 미검증
- ⚠ PC 디렉토리 — scan.py 가 호출 안 해서 미검증
