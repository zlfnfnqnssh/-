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
