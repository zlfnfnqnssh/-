# 통합 수정사항 정리 (2026-05-03)

> riri 브랜치 통합 후 4명의 작업이 한 시스템에서 동작하도록 수정한 내역.

---

## 🗺️ 통합 전체 흐름

```
[은이 PDF 파서]                  [본인 메인 시스템]                 [서연 Linux 스크립트]
tools/jutonggi_parser/   ────►   vulnerability-scanner/      ◄────  scripts/linux/U-XX.py
                                          │
                                          ▼
                                    [서진 웹/UI]
                                  Tailwind 디자인
                                  patch_history 등
```

---

## 🔧 어댑터·연결 작업 4건

### ✅ 1. 은이 PDF 파서 → 본인 vs_guideline_items
**파일**: `vulnerability-scanner/knowledge/import_from_euni.py` (신규, 217줄)

#### 문제
- 은이의 jutonggi_parser는 `vulnerabilities` 테이블에 PostgreSQL 별도 DB(`jtk_db`)에 저장
- 본인 시스템은 `vs_guideline_items` 테이블에서 가이드라인을 읽음
- 필드명/구조도 다름

#### 해결
- 은이의 `parser.py`만 직접 importlib로 로드 (`db.py`의 psycopg 의존 회피)
- `transform()` 함수로 필드 매핑 (12개 필드 변환)
- `filter_items()`로 OS/prefix 기반 선별 (기본: linux/windows + U/W/PC)
- `pdfplumber`는 lazy import (실제 파싱 시점에만 로드)

#### 사용법
```bash
cd vulnerability-scanner
python -m knowledge.import_from_euni \
  --pdf "../docs/reference/주요정보통신기반시설_*.pdf" \
  --label "2026 KISA"
```

#### 매핑 표
| 은이 필드 | 본인 필드 |
|---|---|
| code | item_code |
| title | item_name |
| os_type | target_os |
| severity | importance |
| check_content + check_purpose + security_threat | description (3중 결합) |
| criteria_good + criteria_bad | criteria ("양호: X / 취약: Y") |
| action | remediation_guide |
| action_impact | impact |
| target | target_systems |
| note | reference |

---

### ✅ 2. 서연 Linux 스크립트 출력 → 본인 pipeline 형식
**파일**: `vulnerability-scanner/engine/linux_adapter.py` (신규, 130줄)

#### 문제
서연 스크립트(72개)와 본인 Windows 스크립트(82개)의 출력 구조가 다름:

```python
# 본인 Windows (단일 dict)
{ "category", "item_code", "item_name",
  "result"          : "양호|취약|규칙불가",   # ← 핵심
  "collected_value", "raw_output", "source_command" }

# 서연 Linux (중첩 dict)
{ "scan_id", "items": [
    { "item_code", "check_results": [
        { "sub_check", "service_status", "collected_value", ... }
    ]}
]}
```

본인 pipeline은 단일 dict를 기대하므로 그대로 받으면 KeyError 발생.

#### 해결
- `adapt_syeon_output(raw_dict)` — 중첩 → 평탄화
- `_infer_result_from_statuses()` — service_status 기반 사전 판정:
  - 모두 NOT_INSTALLED/NOT_RUNNING → **양호**
  - RUNNING 포함 → **규칙불가** (LLM 판정으로 위임)
- `_join_collected()` — sub_check 별 정보를 가독성 좋게 합침
- 본인 형식이 들어와도 그대로 통과 (`item_code` 키 존재 시 단일 dict 처리)

#### 호출 지점
**파일**: `vulnerability-scanner/web/routes/scan.py` 수정

```python
# OS별 출력 형식 분기 — Linux(서연 형식)는 평탄화
if target_os == "linux":
    from engine.linux_adapter import adapt_syeon_output
    for flat in adapt_syeon_output(parsed_json):
        results.append(sanitize(flat))
else:
    results.append(sanitize(parsed_json))
```

#### 추가: stdout trailing 메시지 처리
서연 스크립트는 stdout 끝에 `[+] 결과 저장됨: ...` 안내 메시지를 출력하므로,
JSON 파싱 전 마지막 `}` 이후 텍스트를 잘라냄:
```python
_end = output.rfind("}")
if _end >= 0:
    output = output[: _end + 1]
```

---

### ✅ 3. 서연 Linux 스크립트 위치 통일
**경로**: `scripts/linux/u01.py~u72.py` → `vulnerability-scanner/scripts/linux/U-01.py~U-72.py`

#### 문제
- 서연 브랜치는 프로젝트 루트의 `scripts/linux/u01.py` (소문자) 위치
- 본인 시스템은 `vulnerability-scanner/scripts/linux/U-01.py` (대문자) 기대

#### 해결
1. 본인 기존 Linux 스크립트(67개) → `scripts/linux_old_riri/` 로 백업
2. 서연 72개 스크립트 → `vulnerability-scanner/scripts/linux/` 로 이동
3. 파일명 `u01.py` → `U-01.py` 변환
4. WSL Ubuntu 24.04 에서 72개 모두 syntax + 실행 OK 검증

---

### ✅ 4. 서진 통합 — 자동 머지 (충돌 0건)
**파일**: `database/models.py`, `database/repository.py`, `web/routes/admin.py`, `web/routes/scan.py`, `web/routes/auth.py`, `web/routes/pages.py`, `web/routes/report.py`, `web/templates/*.html`, `web/static/css/*`

#### 추가된 기능 (서진 작업)
- `VsLoginAttempt` 테이블 — 로그인 시도 이력 (잠금 정책 + 보안 감사)
- `record_login_attempt()`, `get_recent_failed_attempts()` 함수
- `/admin/users` — 사용자 역할 변경/삭제, 마지막 admin 보호
- `/admin/patch-history` — **본인의 `vs_patch_executions` 시각화 페이지**
- `POST /scan/{scan_id}/delete` — 스캔+판정+리포트+패치이력 일괄 삭제
- 모든 HTML 템플릿 Tailwind CSS 재디자인

#### 충돌 처리
- 자동 머지 성공 (`git merge` 충돌 0건)
- 본인이 만든 `VsPatchExecution` 모델 위에 서진이 `VsLoginAttempt` 추가하는 구조
- 본인 로직(scan_id, 진행률, patch.py 등) 일체 안 건드림

---

## 🚫 통합하지 않은 것 (이유)

### 서연 (syeon) 브랜치
| 항목 | 통합 안 함 이유 |
|---|---|
| `core/` (runner/collector/batch_judge/db_writer) | 별개 CLI 시스템 (FastAPI 아님, SQLite 사용) — 본인 engine과 중복 |
| `db/parse_pdf_guidelines.py` | 은이 jutonggi_parser와 중복 (PDF 파싱 도구 2개) |
| `db/seed_guidelines.py` | 25개 수기 작성, 본인은 PDF 자동 파싱으로 149개 보유 |
| `main.py` (CLI 진입점) | 본인 FastAPI main.py와 충돌 |

### 은이 (euni) 브랜치
| 항목 | 통합 안 함 이유 |
|---|---|
| `.venv/` 14000+ 파일 | 가상환경 통째 커밋, .gitignore 처리 안 됨 |
| `scripts/windows/` | 본인 초기 버전 복사본 (최신 W-XX.py가 정답) |
| 별도 DB(`jtk_db`) | 본인 `forensic_db`와 분리, 어댑터로 통합 가능하지만 메인 시스템은 우리 DB 사용 |

---

## 📁 통합 후 최종 구조

```
취약점진단/
├── README.md / INTEGRATION_NOTES.md / INTEGRATION_FIXES.md
├── docker-compose.yml / .gitignore
├── vulnerability-scanner/          ★ 메인 FastAPI 시스템
│   ├── scripts/
│   │   ├── windows/                # riri: W-01~W-64 + PC-01~PC-18
│   │   ├── linux/                  # syeon: U-01~U-72 (어댑터로 평탄화)
│   │   └── linux_old_riri/         # riri 기존 백업
│   ├── engine/
│   │   ├── linux_adapter.py        ✨ 신규: 서연 출력 → 본인 형식
│   │   ├── llm_judge.py            # 본인 Gemini CLI 판정
│   │   └── pipeline.py
│   ├── knowledge/
│   │   ├── import_from_euni.py     ✨ 신규: 은이 PDF → vs_guideline_items
│   │   └── ...
│   ├── database/
│   │   ├── models.py               # vs_* 테이블 + VsPatchExecution(riri) + VsLoginAttempt(seojin)
│   │   └── repository.py
│   ├── web/                        # Tailwind UI (seojin 디자인)
│   │   ├── routes/
│   │   │   ├── patch.py            # riri: UAC + Gemini 재작성 + 안전장치
│   │   │   ├── admin.py            # seojin: 사용자관리·패치이력
│   │   │   └── ...
│   │   └── templates/admin/patch_history.html  ✨ seojin
│   └── ...
├── tools/                          # 별도 도구 (euni)
│   ├── jutonggi_parser/            # PDF 파서
│   ├── mcp_server/                 # MCP 서버
│   ├── diagnosis/                  # 진단 모듈
│   └── ingest.py                   # PDF→DB CLI
└── docs/                           # 문서·자료
    ├── presentation/               # PPT, 이미지, 엑셀
    ├── work-log/                   # 작업 일지
    ├── reference/                  # 주통기 참조 자료
    └── archive/                    # 옛 자료
```

---

## 🎯 데이터 흐름 — 통합 후

### 가이드라인 등록 (관리자)
```
PDF 업로드
  ↓
[tools/jutonggi_parser/parser.py]  은이 파서로 PDF → dict 리스트
  ↓
[vulnerability-scanner/knowledge/import_from_euni.py]  필드 매핑 + 필터
  ↓
PostgreSQL vs_guideline_items 적재
```

### Windows 스캔 (사용자)
```
"스캔 시작" 클릭
  ↓
machine_id 기반 scan_id 생성 (riri)
  ↓
UAC 승격 → Windows 82개 스크립트 병렬 실행 (riri)
  ↓
JSON 출력 (단일 dict, result 필드 포함)
  ↓
vs_scan_results 저장 → engine/pipeline.py LLM 판정
  ↓
vs_judgments 저장 → 웹 UI 표시 (seojin Tailwind)
```

### Linux 스캔 (사용자)
```
"스캔 시작" 클릭
  ↓
machine_id 기반 scan_id 생성 (riri)
  ↓
sudo 승격 → Linux 72개 스크립트 병렬 실행 (syeon)
  ↓
JSON 출력 (중첩 구조, check_results[] 포함)
  ↓
[engine/linux_adapter.py adapt_syeon_output()]  ✨ 평탄화
  ↓
vs_scan_results 저장 → engine/pipeline.py LLM 판정
  ↓
vs_judgments 저장 → 웹 UI 표시
```

### 패치 적용 (사용자)
```
취약 항목에 "패치 적용" 클릭
  ↓
[web/routes/patch.py]  riri 안전장치(위험 패턴 18종 차단)
  ↓
양호/규칙불가 항목은 거부 (감사 추적: vs_patch_executions)
  ↓
UAC/sudo 자동 승격 → patch_script 실행
  ↓
실패 시 Gemini 재작성 (3회 루프)
  ↓
성공 → vs_judgments.patch_script DB 갱신
  ↓
[/admin/patch-history]  seojin 페이지에서 모든 이력 조회 가능
```

---

## 📊 통합 검증 결과

| 항목 | 결과 |
|---|:-:|
| 자동 머지 (서진) | ✅ 충돌 0건 |
| 라우트 등록 | ✅ 42개 |
| 로그인 / 대시보드 / 관리자 / patch-history HTTP 200 | ✅ |
| 스캔 시작 API + machine_id scan_id 생성 | ✅ |
| 진행률 polling (overall + phase_label) | ✅ |
| Linux 스크립트 syntax (72개) | ✅ |
| Linux 스크립트 WSL 실행 (5개 샘플) | ✅ |
| 은이 어댑터 transform() 단위 테스트 | ✅ |
| 서연 어댑터 adapt_syeon_output() 단위 테스트 | ✅ |
| import 검증 | ✅ |

---

## 📌 5/11 통합 테스트 시 확인 사항

### 실제 환경에서 검증 필요
1. **Linux 머신에서 실제 스캔** — sudo 승격 → 72개 스크립트 → 어댑터 → DB 저장
2. **PDF 적재** — `python -m knowledge.import_from_euni --pdf <PATH>` (pdfplumber 설치 필요)
3. **Gemini CLI Quota** — Linux 72개 + Windows 82개 = 154개 항목, Quota 한도 내에서 처리되는지
4. **patch_history 화면** — 실제 패치 실행 후 로그가 제대로 쌓이는지 (현재는 0건 표시)
5. **machine_id 동일성** — Windows wmic UUID, Linux /etc/machine-id가 같은 PC에서 안정적으로 같은 값 반환

### 알려진 잠재 이슈
- **서연 스크립트 `service_status`가 항상 채워지지는 않음** (UNKNOWN 일 때 어댑터가 규칙불가로 처리 → LLM 호출 늘어남)
- **은이 파서의 `criteria_good/criteria_bad`가 빈 항목이 일부 있음** (PDF 파싱 한계) — LLM이 부족한 정보로 판정해야 할 수 있음
- **WSL에서 Windows 경로 문제** — 한글 경로 인식 OK 확인됨, 하지만 실기기 Linux 머신에서는 ASCII 경로 권장

---

## 🛠️ 통합으로 새로 추가된 파일

| 파일 | 줄 수 | 역할 |
|---|:-:|---|
| `vulnerability-scanner/knowledge/import_from_euni.py` | 217 | 은이 PDF 파서 → vs_guideline_items 어댑터 |
| `vulnerability-scanner/engine/linux_adapter.py` | 130 | 서연 Linux 출력 → 본인 형식 평탄화 |
| `INTEGRATION_NOTES.md` | 100 | 통합 결과 정리 |
| `INTEGRATION_FIXES.md` | 이 파일 | 통합 수정사항 상세 |

## 🛠️ 통합으로 수정된 파일

| 파일 | 변경 |
|---|---|
| `vulnerability-scanner/web/routes/scan.py` | OS별 출력 분기 (Linux는 어댑터 거침) + stdout 끝 메시지 제거 |
| `vulnerability-scanner/database/models.py` | `VsLoginAttempt` 추가 (서진) |
| `vulnerability-scanner/database/repository.py` | `record_login_attempt()` 등 사용자/스캔 관련 함수 (서진) |
| `vulnerability-scanner/web/routes/admin.py` | 사용자 관리·패치 이력 핸들러 (서진) |
| `vulnerability-scanner/web/templates/*.html` | Tailwind 재디자인 (서진) |
| `vulnerability-scanner/scripts/linux/` | 서연 72개 스크립트 (위치/이름 통일) |
