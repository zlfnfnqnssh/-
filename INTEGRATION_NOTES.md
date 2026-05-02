# 1차 통합 정리 (2026-05-03)

> 4개 브랜치(riri/seojin/syeon/euni) 통합 결과

---

## 📦 통합 후 디렉토리 구조

```
취약점진단/
├── vulnerability-scanner/         # ★ 메인 웹 시스템 (FastAPI, riri+seojin)
│   ├── main.py                    # 포트 8081 진입점
│   ├── scripts/
│   │   ├── windows/               # W-01~W-64 + PC-01~PC-18 (riri 작성)
│   │   ├── linux/                 # ✨ U-01~U-72 (syeon에서 가져옴)
│   │   └── linux_old_riri/        # riri의 기존 Linux 스크립트 백업
│   ├── database/                  # vs_* 테이블 (VsPatchExecution, VsLoginAttempt 포함)
│   ├── web/                       # Tailwind UI (seojin 디자인)
│   └── ...
│
├── jutonggi_parser/               # ✨ 은이 PDF 파서 (별도 도구)
│   ├── parser.py                  # pdfplumber 기반
│   └── db.py                      # JutonggiRepository
│
├── mcp_server/                    # ✨ 은이 MCP 서버 (별도 도구)
│   ├── server.py                  # FastMCP 기반
│   └── runner.py
│
├── diagnosis/                     # ✨ 은이 진단 모듈 (별도 도구)
│   ├── run_scripts.py
│   └── scripts_db.py
│
└── ingest.py                      # ✨ 은이 CLI: PDF → DB 적재
```

---

## 🔧 누가 무엇을 했나

| 사람 | 통합 방식 | 위치 |
|---|---|---|
| **riri** (본인) | 베이스 | `vulnerability-scanner/` 전체 |
| **seojin** (백서진) | `git merge` (자동) | `vulnerability-scanner/` (Tailwind UI + 사용자관리 + 패치이력 페이지) |
| **syeon** (이서연) | Linux 스크립트만 추출 | `vulnerability-scanner/scripts/linux/U-01~U-72` (소문자 → 대문자 변환) |
| **euni** (고은이) | 디렉토리 추출 | `jutonggi_parser/` + `mcp_server/` + `diagnosis/` + `ingest.py` |

---

## ✅ 통합 검증 결과

| 항목 | 상태 |
|---|:-:|
| 서진 머지 (자동, 충돌 0건) | ✅ |
| 서진 import/syntax 검증 | ✅ |
| 서진 서버 실행 → 로그인/대시보드/admin/patch-history HTTP 200 | ✅ |
| 서연 Linux 스크립트 72개 syntax | ✅ |
| 은이 PDF 파서·MCP·diagnosis syntax | ✅ |

---

## 🚫 통합하지 않은 것 (이유)

### 서연 (syeon) — 별개 시스템
- `core/` (별도 엔진), `db/` (SQLite), `main.py` (CLI)
- → 본인 FastAPI 시스템과 호환 불가, **Linux 스크립트만 추출**

### 은이 (euni) — `.venv` 폭탄
- `.venv/Lib/site-packages/...` 14000+ 파일이 커밋에 포함됨
- → `.venv`는 무시, 본질 코드(jutonggi_parser, mcp_server, diagnosis, ingest.py)만 추출
- 은이의 `scripts/windows/` = 본인 옛날 버전 복사본 → **무시** (본인 최신 W-XX.py 유지)

### 둘 다 별도 도구로 운영
- 은이의 jutonggi_parser/mcp_server는 **별도 DB(`jtk_db`)** 사용
- 메인 시스템(`forensic_db`)와 분리 → 관리자 도구로 활용

---

## 🚀 실행 방법

### 메인 시스템 (FastAPI)
```bash
cd vulnerability-scanner
python main.py
# → http://localhost:8081
# → admin / admin1234
```

### 은이 PDF 파서 (별도)
```bash
python ingest.py path/to/jutonggi.pdf \
  --json-out parsed_items.json \
  --db-dsn "postgresql://admin:admin123@localhost:5432/jtk_db"
```

### 은이 MCP 서버 (별도)
```bash
python -m mcp_server.server
```

---

## 🔄 다음 단계 (5/11 통합 테스트 시 확인)

1. 서연 Linux 스크립트 → 본인 `engine/pipeline.py` 와 인터페이스 호환 확인
   - 서연 스크립트의 출력 JSON 스키마가 본인이 기대하는 `vs_scan_results` 컬럼과 맞는지
2. 은이 jutonggi_parser → 메인 시스템 `vs_guideline_items` 적재 흐름과 통합 가능성 검토
3. 서진 admin/users 페이지 → 본인 라우트와 잘 연결되는지 실제 클릭 테스트
4. **scripts/windows/ 와 scripts/linux/ 인터페이스 통일** — pipeline.py에서 양쪽 다 잘 굴러가는지
