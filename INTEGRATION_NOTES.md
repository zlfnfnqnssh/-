# 1차 통합 정리 (2026-05-03)

> 4개 모듈 (백엔드 / 웹 UI / Linux 엔진 / PDF 가이드라인) 통합 결과

---

## 통합 후 디렉토리 구조

```
취약점진단/
├── README.md                       # 프로젝트 메인
├── INTEGRATION_NOTES.md            # 이 파일 (통합 결과)
├── docker-compose.yml              # PostgreSQL Docker
├── .gitignore
│
├── vulnerability-scanner/          메인 웹 시스템 (FastAPI)
│   ├── main.py                     # 포트 8081 진입점
│   ├── scripts/
│   │   ├── windows/                # W-01~W-82 (Windows 점검)
│   │   ├── pc/                     # PC-01~PC-19 (PC 점검)
│   │   ├── linux/                  # U-01~U-72 (Linux 점검 — Linux 엔진이 사용)
│   │   └── linux_old_riri/         # 이전 Linux 스크립트 백업
│   ├── database/                   # vs_* 테이블 (VsPatchExecution, VsLoginAttempt)
│   ├── web/                        # Tailwind UI
│   ├── engine/                     # LLM 판정·파이프라인
│   └── ...
│
├── tools/                          별도 도구 (PDF 가이드라인 + Linux 엔진)
│   ├── jutonggi_parser/            # PDF 파서 (pdfplumber)
│   ├── mcp_server/                 # MCP 서버 (FastMCP)
│   ├── diagnosis/                  # 진단 실행 모듈
│   ├── ingest.py                   # PDF → DB 적재 CLI
│   └── syeon_engine/               # Linux 엔진 (8 .py)
│
└── docs/                           # 모든 문서·자료
    ├── presentation/               # PPT·이미지·생성 스크립트
    ├── work-log/                   # 작업 일지
    ├── reference/                  # 주통기 참조 자료 (PDF 포함)
    └── archive/                    # 옛 자료
```

---

## 모듈별 통합 방식

| 모듈 | 통합 방식 | 위치 |
|---|---|---|
| **백엔드 + Windows** | 베이스 | `vulnerability-scanner/` 전체 |
| **웹 UI + 운영** | `git merge` (자동) | `vulnerability-scanner/` (Tailwind UI + 사용자관리 + 패치이력 페이지) |
| **Linux 엔진** | 디렉토리 추출 | `tools/syeon_engine/` (runner/collector/batch_judge 등 8파일) + `vulnerability-scanner/scripts/linux/U-01~U-72` |
| **PDF 가이드라인** | 디렉토리 추출 | `tools/{jutonggi_parser, mcp_server, diagnosis}` + `tools/ingest.py` |

---

## 통합 검증 결과

| 항목 | 상태 |
|---|:-:|
| UI 머지 (자동, 충돌 0건) | OK |
| UI import/syntax 검증 | OK |
| UI 서버 실행 → 로그인/대시보드/admin/patch-history HTTP 200 | OK |
| Linux 점검 스크립트 72개 syntax | OK |
| PDF 파서·MCP·diagnosis syntax | OK |

---

## 통합하지 않은 것 (이유)

### Linux 엔진 — 별개 시스템
- `core/` (별도 엔진), `db/` (SQLite), `main.py` (CLI) 구조
- → 메인 FastAPI 시스템과 직접 호환 불가
- → 어댑터 (`integration/syeon_db_adapter.py`) 로 연결, **Linux 스크립트는 추출**

### PDF 가이드라인 모듈 — `.venv` 폭탄
- `.venv/Lib/site-packages/...` 14000+ 파일이 커밋에 포함되어 있었음
- → `.venv`는 무시, 본질 코드(jutonggi_parser, mcp_server, diagnosis, ingest.py)만 추출
- PDF 모듈의 `scripts/windows/` = 옛날 버전 복사본 → **무시** (최신 W-XX.py 유지)

### 둘 다 별도 도구로도 운영 가능
- jutonggi_parser/mcp_server는 **별도 DB(`jtk_db`)** 도 지원
- 메인 시스템(`forensic_db`)과 분리 운영 시 관리자 도구로 활용

---

## 실행 방법

### 메인 시스템 (FastAPI)
```bash
cd vulnerability-scanner
python main.py
# http://localhost:8081
# admin / admin1234
```

### PDF 파서 단독 실행 (별도, tools/ 폴더에서)
```bash
cd tools
python ingest.py path/to/jutonggi.pdf \
  --json-out parsed_items.json \
  --db-dsn "postgresql://admin:admin123@localhost:5432/jtk_db"
```

### MCP 서버 단독 실행
```bash
cd tools
python -m mcp_server.server
```

---

## 다음 단계 (5/11 통합 테스트 시 확인)

1. Linux 점검 스크립트 → `engine/pipeline.py` 와 인터페이스 호환 확인
   - Linux 스크립트 출력 JSON 스키마가 `vs_scan_results` 컬럼과 맞는지
2. jutonggi_parser → 메인 시스템 `vs_guideline_items` 적재 흐름과 통합 가능성 검토
3. admin/users 페이지 → 라우트 연결 클릭 테스트
4. **scripts/windows/ 와 scripts/linux/ 인터페이스 통일** — pipeline.py 에서 양쪽 다 잘 굴러가는지
