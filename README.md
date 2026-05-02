# AI 기반 취약점 자동 점검 및 자가 조치 웹 플랫폼

> 주요정보통신기반시설(주통기) 보안 가이드라인 기반, LLM(Gemini)을 활용한 자동 취약점 판정 및 맞춤형 조치 스크립트 제공 웹 플랫폼
> 중부대학교 정보보호학과 2026-1 캡스톤디자인

---

## 프로젝트 개요

점검 대상 시스템(Linux/Windows)의 구성 정보를 파악하고, KISA 주통기 가이드라인 최신 버전을 기반으로 컴플라이언스를 점검하는 전 과정을 자동화합니다.
관리자(Admin) 권한에서는 가이드라인 변경에 따른 점검 스크립트의 자동 업데이트를 수행하며,
사용자(Users) 권한에서는 클릭 한 번으로 시스템 진단부터 LLM(Gemini) 기반 맞춤형 조치 스크립트 및 설명 생성까지 원스톱으로 제공합니다.

> **판정 방식**: 가이드라인을 사전 임베딩하는 RAG 방식이 아니라, **PostgreSQL `vs_guideline_items` 테이블에서 항목별 `criteria + remediation_guide + check_examples`를 LLM 프롬프트에 직접 주입**하는 방식입니다. 항목코드(item_code)로 1:1 직접 조회 가능하므로 벡터 검색이 불필요하고, 토큰 효율과 정확성이 더 높습니다.

---

## 핵심 기능

### 1. 보안 가이드라인(PDF) 변경 자동 반영 스크립트 생성 (Admin)
- 관리자가 새로운 주통기 가이드라인 PDF를 업로드하면 파싱하여 DB에 저장
- 기존 DB 버전과의 변경점(추가/삭제/수정) 자동 도출
- 변경점에 맞춰 Gemini CLI로 Linux/Windows 별 점검 스크립트 자동 생성·갱신

### 2. 사용자 맞춤형 시스템 점검 (Users)
- **machine_id 기반 scan_id**: Windows `wmic csproduct UUID` / Linux `/etc/machine-id` 활용
  - 같은 PC·사용자·OS는 prefix 공유 → 이력 추적 가능
  - 형식: `{os}_{machine_id}_{user_short}_{timestamp}`
- '점검 시작' 클릭 시 OS 자동 판단 → 점검 스크립트 실행 → 임시 JSON 반환 → 판정 후 파기

### 3. LLM (Gemini) 지능형 판정 파이프라인
- **양호(규칙 기반):** 여러 항목 묶어 일괄 LLM 검증 (Batch)
- **취약/판정불가:** 개별 병렬 전송 (Parallel)
- **판정 정책**:
  - "판정불가" 반환 차단 → 항상 양호/취약 둘 중 하나
  - 불확실하면 보수적으로 **취약** (False Negative 방지)
  - 취약 reason 4가지 필수: 현재 상태 / 안전한 상태 / 왜 위험 / 악용 시 피해 (4~6문장)
  - 양호 reason 2~3문장 + scenario·remediation 상세화
- **가이드라인 DB 직접 주입** (RAG 아님): PostgreSQL `vs_guideline_items`에서 항목별 `criteria + remediation_guide + check_examples` 프롬프트에 포함

### 4. UAC 패치 자동 실행 + Gemini 재작성 루프
- 판정 결과의 `patch_script`를 **UAC 자동 승격**(`Start-Process -Verb RunAs`) 으로 실행
- 실행 실패 시 Gemini가 (현재 스크립트 + stderr + criteria + remediation_guide + check_examples) 받아 **자동 재작성**
- 최대 3회 재시도, 성공 시 DB `patch_script` 자동 갱신

### 5. PDF 보고서 자동 생성 & 다운로드
- 스캔 완료 시 ReportLab + matplotlib로 PDF 자동 생성
- 표지 / 양호·취약 비율 차트 / 항목별 상세 / 조치 방법 / 부록 구성
- `GET /report/{scan_id}/download` 로 다운로드

### 6. 시계열 점검 비교 시각화
- 과거 이력과 자동 대조 — "여전히 취약 / 새로 취약 / 양호 전환" 상태 시각화

### 7. 통합 진행률 표시
- UAC 대기 → 스크립트 실행 중(0% 고정) → LLM 판정(0~100%)
- 퍼센트는 LLM 처리 진행률만 반영해 사용자 체감과 일치

---

## 점검 항목 현황

| OS | 항목 범위 | 스크립트 수 |
|----|-----------|------------|
| Linux (Unix) | U-01 ~ U-67 | **67개** |
| Windows Server | W-01 ~ W-64 | **64개** |
| Windows PC | PC-01 ~ PC-18 | **18개** |
| **합계** | | **149개** |

### Windows 판정 분포 (82개 기준 / 2026-04-27)
| 분류 | 개수 | 비율 |
|---|:-:|:-:|
| 🟢 양호 확정 (스크립트 직접 판정) | 43 | 52% |
| 🔴 취약 확정 (스크립트 직접 판정) | 26 | 32% |
| 🟡 규칙불가 (LLM 판정 위임) | 13 | 16% |

---

## 설치 및 실행 방법

### 사전 요구사항

| 구분 | 버전 | 비고 |
|------|------|------|
| Python | 3.10 이상 | |
| Node.js | 18 이상 | Gemini CLI (npx) 실행용 |
| PostgreSQL | 14 이상 | Docker 컨테이너 권장 |
| Docker | 최신 | PostgreSQL 실행용 |

### 1. 저장소 클론

```bash
git clone https://github.com/zlfnfnqnssh/-.git
cd 취약점진단/vulnerability-scanner
```

### 2. Python 패키지 설치

```bash
pip install -r requirements.txt
```

주요 패키지:
- `fastapi`, `uvicorn`, `jinja2` — 웹 서버
- `sqlalchemy`, `asyncpg` — PostgreSQL 비동기 ORM
- `pymupdf` — PDF 파싱
- `passlib[bcrypt]`, `itsdangerous` — 인증
- `reportlab`, `matplotlib` — PDF 보고서 생성
- `pydantic` — 데이터 검증
- `python-dotenv` — 환경변수 관리

### 3. Gemini CLI 설치

```bash
npm install -g @google/gemini-cli
```

또는 npx를 통해 자동 설치됩니다 (첫 실행 시 다운로드).

### 4. PostgreSQL (Docker)

프로젝트 루트에 `docker-compose.yml`이 포함되어 있어 한 줄로 실행 가능:

```bash
docker compose up -d
```

또는 수동으로:

```bash
docker run -d \
  --name postgres-db \
  -e POSTGRES_PASSWORD=admin123 \
  -e POSTGRES_DB=forensic_db \
  -p 5432:5432 \
  postgres:14
```

### 5. 환경변수 설정

`.env.example`을 복사하여 `.env` 파일 생성:

```bash
cd vulnerability-scanner
cp .env.example .env
```

필요 시 `.env` 내용 수정 (PostgreSQL 비밀번호, Gemini 모델 등)

### 6. 서버 실행

```bash
cd vulnerability-scanner
python main.py
```

### 7. 웹 접속

- 대시보드: http://localhost:8000
- 관리자 페이지: http://localhost:8000/admin
- 기본 관리자 계정: `admin` / `admin1234`

---

## 기술 스택

| 구분 | 기술 |
|------|------|
| 언어 | Python 3.10+ |
| LLM | Gemini CLI (`npx @google/gemini-cli`, `gemini-2.5-flash`) |
| RDB | PostgreSQL (Docker, DB: `forensic_db`, `vs_*` 8개 테이블) |
| 웹 프레임워크 | FastAPI + Jinja2 (SSR) |
| ASGI 서버 | uvicorn |
| UI | Bootstrap 5 + Bootstrap Icons |
| PDF 파싱 | PyMuPDF |
| PDF 보고서 | ReportLab + matplotlib |
| 비동기 | asyncio + SQLAlchemy async + asyncpg |
| 인증 | bcrypt + 세션 기반 |
| 수집 스크립트 | PowerShell (Windows) / Bash (Linux) |
| 권한 상승 | UAC (`Start-Process -Verb RunAs` + Base64 인코딩) / sudo |

> 🚫 **사용 안 하는 기술** (혼동 방지)
> - Vector DB (Milvus 등) — 가이드라인은 PostgreSQL에 직접 저장
> - 임베딩 모델 (sentence-transformers 등) — 항목코드 1:1 매핑이라 불필요
> - RAG 검색 — 프롬프트에 가이드라인을 직접 주입

---

## 디렉토리 구조

```
vulnerability-scanner/
├── main.py                      # FastAPI 앱 진입점 (포트 8000)
├── requirements.txt             # Python 패키지
├── .env                         # 환경변수 (git 미추적)
├── config/
│   ├── settings.py              # 환경 설정
│   └── machine_id.py            # PC 고유 ID + scan_id 빌더
├── auth/
│   └── security.py              # 세션 기반 인증
├── scripts/
│   ├── windows/                 # W-01~W-64, PC-01~PC-18 (총 82개)
│   └── linux/                   # U-01~U-67 (67개)
├── knowledge/
│   ├── document_parser.py       # PDF 텍스트 추출 (PyMuPDF)
│   ├── guideline_extractor.py   # 항목코드별 구조화 파싱
│   ├── guideline_differ.py      # 가이드라인 버전 비교 (add/mod/del)
│   ├── load_guidelines.py       # PostgreSQL 적재 스크립트
│   └── data/
│       ├── guidelines/          # 가이드라인 PDF 원본
│       ├── extracted/           # 파싱 결과 JSON
│       └── uploads/             # 관리자 업로드 PDF
├── engine/
│   ├── llm_judge.py             # Gemini CLI 판정 + 정책 강화
│   ├── pipeline.py              # 3분류 스마트 파이프라인
│   ├── script_generator.py      # 신규 항목 스크립트 자동 생성
│   └── comparison.py            # 점검 이력 비교
├── database/
│   ├── models.py                # SQLAlchemy 비동기 모델 (vs_* 8개 테이블)
│   └── repository.py            # 비동기 CRUD
├── report/
│   ├── generator.py             # ReportLab PDF 자동 생성
│   └── comparator.py            # 이전 진단 비교
└── web/
    ├── routes/
    │   ├── pages.py             # 페이지 라우터
    │   ├── scan.py              # 스캔 시작·진행률·비교 API
    │   ├── admin.py             # 관리자 API (PDF 업로드 등)
    │   ├── auth.py              # 로그인/회원가입
    │   ├── patch.py             # UAC 패치 실행 + Gemini 재작성 루프
    │   ├── report.py            # PDF 리포트 API
    │   ├── judge.py             # 판정 트리거 (deprecated, 자동화됨)
    │   └── upload.py            # 수동 업로드 (deprecated)
    ├── templates/               # Jinja2 HTML 템플릿 (15개)
    └── static/                  # CSS, JS, 이미지
```

---

## 데이터베이스 스키마 (vs_* 8개 테이블)

| 테이블 | 역할 |
|---|---|
| `vs_users` | 사용자/관리자 계정 (bcrypt) |
| `vs_guideline_versions` | 주통기 가이드라인 버전 이력 |
| `vs_guideline_items` | 항목별 criteria/remediation/examples (149건) |
| `vs_guideline_diffs` | 버전 간 add/mod/del 차이 |
| `vs_script_registry` | 점검 스크립트 메타정보 |
| `vs_scan_results` | 수집 결과 (item별 collected_value) |
| `vs_judgments` | LLM 판정 결과 (양호/취약, reason, patch_script) |
| `vs_comparisons` | 이전 진단과 비교 (개선/악화/유지) |

---

## 향후 확장 과제

- 한 사용자가 서로 다른 로컬 OS 여러 대를 운용하는 케이스를 DB 구조에 정식 반영
- Linux 패치 스크립트 sudo 자동 실행 + Gemini 재작성 루프 검증
- 신규 PDF 가이드라인 → Gemini로 점검 스크립트 자동 생성 루프 완성
- LLM 판정 정확도 벤치마크 및 회귀 테스트
