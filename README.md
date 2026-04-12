# AI 기반 취약점 자동 점검 및 자가 조치 웹 플랫폼

> 주요정보통신기반시설(주통기) 보안 가이드라인 기반, LLM(Gemini)을 활용한 자동 취약점 판정 및 맞춤형 조치 스크립트 제공 웹 플랫폼

## 프로젝트 개요

점검 대상 시스템(Linux/Windows)의 구성 정보를 파악하고, KISA 주통기 가이드라인 최신 버전을 기반으로 컴플라이언스를 점검하는 전 과정을 자동화합니다.
관리자(Admin) 권한에서는 가이드라인 변경에 따른 점검 스크립트의 자동 업데이트를 수행하며,
사용자(Users) 권한에서는 클릭 한 번으로 시스템 진단부터 LLM(Gemini) 기반 맞춤형 조치 스크립트 및 설명 생성까지 원스톱으로 제공합니다.

## 핵심 기능

### 1. 보안 가이드라인(PDF) 변경 자동 반영 스크립트 생성 (Admin)
- 관리자가 새로운 주통기 가이드라인 PDF를 업로드하면 파싱하여 DB에 저장
- 기존 DB에 저장된 버전과의 변경점(추가/삭제/수정 내역)을 자동으로 도출
- 변경점에 맞춰 Gemini CLI를 활용해 Linux/Windows 별 취약점 점검 스크립트를 자동 생성 및 업데이트

### 2. 사용자 맞춤형 시스템 점검 (Users)
- UUID 기반의 개별 사용자 계정을 DB로 분리, 접속 및 지속적인 이력 관리
- '점검 시작' 버튼 클릭 시 대상 시스템 OS(Linux/Windows) 자동 판단 후 해당 점검 스크립트 실행
- 실행 결과를 임시 JSON으로 반환, 판정 완료 즉시 파기

### 3. LLM (Gemini) 기반 지능형 판정 & 분석
- **양호(규칙 기반 판정 가능 항목):** 여러 항목을 묶어 일괄 LLM 처리 (Batch)
- **취약/판정 불가:** 개별 건을 병렬(Parallel)로 전송하여 빠른 결과 확보
- 판정 결과: 쉬운 설명, 공격 시나리오, 가이드라인 기반 조치 방법, 즉시 실행 가능한 패치 스크립트

### 4. 시계열 점검 비교 추이 시각화
- 과거 점검 이력과 현재 결과를 자동 대조
- "여전히 취약", "새로 취약", "양호로 전환" 등 상태 변화를 웹에서 시각화

---

## 점검 항목 현황

| OS | 항목 범위 | 스크립트 수 |
|----|-----------|------------|
| Linux (Unix) | U-01 ~ U-72 | 56개 |
| Windows | W-01 ~ W-47 | 32개 |
| **합계** | | **88개** |

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

```bash
docker run -d \
  --name postgres-db \
  -e POSTGRES_PASSWORD=admin123 \
  -e POSTGRES_DB=forensic_db \
  -p 5432:5432 \
  postgres:14
```

### 5. 환경변수 설정

`vulnerability-scanner/.env` 파일 생성:

```env
# PostgreSQL
PG_HOST=localhost
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=admin123
PG_DB=forensic_db

# Gemini CLI
GEMINI_CLI_CMD=npx @google/gemini-cli
GEMINI_MODEL=gemini-2.5-flash
GEMINI_TIMEOUT=120

# 병렬 처리
MAX_CONCURRENT=5
```

### 6. 서버 실행

```bash
cd vulnerability-scanner
python main.py
```

또는:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
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
| LLM | Gemini CLI (`npx @google/gemini-cli`) |
| RDB | PostgreSQL (Docker, DB: forensic_db) |
| 웹 프레임워크 | FastAPI + Jinja2 (SSR) |
| ASGI 서버 | uvicorn |
| UI | Bootstrap 5 + Bootstrap Icons |
| PDF 파싱 | PyMuPDF |
| PDF 보고서 | ReportLab + matplotlib |
| 비동기 | asyncio + SQLAlchemy async + asyncpg |
| 인증 | bcrypt + 세션 기반 |

---

## 디렉토리 구조

```
vulnerability-scanner/
├── main.py                      # FastAPI 앱 진입점 (포트 8000)
├── requirements.txt             # Python 패키지
├── .env                         # 환경변수 (git 미추적)
├── config/
│   └── settings.py              # 환경 설정
├── auth/
│   └── session.py               # 세션/인증 미들웨어
├── scripts/
│   ├── windows/                 # W-01 ~ W-47 점검 스크립트 (32개)
│   └── linux/                   # U-01 ~ U-72 점검 스크립트 (56개)
├── knowledge/
│   ├── guideline_extractor.py   # PDF → DB 파싱
│   ├── guideline_differ.py      # 가이드라인 버전 비교
│   └── data/
│       ├── guidelines/          # 가이드라인 PDF
│       └── uploads/             # 관리자 업로드 PDF
├── engine/
│   ├── llm_judge.py             # Gemini CLI LLM 판정
│   ├── pipeline.py              # 3단계 스마트 판정 파이프라인
│   ├── script_generator.py      # LLM 기반 스크립트 자동 생성
│   └── comparison.py            # 점검 이력 비교
├── database/
│   ├── models.py                # SQLAlchemy 비동기 모델 (vs_ 접두사)
│   └── repository.py            # 비동기 CRUD
├── report/
│   ├── generator.py             # ReportLab PDF 보고서 생성
│   └── comparator.py            # 이전 진단 비교
└── web/
    ├── routes/
    │   ├── pages.py             # 페이지 라우터
    │   ├── scan.py              # 스캔 API
    │   ├── admin.py             # 관리자 API
    │   ├── auth.py              # 인증 API
    │   └── patch.py             # 패치 실행 API
    ├── templates/               # Jinja2 HTML 템플릿
    └── static/                  # CSS, JS
```

---

## 향후 확장 과제
- 한 명의 사용자가 여러 개의 서로 다른 로컬 OS를 운용하는 경우를 DB에 구조적으로 포함하고 관리할 수 있도록 개선
