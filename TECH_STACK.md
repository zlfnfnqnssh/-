# 필요 기술 및 도구

## 공통 기술

| 기술 | 용도 | 학습 난이도 |
|------|------|-----------|
| **Python 3.10+** | 전체 시스템 개발 언어 | 필수 (기본) |
| **Git/GitHub** | 버전 관리 및 협업 | 필수 (기본) |
| **Docker** | Milvus, DB 등 인프라 실행 | 기본 사용법만 |
| **가상환경 (venv/conda)** | Python 패키지 관리 | 기본 |

> **UI 방식: CLI (Command Line Interface)**
> 웹 프레임워크 없이 터미널에서 명령어로 실행하는 방식입니다.

**CLI 관련 패키지:**
```
argparse            # 명령어 인자 처리 (기본 내장)
rich                # 터미널 출력 꾸미기 (테이블, 프로그레스바, 색상)
click               # CLI 명령어 프레임워크 (argparse 대안, 선택)
```

**사용 예시:**
```bash
# 시스템 정보 수집
python main.py collect --os linux --target localhost

# 취약점 판정 실행
python main.py scan --scan-id scan_20260401_001

# 리포트 생성
python main.py report --scan-id scan_20260401_001 --format pdf

# 이전 진단과 비교
python main.py compare --current scan_20260401_001 --previous scan_20260301_001
```

---

## 역할별 필요 기술

### 역할 A: 시스템 정보 수집

| 기술 | 설명 | 참고 자료 |
|------|------|----------|
| **Python subprocess** | 외부 명령어 실행 및 결과 파싱 | Python 표준 라이브러리 |
| **Linux 시스템 명령어** | cat, grep, awk, systemctl, iptables 등 | 주통기 가이드라인 점검 명령어 참고 |
| **PowerShell** | Windows 보안 정보 수집 (Get-Service, secedit 등) | Microsoft 공식 문서 |
| **정규표현식 (re)** | 명령어 출력 결과 파싱 | Python re 모듈 |
| **JSON** | 수집 결과 정규화 포맷 | Python json 모듈 |

**핵심 Python 패키지:**
```
subprocess      # 시스템 명령어 실행 (기본 내장)
json            # JSON 처리 (기본 내장)
re              # 정규표현식 (기본 내장)
platform        # OS 판별 (기본 내장)
paramiko        # SSH 원격 접속 (원격 수집 시)
```

---

### 역할 B: 가이드라인 문서 처리 & Vector DB

| 기술 | 설명 | 참고 자료 |
|------|------|----------|
| **PDF 파싱** | 가이드라인 PDF에서 텍스트 추출 | PyMuPDF, pdfplumber |
| **텍스트 청킹** | 문서를 점검항목 단위로 분할 | LangChain TextSplitter 또는 직접 구현 |
| **임베딩 (Embedding)** | 텍스트를 벡터로 변환 | OpenAI API 또는 HuggingFace 모델 |
| **Milvus** | 벡터 유사도 검색 DB | pymilvus 라이브러리 |
| **Docker** | Milvus 서버 실행 | docker-compose |

**핵심 Python 패키지:**
```
pymupdf (fitz)        # PDF 텍스트 추출
pdfplumber            # PDF 테이블/텍스트 추출 (대안)
pymilvus              # Milvus 벡터 DB 클라이언트
openai                # OpenAI Embedding API (text-embedding-3-small)
sentence-transformers # HuggingFace 임베딩 모델 (로컬, 무료 대안)
tiktoken              # 토큰 수 계산
```

**임베딩 모델 선택지:**
| 모델 | 장점 | 단점 |
|------|------|------|
| `text-embedding-3-small` (OpenAI) | 고품질, 간편 | 유료 (저렴), API 키 필요 |
| `jhgan/ko-sbert-nli` (HuggingFace) | 무료, 한국어 특화 | 로컬 실행 필요 |
| `intfloat/multilingual-e5-large` | 무료, 다국어 지원, 고품질 | GPU 권장 |

**Milvus 설치 (Docker):**
```bash
# docker-compose.yml로 Milvus 실행
wget https://github.com/milvus-io/milvus/releases/download/v2.4.0/milvus-standalone-docker-compose.yml -O docker-compose.yml
docker-compose up -d

# 또는 Milvus Lite (테스트용, Docker 불필요)
pip install milvus-lite
```

---

### 역할 C: DB 설계/구축 & 리포트

| 기술 | 설명 | 참고 자료 |
|------|------|----------|
| **SQLite** | 경량 관계형 DB (개발 단계) | Python sqlite3 내장 모듈 |
| **SQLAlchemy** | Python ORM (DB 추상화) | SQLAlchemy 공식 문서 |
| **SQL** | 데이터 조회/저장/비교 쿼리 | 기본 SQL 문법 |
| **Jinja2** | 보고서 HTML 템플릿 엔진 | Jinja2 공식 문서 |
| **WeasyPrint 또는 ReportLab** | HTML → PDF 변환 | 보고서 PDF 출력 |
| **matplotlib / plotly** | 통계 차트 (양호/취약 비율 등) | 보고서 시각화 |

**핵심 Python 패키지:**
```
sqlalchemy            # ORM (DB 모델 정의, CRUD)
sqlite3               # SQLite 드라이버 (기본 내장)
psycopg2-binary       # PostgreSQL 드라이버 (운영 전환 시)
alembic               # DB 마이그레이션 관리
jinja2                # HTML 템플릿 엔진
weasyprint            # HTML → PDF 변환
matplotlib            # 차트/그래프 생성
```

---

### 역할 D: RAG 검색 & LLM 판정

| 기술 | 설명 | 참고 자료 |
|------|------|----------|
| **RAG (Retrieval-Augmented Generation)** | 검색 증강 생성 — VDB 검색 + LLM 조합 | LangChain RAG 튜토리얼 |
| **LLM API** | GPT-4 또는 Claude API 호출 | OpenAI / Anthropic 공식 문서 |
| **프롬프트 엔지니어링** | LLM에게 정확한 판정을 유도하는 프롬프트 설계 | 프롬프트 가이드 |
| **LangChain** | RAG 파이프라인 프레임워크 | LangChain 공식 문서 |
| **JSON 출력 파싱** | LLM 응답을 구조화된 JSON으로 변환 | pydantic, json |

**핵심 Python 패키지:**
```
openai                # OpenAI GPT-4 API
anthropic             # Anthropic Claude API (대안)
langchain             # RAG 파이프라인 프레임워크
langchain-openai      # LangChain OpenAI 연동
langchain-milvus      # LangChain Milvus 연동
pydantic              # LLM 출력 스키마 정의 및 검증
```

**LLM 선택지:**
| 모델 | 장점 | 단점 | 비용 |
|------|------|------|------|
| GPT-4o (OpenAI) | 고성능, 한국어 우수 | 유료 | ~$2.5/1M input tokens |
| GPT-4o-mini | 저렴, 충분한 성능 | GPT-4o 대비 약간 낮음 | ~$0.15/1M input tokens |
| Claude Sonnet 4.6 | 고성능, 긴 컨텍스트 | 유료 | ~$3/1M input tokens |
| Claude Haiku 4.5 | 빠르고 저렴 | 성능 약간 낮음 | ~$0.8/1M input tokens |

**추천**: 개발/테스트에는 GPT-4o-mini (저렴), 최종 데모에는 GPT-4o 또는 Claude

---

## 전체 requirements.txt (예상)

```
# 공통
python-dotenv>=1.0.0
rich>=13.0.0              # CLI 출력 (테이블, 프로그레스바)

# 수집 모듈 (역할 A)
paramiko>=3.0.0           # SSH 원격 접속 (선택)

# 가이드라인 & VDB (역할 B)
pymupdf>=1.24.0           # PDF 파싱
pdfplumber>=0.11.0        # PDF 파싱 (대안)
pymilvus>=2.4.0           # Milvus 클라이언트
sentence-transformers>=3.0.0  # 로컬 임베딩 (선택)
tiktoken>=0.7.0           # 토큰 카운트

# DB & 리포트 (역할 C)
sqlalchemy>=2.0.0         # ORM
alembic>=1.13.0           # DB 마이그레이션
jinja2>=3.1.0             # 템플릿 엔진
weasyprint>=62.0          # PDF 생성
matplotlib>=3.9.0         # 차트

# RAG & LLM (역할 D)
openai>=1.50.0            # OpenAI API
langchain>=0.3.0          # RAG 프레임워크
langchain-openai>=0.2.0   # LangChain OpenAI
langchain-milvus>=0.1.0   # LangChain Milvus
pydantic>=2.0.0           # 데이터 검증
```

---

## 개발 환경 세팅

### 1. Python 가상환경
```bash
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

### 2. 환경변수 (.env)
```
OPENAI_API_KEY=sk-xxxxxxxxxxxx
MILVUS_HOST=localhost
MILVUS_PORT=19530
DB_PATH=./data/scanner.db
```

### 3. Milvus 실행 (Docker)
```bash
docker-compose up -d
```

### 4. 테스트 환경
- **Linux**: WSL2 또는 VirtualBox/VMware에 Ubuntu 설치
- **Windows**: 로컬 Windows 10/11 PC에서 직접 테스트
