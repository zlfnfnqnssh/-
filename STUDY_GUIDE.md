# 개념 공부 가이드

> 역할 배정 전, 팀원 전체가 먼저 공통 개념을 이해한 뒤 역할별 심화 학습 진행

---

## 1단계: 전원 필수 (1~2주)

### 1-1. RAG가 뭔지 이해하기 (가장 중요)

우리 프로젝트의 핵심이 RAG이므로 전원이 반드시 이해해야 합니다.

**RAG (Retrieval-Augmented Generation) = 검색 + AI 생성**

```
일반 LLM 사용:
  "U-01 root 원격접속 제한 점검해줘" → LLM이 학습된 지식으로만 대답 (부정확할 수 있음)

RAG 사용 (우리 프로젝트):
  "U-01 root 원격접속 제한 점검해줘"
       ↓
  1) 질문을 벡터로 변환 (임베딩)
  2) 벡터 DB에서 관련 가이드라인 검색
  3) 검색된 가이드라인 + 질문을 함께 LLM에 전달
       ↓
  LLM이 정확한 가이드라인 기반으로 대답 (정확함)
```

**공부 자료:**
- 영상: YouTube "RAG 설명" 검색 (10분짜리 개요 영상)
- 글: LangChain RAG 공식 튜토리얼 (https://python.langchain.com/docs/tutorials/rag/)
- 핵심만: "임베딩 → 벡터DB 저장 → 질문 시 검색 → LLM에 전달" 이 흐름만 이해하면 됨

---

### 1-2. 임베딩(Embedding)이 뭔지

**텍스트를 숫자 배열(벡터)로 변환하는 것**

```
"root 계정 원격 접속 제한" → [0.12, -0.34, 0.56, 0.78, ...]  (1536차원 벡터)
"관리자 계정 원격 로그인 차단" → [0.11, -0.33, 0.55, 0.77, ...]  (비슷한 벡터!)

→ 의미가 비슷한 문장은 벡터도 비슷함 → 유사도 검색 가능
```

**왜 필요한가:**
- 수집 결과 "PermitRootLogin yes"를 임베딩
- 벡터 DB에서 가장 비슷한 가이드라인 항목을 찾음
- "U-01 root 계정 원격 접속 제한" 가이드라인이 검색됨

**공부 자료:**
- 영상: YouTube "임베딩 embedding 쉽게 설명" 검색
- 실습: OpenAI Embedding API 호출 한번 해보기 (5줄이면 됨)

```python
from openai import OpenAI
client = OpenAI()
response = client.embeddings.create(
    model="text-embedding-3-small",
    input="root 계정 원격 접속 제한"
)
print(len(response.data[0].embedding))  # 1536차원 벡터
```

---

### 1-3. 벡터 DB (Vector Database)

**임베딩 벡터를 저장하고 유사도 검색하는 전용 DB**

```
일반 DB (SQL):  SELECT * FROM items WHERE name = 'root 접속 제한'  → 정확히 일치해야 검색됨
벡터 DB:       "관리자 원격 로그인" 검색 → "root 계정 원격 접속 제한"도 검색됨 (의미 유사)
```

**우리 프로젝트에서:**
- 주통기 가이드라인 72+47개 항목을 벡터로 변환해서 Milvus에 저장
- 수집 결과가 들어오면 → 임베딩 → Milvus에서 관련 가이드라인 검색

**공부 자료:**
- Milvus 공식 문서: https://milvus.io/docs
- 핵심만: "벡터 저장 + 유사도 검색" 이 2가지 기능만 이해하면 됨

---

### 1-4. LLM API 사용법

**ChatGPT를 코드에서 호출하는 방법**

```python
from openai import OpenAI
client = OpenAI()

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "보안 전문가로서 취약점을 판정해주세요."},
        {"role": "user", "content": "시스템 현황: PermitRootLogin yes\n가이드라인: root 원격접속 금지"}
    ]
)
print(response.choices[0].message.content)
```

**공부 자료:**
- OpenAI API 문서: https://platform.openai.com/docs/quickstart
- API 키 발급: https://platform.openai.com/api-keys
- 핵심만: API 키 발급 → pip install openai → 위 코드 실행해보기

---

### 1-5. 주통기 가이드라인 읽어보기

**KISA에서 PDF 다운로드 후 시스템 부분만 읽기**

- 다운로드: https://www.kisa.or.kr/2060204/form?postSeq=12&lang_type=KO&page=1
- **Unix 서버 부분**과 **Windows 서버 부분**만 읽으면 됨
- 각 항목의 구조 파악: 항목코드, 항목명, 점검내용, 판단기준, 조치방법

```
[항목 구조 예시]
항목코드: U-01
항목명: root 계정 원격 접속 제한
중요도: 상
점검내용: SSH 설정에서 root 직접 로그인 차단 여부
판단기준:
  - 양호: PermitRootLogin no
  - 취약: PermitRootLogin yes
조치방법: /etc/ssh/sshd_config에서 PermitRootLogin을 no로 변경
```

---

## 2단계: 역할별 심화 (역할 배정 후)

### 역할 A (수집 모듈) 공부할 것

| 순서 | 주제 | 공부 방법 |
|------|------|----------|
| 1 | Linux 기본 명령어 | `cat`, `grep`, `awk`, `chmod`, `systemctl` 실습 |
| 2 | Python subprocess | `subprocess.run()` 으로 명령어 실행하고 결과 파싱 |
| 3 | PowerShell 기초 | `Get-Service`, `net user`, `secedit` 등 보안 명령어 |
| 4 | 주통기 점검 명령어 | 각 항목(U-01~U-72)에서 어떤 명령어로 점검하는지 |

**실습 추천:**
```bash
# Linux (WSL에서 해보기)
grep PermitRootLogin /etc/ssh/sshd_config
cat /etc/passwd
ls -la /etc/shadow
systemctl list-units --type=service
```
```powershell
# Windows (PowerShell에서 해보기)
net user
net accounts
Get-Service | Where-Object {$_.Status -eq 'Running'}
auditpol /get /category:*
```

---

### 역할 B (VDB 구축) 공부할 것

| 순서 | 주제 | 공부 방법 |
|------|------|----------|
| 1 | PDF 파싱 | PyMuPDF로 PDF에서 텍스트 추출 실습 |
| 2 | 텍스트 청킹 | 문서를 적절한 크기로 나누는 방법 |
| 3 | 임베딩 API | OpenAI 또는 HuggingFace 임베딩 실습 |
| 4 | Milvus 사용법 | Docker로 설치 → 컬렉션 생성 → 데이터 삽입 → 검색 |

**실습 추천:**
```python
# PDF 텍스트 추출
import fitz  # PyMuPDF
doc = fitz.open("가이드라인.pdf")
for page in doc:
    print(page.get_text())
```
```python
# Milvus 기본 사용
from pymilvus import connections, Collection
connections.connect("default", host="localhost", port="19530")
```

---

### 역할 C (DB + 리포트) 공부할 것

| 순서 | 주제 | 공부 방법 |
|------|------|----------|
| 1 | SQLAlchemy ORM | 모델 정의, CRUD 작성 실습 |
| 2 | DB 설계 | ERD 그려보기, 테이블 관계 설계 |
| 3 | Jinja2 템플릿 | HTML 템플릿에 데이터 넣어서 렌더링 |
| 4 | WeasyPrint | HTML → PDF 변환 실습 |

**실습 추천:**
```python
# SQLAlchemy 기본
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import declarative_base, Session

engine = create_engine("sqlite:///test.db")
Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scan_results"
    item_code = Column(String, primary_key=True)
    result = Column(String)
```

---

### 역할 D (RAG + LLM) 공부할 것

| 순서 | 주제 | 공부 방법 |
|------|------|----------|
| 1 | LangChain RAG | 공식 RAG 튜토리얼 따라하기 |
| 2 | 프롬프트 엔지니어링 | 판정 정확도를 높이는 프롬프트 작성법 |
| 3 | asyncio | 비동기 프로그래밍, gather, Semaphore |
| 4 | JSON 출력 강제 | LLM에서 구조화된 JSON 응답 받기 |

**실습 추천:**
```python
# asyncio 기본
import asyncio

async def process(item):
    await asyncio.sleep(1)  # API 호출 시뮬레이션
    return f"{item} 완료"

async def main():
    tasks = [process(f"항목{i}") for i in range(10)]
    results = await asyncio.gather(*tasks)  # 10개 동시 실행
    print(results)  # 1초만에 전부 완료

asyncio.run(main())
```

---

## 공부 순서 요약

```
[1주차] 전원 공통
  ├── RAG 개념 이해 (영상 1개 + 글 1개)
  ├── 임베딩 개념 이해
  ├── LLM API 호출 한번 해보기
  └── 주통기 가이드라인 PDF 시스템 부분 읽기

[2주차] 전원 공통 + 역할 논의
  ├── 벡터 DB 개념 이해
  ├── 전체 파이프라인 흐름 다시 정리
  └── 역할 배정 논의

[3주차~] 역할별 심화
  ├── 역할 A: Linux 명령어 + subprocess + PowerShell
  ├── 역할 B: PDF 파싱 + Milvus 설치/실습
  ├── 역할 C: SQLAlchemy + Jinja2
  └── 역할 D: LangChain RAG + asyncio
```

---

## 추천 학습 자료 모음

| 주제 | 자료 | 형태 |
|------|------|------|
| RAG 개념 | LangChain RAG 튜토리얼 | 공식 문서 |
| 임베딩 | OpenAI Embedding Guide | 공식 문서 |
| Milvus | Milvus Bootcamp | GitHub 예제 |
| LLM API | OpenAI Quickstart | 공식 문서 |
| 프롬프트 | Anthropic Prompt Engineering Guide | 공식 문서 |
| asyncio | Python asyncio 공식 문서 | 공식 문서 |
| SQLAlchemy | SQLAlchemy 2.0 튜토리얼 | 공식 문서 |
| 주통기 | KISA 기술적 취약점 분석평가 상세가이드 | PDF |
