# 프로젝트 핵심 개념 정리

---

## 1. LLM (Large Language Model, 대규모 언어 모델)

### LLM이란?

대량의 텍스트 데이터를 학습한 인공지능 모델이다. ChatGPT, Claude 등이 대표적이다.
사람이 쓴 것처럼 자연어를 이해하고 생성할 수 있다.

### 작동 원리

LLM은 "다음에 올 단어를 예측"하는 방식으로 학습된다.

```
입력: "서울의 수도는"
예측: "서울" (X) → 질문이 잘못됨을 인식
      "한국의 수도는 서울입니다" 로 교정하여 응답

입력: "PermitRootLogin yes 설정은 보안상"
예측: "위험합니다. root 계정으로 SSH 원격 접속이 가능하기 때문입니다..."
```

수십억~수조 개의 텍스트를 학습했기 때문에, 보안 설정의 의미도 맥락적으로 이해할 수 있다.

### LLM의 한계 — 할루시네이션(Hallucination)

LLM은 학습 데이터에 없는 내용도 그럴듯하게 지어낼 수 있다.

```
질문: "주통기 가이드라인 U-99 항목은 뭔가요?"
LLM:  "U-99는 시스템 백업 정책 점검 항목입니다..." (존재하지 않는 항목을 지어냄)
```

이것이 우리가 **RAG**를 사용하는 이유다.
LLM이 자기 지식으로 답하는 게 아니라, **우리가 제공한 가이드라인 문서를 기반으로만 답**하게 만든다.

### 코드에서 LLM 호출하기

LLM은 API로 호출한다. 웹에서 ChatGPT 쓰는 것과 같은 기능을 코드에서 실행하는 것이다.

```python
from openai import OpenAI

client = OpenAI(api_key="sk-xxxxx")  # API 키 필요

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {
            "role": "system",
            "content": "너는 보안 전문가야. 주통기 가이드라인 기준으로 취약점을 판정해."
        },
        {
            "role": "user",
            "content": """
            [수집된 시스템 현황]
            /etc/ssh/sshd_config 파일 내용:
            PermitRootLogin yes

            [관련 가이드라인]
            U-01: root 계정 원격 접속 제한
            판단기준: PermitRootLogin이 no이면 양호, yes이면 취약

            위 내용을 비교하여 양호/취약을 판정하고 이유와 조치방법을 알려줘.
            """
        }
    ]
)

print(response.choices[0].message.content)
# 출력: "취약합니다. PermitRootLogin이 yes로 설정되어 있어 root 계정으로
#        SSH 원격 접속이 가능합니다. /etc/ssh/sshd_config 파일에서
#        PermitRootLogin을 no로 변경 후 systemctl restart sshd를 실행하세요."
```

**messages 구조:**
- `system`: LLM에게 역할을 부여 (보안 전문가처럼 행동해라)
- `user`: 실제 질문/판정 요청 (수집 데이터 + 가이드라인)

---

## 2. 임베딩 (Embedding)

### 임베딩이란?

텍스트를 숫자 배열(벡터)로 변환하는 기술이다.
컴퓨터는 텍스트를 직접 비교할 수 없으므로, 숫자로 바꿔서 비교한다.

### 핵심 원리: 의미가 비슷하면 벡터도 비슷하다

```
"root 계정 원격 접속 제한"     → [0.12, -0.34, 0.56, 0.78, ...] (1536개 숫자)
"관리자 계정 원격 로그인 차단"  → [0.11, -0.33, 0.55, 0.77, ...] (비슷한 숫자!)
"파일 권한 설정"               → [0.89, 0.23, -0.45, 0.12, ...] (완전 다른 숫자)
```

두 벡터가 얼마나 비슷한지를 **코사인 유사도(cosine similarity)**로 측정한다.
- 1.0 = 완전 동일한 의미
- 0.0 = 전혀 관련 없음

```
"root 원격 접속" vs "관리자 원격 로그인"  → 유사도: 0.95 (매우 유사)
"root 원격 접속" vs "파일 권한 설정"      → 유사도: 0.15 (관련 없음)
```

### 우리 프로젝트에서 임베딩이 쓰이는 곳

**1) 가이드라인 적재 시 (사전 준비)**
```
가이드라인 항목 텍스트 → 임베딩 → 벡터 DB에 저장

"U-01 root 계정 원격 접속 제한 PermitRootLogin no..." → [0.12, -0.34, ...] → Milvus 저장
"U-02 패스워드 복잡성 설정 영문 숫자 특수문자..."       → [0.45, 0.67, ...]  → Milvus 저장
```

**2) 수집 결과 검색 시 (판정 단계)**
```
수집된 항목 텍스트 → 임베딩 → 벡터 DB에서 유사한 가이드라인 검색

"PermitRootLogin yes sshd_config" → [0.13, -0.33, ...] → Milvus 검색
                                                         → U-01 항목이 검색됨 (유사도 0.93)
```

### 임베딩 모델

텍스트를 벡터로 변환해주는 AI 모델이다. LLM과는 다른 별도 모델이다.

| 모델 | 벡터 차원 | 특징 |
|------|----------|------|
| `text-embedding-3-small` (OpenAI) | 1536 | 유료, 고품질, API 호출 |
| `jhgan/ko-sbert-nli` (HuggingFace) | 768 | 무료, 한국어 특화, 로컬 실행 |
| `intfloat/multilingual-e5-large` | 1024 | 무료, 다국어, 고품질 |

```python
# OpenAI 임베딩 예시
from openai import OpenAI
client = OpenAI()

response = client.embeddings.create(
    model="text-embedding-3-small",
    input="root 계정 원격 접속 제한"
)

vector = response.data[0].embedding
print(f"벡터 차원: {len(vector)}")   # 1536
print(f"벡터 일부: {vector[:5]}")    # [0.0123, -0.0345, 0.0567, ...]
```

```python
# HuggingFace 임베딩 예시 (무료, 로컬)
from sentence_transformers import SentenceTransformer

model = SentenceTransformer("jhgan/ko-sbert-nli")

sentences = [
    "root 계정 원격 접속 제한",
    "관리자 원격 로그인 차단",
    "파일 권한 설정"
]

vectors = model.encode(sentences)
print(f"벡터 차원: {vectors.shape}")  # (3, 768)

# 유사도 계산
from sklearn.metrics.pairwise import cosine_similarity
sim = cosine_similarity([vectors[0]], [vectors[1]])
print(f"유사도: {sim[0][0]:.4f}")  # 0.92xx (매우 유사)
```

---

## 3. 벡터 DB (Vector Database)

### 벡터 DB란?

임베딩 벡터를 저장하고, **유사도 기반으로 검색**하는 전용 데이터베이스이다.

### 일반 DB와의 차이

```
[일반 DB (SQL)]
SELECT * FROM guidelines WHERE item_name = 'root 접속 제한'
→ 정확히 'root 접속 제한'이라고 써야만 검색됨
→ '관리자 원격 로그인'으로 검색하면 아무것도 안 나옴

[벡터 DB]
search(vector_of("관리자 원격 로그인"), top_k=3)
→ 1위: "root 계정 원격 접속 제한" (유사도 0.93)
→ 2위: "SSH 원격접속 허용" (유사도 0.78)
→ 3위: "패스워드 복잡성 설정" (유사도 0.21)
→ 의미가 비슷한 것을 찾아줌
```

### Milvus

우리 프로젝트에서 사용하는 벡터 DB이다. 오픈소스이고, Docker로 쉽게 설치할 수 있다.

**핵심 개념:**
- **컬렉션(Collection)**: 일반 DB의 테이블에 해당
- **필드(Field)**: 컬럼에 해당. 벡터 필드 + 메타데이터 필드로 구성
- **인덱스(Index)**: 빠른 검색을 위한 구조 (IVF_FLAT, HNSW 등)

```python
from pymilvus import connections, Collection, FieldSchema, CollectionSchema, DataType

# 1) Milvus 연결
connections.connect("default", host="localhost", port="19530")

# 2) 컬렉션(테이블) 생성
fields = [
    FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
    FieldSchema(name="item_code", dtype=DataType.VARCHAR, max_length=10),
    FieldSchema(name="item_name", dtype=DataType.VARCHAR, max_length=200),
    FieldSchema(name="os_type", dtype=DataType.VARCHAR, max_length=10),     # linux / windows
    FieldSchema(name="category", dtype=DataType.VARCHAR, max_length=50),    # 계정관리, 파일관리 등
    FieldSchema(name="content", dtype=DataType.VARCHAR, max_length=5000),   # 가이드라인 전체 내용
    FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=1536),   # 임베딩 벡터
]
schema = CollectionSchema(fields, description="주통기 가이드라인")
collection = Collection("guidelines", schema)

# 3) 데이터 삽입
data = [
    ["U-01"],                          # item_code
    ["root 계정 원격 접속 제한"],        # item_name
    ["linux"],                          # os_type
    ["계정관리"],                        # category
    ["점검내용: SSH에서 root..."],       # content
    [[0.12, -0.34, 0.56, ...]],        # embedding (1536차원)
]
collection.insert(data)

# 4) 검색 (유사도 기반)
collection.load()
search_vector = embed("PermitRootLogin yes")  # 수집 결과를 임베딩
results = collection.search(
    data=[search_vector],
    anns_field="embedding",
    param={"metric_type": "COSINE", "params": {"nprobe": 10}},
    limit=3,                                  # 상위 3개
    output_fields=["item_code", "item_name", "content"]
)

for hit in results[0]:
    print(f"{hit.entity.get('item_code')}: {hit.entity.get('item_name')} (유사도: {hit.distance:.4f})")
# U-01: root 계정 원격 접속 제한 (유사도: 0.9312)
# U-60: SSH 원격접속 허용 (유사도: 0.7845)
```

---

## 4. RAG (Retrieval-Augmented Generation)

### RAG란?

**검색(Retrieval) + 생성(Generation)을 결합**한 기술이다.

LLM이 자기 학습 지식으로만 답하는 게 아니라,
**외부 문서를 먼저 검색한 뒤 그 내용을 기반으로 답변을 생성**한다.

### 왜 RAG를 쓰는가?

```
[문제 1] LLM은 주통기 가이드라인을 정확히 모름
  → 2021년 이후 업데이트된 내용, 세부 판단기준 등을 모를 수 있음

[문제 2] LLM은 거짓말을 할 수 있음 (할루시네이션)
  → 없는 항목 번호를 지어내거나, 판단기준을 틀리게 말할 수 있음

[해결] RAG = 정확한 문서를 찾아서 LLM에게 함께 전달
  → LLM은 제공된 문서 내에서만 답하므로 정확도가 대폭 향상
```

### RAG 전체 흐름 (우리 프로젝트)

```
[사전 준비 — 1회]
  주통기 PDF → 점검항목별 분할(청킹) → 각 청크를 임베딩 → Milvus에 저장

[판정 시 — 매 항목마다]
  수집 결과 "PermitRootLogin yes"
      │
      ├─ 1) 임베딩: 텍스트를 벡터로 변환
      │
      ├─ 2) 검색(Retrieval): Milvus에서 유사한 가이드라인 top-3 검색
      │     → U-01 "root 계정 원격 접속 제한... PermitRootLogin no이면 양호..."
      │
      ├─ 3) 프롬프트 구성: 수집 결과 + 검색된 가이드라인을 합쳐서 프롬프트 생성
      │
      └─ 4) 생성(Generation): LLM에 프롬프트 전달 → 판정 결과 생성
            → "취약. root 원격 접속이 허용됨. PermitRootLogin을 no로 변경하세요."
```

### 청킹 (Chunking)

PDF 문서를 적절한 크기의 조각(chunk)으로 나누는 것이다.
너무 크면 검색 정확도가 떨어지고, 너무 작으면 맥락이 부족하다.

```
[나쁜 청킹] 페이지 단위로 자름
  → 한 페이지에 여러 항목이 섞여서 검색 정확도 낮음

[좋은 청킹] 점검 항목 단위로 자름 (우리 방식)
  → 각 청크가 하나의 점검 항목 전체 (항목코드 + 항목명 + 점검내용 + 판단기준 + 조치방법)
  → 검색하면 딱 필요한 항목 하나가 나옴
```

```
청크 예시 (U-01):

"항목코드: U-01
항목명: root 계정 원격 접속 제한
중요도: 상
점검내용: 시스템 정책에 root 계정의 원격터미널 접속 차단 설정 여부를 점검
판단기준:
  양호 - 원격 서비스를 사용하지 않거나 사용 시 root 직접 접속을 차단한 경우
  취약 - root 직접 접속을 허용하고 있는 경우
조치방법:
  1. vi /etc/ssh/sshd_config
  2. PermitRootLogin no 설정
  3. systemctl restart sshd"
```

### RAG 코드 구조

```python
# 1) 검색 (Retrieval)
def search_guidelines(query_text: str, top_k: int = 3):
    """수집 결과를 임베딩하여 관련 가이드라인 검색"""
    query_vector = embed(query_text)
    results = milvus_collection.search(
        data=[query_vector],
        anns_field="embedding",
        limit=top_k,
        output_fields=["item_code", "item_name", "content"]
    )
    return [hit.entity.get("content") for hit in results[0]]


# 2) 프롬프트 구성
def build_prompt(collected_data: dict, guidelines: list) -> str:
    """수집 데이터 + 검색된 가이드라인으로 프롬프트 생성"""
    guidelines_text = "\n---\n".join(guidelines)

    return f"""
당신은 주요정보통신기반시설 보안 점검 전문가입니다.
아래 [시스템 현황]을 [보안 가이드라인]과 비교하여 판정해주세요.

[시스템 현황]
항목: {collected_data['item_name']}
수집값: {collected_data['collected_value']}
원본 출력:
{collected_data['raw_output']}

[보안 가이드라인]
{guidelines_text}

다음 JSON 형식으로 응답하세요:
{{"result": "양호 또는 취약", "reason": "판정 이유", "remediation": "조치 방법"}}
"""


# 3) 생성 (Generation)
async def judge_item(collected_data: dict) -> dict:
    """하나의 항목을 RAG로 판정"""
    # 검색
    guidelines = search_guidelines(
        f"{collected_data['item_name']} {collected_data['collected_value']}"
    )

    # 프롬프트 구성
    prompt = build_prompt(collected_data, guidelines)

    # LLM 호출
    response = await client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"}
    )

    return json.loads(response.choices[0].message.content)
```

---

## 5. 병렬 처리 (asyncio)

### 왜 병렬 처리가 필요한가?

LLM API 호출은 **네트워크 I/O** 작업이다. 요청을 보내고 응답을 기다리는 동안 CPU는 놀고 있다.

```
[순차 처리] CPU가 대부분 대기 상태
항목1: 요청전송(0.1초) ──── 대기(3초) ──── 응답처리(0.1초)
                                                          항목2: 요청전송 ── 대기(3초) ── 응답처리
                                                                                                    항목3: ...
총 시간: 3.2초 × 119개 = ~6분

[병렬 처리] 대기 시간에 다른 요청을 보냄
항목1: 요청전송 ──── 대기(3초) ──── 응답처리
항목2: 요청전송 ──── 대기(3초) ──── 응답처리    ← 항목1 대기 중에 시작
항목3: 요청전송 ──── 대기(3초) ──── 응답처리    ← 동시에 시작
...
총 시간: ~3.5초 (10개 동시) × 12배치 = ~42초
```

### asyncio란?

Python에서 비동기 프로그래밍을 하는 표준 라이브러리이다.
`await`로 대기하는 동안 다른 작업을 실행할 수 있다.

### 핵심 개념 3가지

**1) async/await — 비동기 함수**

```python
import asyncio

# 일반 함수: 3초 동안 아무것도 못함
def sync_work():
    time.sleep(3)    # 3초 블로킹
    return "완료"

# 비동기 함수: 3초 대기 중 다른 작업 가능
async def async_work():
    await asyncio.sleep(3)  # 3초 대기하지만, 다른 코루틴 실행 가능
    return "완료"
```

**2) gather — 여러 작업을 동시에 실행**

```python
async def call_llm(item_name):
    """LLM API 호출 시뮬레이션 (3초 소요)"""
    print(f"  {item_name} 시작")
    await asyncio.sleep(3)  # API 응답 대기
    print(f"  {item_name} 완료")
    return f"{item_name}: 취약"

async def main():
    items = ["U-01 root 접속", "U-02 패스워드", "U-03 계정잠금",
             "U-04 패스워드파일", "U-05 PATH설정"]

    # 5개를 동시에 실행 → 3초면 전부 완료 (순차면 15초)
    results = await asyncio.gather(*[call_llm(item) for item in items])

    for r in results:
        print(r)

asyncio.run(main())
# 출력:
#   U-01 root 접속 시작
#   U-02 패스워드 시작
#   U-03 계정잠금 시작     ← 거의 동시에 시작
#   U-04 패스워드파일 시작
#   U-05 PATH설정 시작
#   (3초 후)
#   U-01 root 접속 완료
#   U-02 패스워드 완료     ← 거의 동시에 완료
#   ...
```

**3) Semaphore — 동시 실행 수 제한**

API에는 분당 요청 제한(rate limit)이 있으므로, 한번에 너무 많이 보내면 에러가 난다.
Semaphore로 동시에 실행되는 최대 개수를 제한한다.

```python
MAX_CONCURRENT = 5  # 동시에 최대 5개만
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

async def process_item(item):
    async with semaphore:      # 5개가 이미 실행 중이면 여기서 대기
        result = await call_llm(item)
        await save_to_db(result)
        return result

async def main():
    items = [f"U-{i:02d}" for i in range(1, 73)]  # U-01 ~ U-72

    # 72개 태스크를 생성하지만, 동시에 5개씩만 실행됨
    tasks = [process_item(item) for item in items]
    results = await asyncio.gather(*tasks)
    print(f"완료: {len(results)}개")

asyncio.run(main())
```

---

## 6. 시스템 정보 수집 (subprocess / PowerShell)

### Python subprocess

Python에서 운영체제 명령어를 실행하고 결과를 받아오는 모듈이다.

```python
import subprocess

# Linux: sshd_config에서 PermitRootLogin 설정 확인
result = subprocess.run(
    ["grep", "PermitRootLogin", "/etc/ssh/sshd_config"],
    capture_output=True,    # 출력을 캡처
    text=True               # 바이트가 아닌 문자열로 반환
)

print(result.stdout)        # "PermitRootLogin yes\n"
print(result.returncode)    # 0 (성공)
```

```python
# Windows: PowerShell 명령어 실행
result = subprocess.run(
    ["powershell", "-Command", "Get-Service | Where-Object {$_.Status -eq 'Running'}"],
    capture_output=True,
    text=True
)
print(result.stdout)
```

### 수집 항목별 명령어 예시

**Linux:**

| 점검 항목 | 수집 명령어 | 수집 결과 예시 |
|----------|-----------|-------------|
| U-01 root 원격접속 | `grep PermitRootLogin /etc/ssh/sshd_config` | `PermitRootLogin yes` |
| U-04 패스워드 파일 보호 | `ls -la /etc/shadow` | `-rw-r----- 1 root shadow` |
| U-07 /etc/passwd 권한 | `stat -c '%a %U' /etc/passwd` | `644 root` |
| U-13 SUID 파일 점검 | `find / -perm -4000 -type f` | `/usr/bin/sudo ...` |
| U-54 세션 타임아웃 | `grep TMOUT /etc/profile` | `TMOUT=300` |

**Windows:**

| 점검 항목 | 수집 명령어 | 수집 결과 예시 |
|----------|-----------|-------------|
| W-01 Administrator 이름 변경 | `net user Administrator` | 계정 정보 출력 |
| W-02 Guest 계정 상태 | `net user Guest` | `계정 활성화 예/아니요` |
| W-04 계정 잠금 임계값 | `net accounts` | `잠금 임계값: 5` |
| W-09 패스워드 복잡성 | `secedit /export /cfg C:\sec.cfg` | 보안 정책 파일 |
| W-34 화면보호기 | PowerShell 레지스트리 조회 | `ScreenSaveTimeOut: 600` |

### 수집 결과 정규화 (JSON)

수집한 결과를 통일된 형식으로 바꿔야 DB에 저장하고 LLM에 전달할 수 있다.

```python
def normalize_result(item_code, item_name, category, command, raw_output, os_type):
    """수집 결과를 표준 JSON으로 변환"""
    return {
        "item_code": item_code,
        "item_name": item_name,
        "category": category,
        "collected_value": extract_key_value(raw_output),  # 핵심 값만 추출
        "raw_output": raw_output,                          # 원본 출력 전체
        "source_command": command,
        "target_os": os_type
    }

# 예시
result = normalize_result(
    item_code="U-01",
    item_name="root 계정 원격 접속 제한",
    category="계정관리",
    command="grep PermitRootLogin /etc/ssh/sshd_config",
    raw_output="PermitRootLogin yes\n",
    os_type="linux"
)
```

---

## 7. DB (SQLite / SQLAlchemy)

### SQLite

파일 하나에 모든 데이터를 저장하는 경량 데이터베이스이다.
별도 서버 설치 없이 Python에서 바로 사용 가능하다.

### SQLAlchemy ORM

Python 코드로 DB 테이블을 정의하고 조작하는 도구이다.
SQL을 직접 쓰지 않고 Python 객체로 DB를 다룬다.

```python
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Float
from sqlalchemy.orm import declarative_base, Session
from datetime import datetime

engine = create_engine("sqlite:///scanner.db")
Base = declarative_base()

# 테이블 정의 (Python 클래스 = DB 테이블)
class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, nullable=False)
    scan_date = Column(DateTime, default=datetime.now)
    target_os = Column(String)          # "linux" or "windows"
    category = Column(String)           # "계정관리", "파일관리" 등
    item_code = Column(String)          # "U-01", "W-01" 등
    item_name = Column(String)
    collected_value = Column(String)    # 핵심 수집값
    raw_output = Column(String)         # 명령어 원본 출력

class Judgment(Base):
    __tablename__ = "judgments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String)
    item_code = Column(String)
    result = Column(String)             # "양호" or "취약"
    reason = Column(String)             # 판정 이유
    remediation = Column(String)        # 조치 방법
    guideline_ref = Column(String)      # 관련 가이드라인 항목
    confidence = Column(Float)          # 판정 신뢰도

# 테이블 생성
Base.metadata.create_all(engine)

# 데이터 저장
with Session(engine) as session:
    result = ScanResult(
        scan_id="scan_001",
        target_os="linux",
        category="계정관리",
        item_code="U-01",
        item_name="root 계정 원격 접속 제한",
        collected_value="PermitRootLogin yes",
        raw_output="PermitRootLogin yes\n"
    )
    session.add(result)
    session.commit()

# 데이터 조회
with Session(engine) as session:
    items = session.query(ScanResult).filter_by(scan_id="scan_001").all()
    for item in items:
        print(f"{item.item_code}: {item.collected_value}")
```

---

## 8. 전체 파이프라인 요약

```
[1회] 가이드라인 PDF ─→ 파싱 ─→ 청킹 ─→ 임베딩 ─→ Milvus 저장
                                                        │
[매번] 대상 시스템 ─→ 수집 스크립트 ─→ JSON 정규화 ─→ SQLite 저장
                                                        │
         ┌──────────────────────────────────────────────┘
         │
         ▼
[병렬 처리] DB에서 항목 N개 조회
         │
         ├─ 워커1: 항목 임베딩 → Milvus 검색 → LLM 판정 → DB 저장
         ├─ 워커2: 항목 임베딩 → Milvus 검색 → LLM 판정 → DB 저장
         ├─ ...
         └─ 워커N: 항목 임베딩 → Milvus 검색 → LLM 판정 → DB 저장
                                                        │
                                                        ▼
                               판정 결과 DB ─→ 보고서 자동 생성 (PDF)
                                           ─→ 이전 진단과 비교
```
