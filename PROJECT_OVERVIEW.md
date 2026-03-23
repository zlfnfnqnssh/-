# AI 기반 시스템 보안 자동 진단 및 취약점 리포팅 시스템

## 프로젝트 개요

주요정보통신기반시설(주통기) 보안 가이드라인을 기반으로, 시스템(Linux/Windows) 보안 상태를 자동 수집하고 **RAG + LLM**을 활용하여 취약점을 자동 판정 및 리포팅하는 시스템

- **대상**: Linux(Unix 서버), Windows(Windows 서버 기준, PC에서도 테스트 가능)
- **기준 문서**: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (KISA)
- **점검 범위**: Unix 서버 항목(U-01~U-72), Windows 서버 항목(W-01~W-84)

---

## 전체 시스템 흐름도

```
┌─────────────────────────────────────────────────────────────────────┐
│                        전체 파이프라인 흐름                           │
└─────────────────────────────────────────────────────────────────────┘

[1단계] 지식 기반 구축 (사전 준비 - 1회만 수행)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  주통기 가이드라인 PDF ──→ 문서 파싱 ──→ 점검항목 단위 청킹 ──→ 임베딩 ──→ Vector DB(Milvus) 저장

  * 가이드라인에서 시스템 부분(Unix 서버 + Windows 서버)만 추출
  * 각 점검항목(항목코드, 항목명, 판단기준, 조치방법)을 하나의 청크로 분할
  * 임베딩 모델로 벡터 변환 후 Milvus에 적재
  * 메타데이터: OS 유형(linux/windows), 분류(계정관리/파일관리 등), 중요도(상/중/하)


[2단계] 시스템 정보 수집 + OS 판별
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  대상 시스템 ──→ OS 자동 판별 ──→ 해당 OS 수집 스크립트 실행 ──→ 정규화(JSON) ──→ RDB 저장

  * OS 판별: platform.system() → "Linux" 또는 "Windows"
  * Linux → linux_collector 실행 → U항목(Unix 서버) 기준 수집
  * Windows → windows_collector 실행 → W항목(Windows 서버) 기준 수집
  * 수집 결과에 target_os 필드를 포함하여 저장
  * 이후 VDB 검색 시 해당 OS의 가이드라인만 검색하는 데 사용됨


[3단계] RAG 검색 + LLM 판정 (핵심) — OS별 VDB 분리 + 병렬 처리
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ※ VDB에 Linux/Windows 가이드라인이 모두 저장되어 있음
  ※ 수집 결과의 OS 정보로 해당 OS의 가이드라인만 필터링하여 검색
  ※ asyncio 기반 병렬 처리로 여러 항목을 동시에 판정

  DB에서 미판정 항목 N개 조회
       │
       ▼
  OS 판별 (target_os 필드 확인)
       │
       ├── linux  → VDB에서 os_type="linux" 필터로 검색 (U항목만)
       └── windows → VDB에서 os_type="windows" 필터로 검색 (W항목만)
       │
       ▼
  ┌─────────────────── 병렬 처리 (asyncio) ───────────────────┐
  │                                                           │
  │  항목1: 임베딩 → VDB검색(OS필터) → LLM추론 → DB저장       │
  │  항목2: 임베딩 → VDB검색(OS필터) → LLM추론 → DB저장       │
  │  항목3: 임베딩 → VDB검색(OS필터) → LLM추론 → DB저장       │
  │  ...  (동시 실행)                                         │
  │  항목N: 임베딩 → VDB검색(OS필터) → LLM추론 → DB저장       │
  │                                                           │
  └───────────────────────────────────────────────────────────┘
       │
       ▼
  다음 배치 조회 → 반복 (모든 항목 완료까지)

  * Milvus 검색 시 expr='os_type == "linux"' 필터로 해당 OS 가이드라인만 검색
  * 동시 실행 수(concurrency)는 LLM API rate limit에 맞춰 조절
  * Semaphore로 최대 동시 요청 수 제한 (예: 5~10개)


[4단계] 리포트 생성
━━━━━━━━━━━━━━━━━

  판정 결과 DB 조회 ──→ 보고서 자동 생성 (PDF/HTML)

  보고서 포함 내용:
    - 전체 요약 (총 항목 수, 양호/취약 비율, 위험도별 분포)
    - 항목별 상세 (항목코드, 판정결과, 위반사유, 관련규정, 조치방법)
    - 이전 진단 대비 변화 추이 (재진단 시)


[5단계] 재진단 시 비교
━━━━━━━━━━━━━━━━━━━

  새로운 수집 → 새로운 판정 → 이전 판정 결과와 자동 비교
    - 개선된 항목 (취약→양호)
    - 악화된 항목 (양호→취약)
    - 유지된 항목
```

---

## 아키텍처 다이어그램

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Linux     │     │   Windows   │     │  주통기 PDF  │
│   서버/VM   │     │   서버/PC   │     │  가이드라인   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                    │
       ▼                   ▼                    ▼
┌──────────────────────────────┐     ┌──────────────────┐
│      수집 모듈 (Collectors)   │     │  문서 처리 모듈   │
│  linux_collector.py          │     │  (Knowledge)     │
│  windows_collector.py        │     │  parser → chunker│
│  normalizer.py               │     │  → embedder      │
└──────────────┬───────────────┘     └────────┬─────────┘
               │                              │
               ▼                              ▼
        ┌─────────────┐              ┌─────────────────┐
        │     RDB     │              │   Vector DB     │
        │  (SQLite/   │              │   (Milvus)      │
        │ PostgreSQL) │              │                 │
        └──────┬──────┘              └────────┬────────┘
               │                              │
               └──────────┬───────────────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │    판정 엔진         │
               │  (RAG + LLM)       │
               │                    │
               │  rag_search.py     │
               │  llm_judge.py      │
               │  pipeline.py       │
               └─────────┬──────────┘
                         │
                         ▼
               ┌─────────────────────┐
               │    리포트 생성       │
               │  generator.py      │
               │  comparator.py     │
               └─────────────────────┘
```

---

## 디렉토리 구조

```
vulnerability-scanner/
├── main.py                       # 진입점
├── requirements.txt
├── config/
│   └── settings.py               # 환경 설정 (DB 경로, API 키, Milvus 주소)
│
├── collectors/                   # [역할 A] 시스템 정보 수집
│   ├── linux_collector.py
│   ├── windows_collector.py
│   └── normalizer.py
│
├── knowledge/                    # [역할 B] 가이드라인 & VDB
│   ├── document_parser.py
│   ├── chunker.py
│   ├── embedder.py
│   ├── milvus_loader.py
│   └── data/guidelines/
│
├── database/                     # [역할 C] DB 관리
│   ├── models.py
│   ├── repository.py
│   └── migrations/
│
├── engine/                       # [역할 D] RAG + LLM 판정
│   ├── rag_search.py
│   ├── llm_judge.py
│   └── pipeline.py
│
└── report/                       # [역할 C] 리포트 생성
    ├── generator.py
    ├── comparator.py
    └── templates/
```

---

## 모듈 간 데이터 흐름 (인터페이스)

### 수집 결과 JSON (수집 모듈 → DB)
```json
{
    "scan_id": "scan_20260401_001",
    "scan_date": "2026-04-01T14:30:00",
    "target_os": "linux",
    "items": [
        {
            "category": "계정관리",
            "item_code": "U-01",
            "item_name": "root 계정 원격 접속 제한",
            "collected_value": "PermitRootLogin yes",
            "raw_output": "# sshd_config 전체 내용...",
            "source_command": "grep PermitRootLogin /etc/ssh/sshd_config"
        }
    ]
}
```

### LLM 판정 결과 JSON (판정 엔진 → DB)
```json
{
    "scan_id": "scan_20260401_001",
    "item_code": "U-01",
    "item_name": "root 계정 원격 접속 제한",
    "guideline_ref": "주통기 Unix 서버 U-01",
    "result": "취약",
    "reason": "sshd_config에서 PermitRootLogin이 yes로 설정되어 root 원격 접속이 허용됨",
    "remediation": "/etc/ssh/sshd_config에서 PermitRootLogin을 no로 변경 후 systemctl restart sshd",
    "confidence": 0.95
}
```

### DB 스키마 (핵심 테이블)
```
[수집 결과] scan_results
  - scan_id, scan_date, target_os, category, item_code, item_name,
    collected_value, raw_output, source_command

[판정 결과] judgments
  - judge_id, scan_id, item_code, guideline_ref, result(양호/취약),
    reason, remediation, confidence, llm_response

[리포트] reports
  - report_id, scan_id, created_at, report_path, summary_stats

[비교 결과] comparisons
  - compare_id, current_scan_id, previous_scan_id, item_code,
    prev_result, curr_result, change_status(개선/악화/유지)
```

---

## 병렬 처리 아키텍처 (3단계 상세)

### 왜 병렬 처리가 필요한가?

순차 처리 시 항목 1개당 소요 시간:
```
임베딩 API 호출:  ~0.3초
VDB 검색:        ~0.1초
LLM API 호출:    ~3~5초  ← 병목
DB 저장:         ~0.05초
─────────────────────────
합계:            ~3.5~5.5초/항목
```

Unix 72개 + Windows 47개 = **약 119개 항목** 순차 처리 시:
- 최악: 119 × 5.5초 = **약 11분**
- 병렬 10개 동시: 12배치 × 5.5초 = **약 1분**

### 순차 vs 병렬 비교

```
[순차 처리] — 느림
──────────────────────────────────────────────────────→ 시간
항목1: ████████████
                    항목2: ████████████
                                        항목3: ████████████
                                                            ...

[병렬 처리] — 빠름 (동시 실행 수 = 5 예시)
──────────────────────────────────────────────────────→ 시간
항목1: ████████████
항목2: ████████████
항목3: ████████████
항목4: ████████████
항목5: ████████████
                    항목6: ████████████
                    항목7: ████████████
                    ...
```

### 병렬 처리 흐름도

```
                    ┌──────────────┐
                    │  DB에서 미판정 │
                    │  항목 전체 조회│
                    └──────┬───────┘
                           │
                           ▼
                  ┌────────────────┐
                  │  asyncio 이벤트 │
                  │  루프 시작      │
                  └────────┬───────┘
                           │
              Semaphore(max_concurrent=5~10)
                           │
          ┌────────┬───────┼───────┬────────┐
          ▼        ▼       ▼       ▼        ▼
      ┌───────┐┌───────┐┌───────┐┌───────┐┌───────┐
      │워커 1 ││워커 2 ││워커 3 ││워커 4 ││워커 5 │
      │       ││       ││       ││       ││       │
      │항목 조회││항목 조회││항목 조회││항목 조회││항목 조회│
      │  ↓    ││  ↓    ││  ↓    ││  ↓    ││  ↓    │
      │임베딩  ││임베딩  ││임베딩  ││임베딩  ││임베딩  │
      │  ↓    ││  ↓    ││  ↓    ││  ↓    ││  ↓    │
      │VDB검색││VDB검색││VDB검색││VDB검색││VDB검색│
      │  ↓    ││  ↓    ││  ↓    ││  ↓    ││  ↓    │
      │LLM추론││LLM추론││LLM추론││LLM추론││LLM추론│
      │  ↓    ││  ↓    ││  ↓    ││  ↓    ││  ↓    │
      │DB저장 ││DB저장 ││DB저장 ││DB저장 ││DB저장 │
      └───────┘└───────┘└───────┘└───────┘└───────┘
          │        │       │       │        │
          └────────┴───────┼───────┴────────┘
                           │
                           ▼
                  ┌────────────────┐
                  │  전체 완료 대기  │
                  │  (gather)      │
                  └────────┬───────┘
                           │
                           ▼
                  ┌────────────────┐
                  │  리포트 생성    │
                  └────────────────┘
```

### 핵심 코드 구조 (pipeline.py)

```python
import asyncio
from openai import AsyncOpenAI

# 동시 실행 수 제한 (LLM API rate limit 고려)
MAX_CONCURRENT = 5
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

client = AsyncOpenAI()  # 비동기 OpenAI 클라이언트


async def process_single_item(item: dict) -> dict:
    """항목 1개를 처리하는 워커 (임베딩 → VDB검색 → LLM추론 → 저장)"""
    async with semaphore:  # 동시 실행 수 제한
        # 1) 임베딩
        embedding = await client.embeddings.create(
            model="text-embedding-3-small",
            input=f"{item['item_name']} {item['collected_value']}"
        )
        query_vector = embedding.data[0].embedding

        # 2) VDB 검색 (Milvus에서 관련 가이드라인 검색)
        guidelines = await search_milvus(query_vector, top_k=3)

        # 3) LLM 추론
        prompt = build_prompt(item, guidelines)
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        judgment = parse_judgment(response)

        # 4) DB 저장
        await save_judgment(item['scan_id'], item['item_code'], judgment)

        return judgment


async def run_pipeline(scan_id: str):
    """전체 파이프라인 실행 (병렬)"""
    # DB에서 미판정 항목 전체 조회
    items = get_unjudged_items(scan_id)

    # 모든 항목을 병렬로 처리
    tasks = [process_single_item(item) for item in items]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 실패한 항목 재처리
    failed = [
        (items[i], results[i])
        for i in range(len(results))
        if isinstance(results[i], Exception)
    ]
    if failed:
        print(f"실패 항목 {len(failed)}개, 재시도 중...")
        retry_tasks = [process_single_item(item) for item, _ in failed]
        await asyncio.gather(*retry_tasks, return_exceptions=True)

    # 리포트 생성
    generate_report(scan_id)


# 실행
if __name__ == "__main__":
    asyncio.run(run_pipeline("scan_20260401_001"))
```

### 병렬 처리 설정 가이드

| 설정 | 값 | 설명 |
|------|---|------|
| `MAX_CONCURRENT` | 5~10 | 동시 LLM API 호출 수 (rate limit에 맞춰 조절) |
| `BATCH_SIZE` | 전체 | asyncio.gather로 전체를 한번에 스케줄링, Semaphore가 제어 |
| `RETRY_COUNT` | 2 | API 실패 시 재시도 횟수 |
| `TIMEOUT` | 30초 | 항목당 최대 대기 시간 |

### 주의사항

1. **Rate Limit**: OpenAI/Claude API는 분당 요청 수 제한이 있음. Semaphore 값을 API 제한에 맞춰 설정
2. **DB 동시 쓰기**: SQLite는 동시 쓰기에 약함 → asyncio에서는 단일 스레드이므로 큰 문제 없지만, WAL 모드 활성화 권장
3. **에러 처리**: 개별 항목 실패가 전체를 중단시키지 않도록 `return_exceptions=True` 사용
4. **진행률 표시**: tqdm 또는 콜백으로 처리 진행률 표시 가능

---

## 추진 일정

| 월 | 주요 활동 | 마일스톤 |
|----|---------|---------|
| **3월** | 요구사항 분석, 전체 설계, 가이드라인 문서 수집/분석 | 설계 문서 완성 |
| **4월** | 수집 스크립트 개발, DB 구축, VDB 구축 및 가이드라인 적재 | 개별 모듈 완성 |
| **5월** | RAG 검색 구현, LLM 연동 및 판정 파이프라인 개발 | 핵심 기능 연동 |
| **6월** | 리포트 생성, 통합 테스트, 최종 결과물 완성 | 시스템 완성 |
