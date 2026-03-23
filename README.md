# AI 기반 시스템 보안 자동 진단 및 취약점 리포팅 시스템

> 주요정보통신기반시설(주통기) 보안 가이드라인 기반, RAG + LLM을 활용한 자동 취약점 판정 시스템

## 프로젝트 소개

보안 점검은 여전히 전문 인력이 수작업으로 수행하고 있어 시간과 비용이 많이 들고, 점검자에 따라 결과가 달라지는 문제가 있습니다.

본 프로젝트는 **시스템 보안 점검 전 과정을 자동화**합니다.
- 시스템 보안 정보를 **자동 수집**
- 정부 보안 가이드라인과 **AI가 자동 비교/판정**
- 문제 항목과 해결 방법을 담은 **보고서 자동 생성**

## 시스템 아키텍처

```
                    ┌──────────────┐
                    │ 주통기 PDF    │
                    │ 가이드라인    │
                    └──────┬───────┘
                           │ 파싱/청킹/임베딩
                           ▼
┌───────────┐       ┌──────────────┐
│  Linux    │       │  Vector DB   │
│  서버/VM  │──┐    │  (Milvus)    │
└───────────┘  │    └──────┬───────┘
               │           │
┌───────────┐  │    ┌──────┴───────┐       ┌──────────────┐
│  Windows  │──┼──→ │  RAG + LLM   │──────→│  보안 점검    │
│  서버/PC  │  │    │  판정 엔진    │       │  보고서 (PDF) │
└───────────┘  │    └──────────────┘       └──────────────┘
               │           ▲
               │    ┌──────┴───────┐
               └──→ │     RDB      │
                    │ (SQLite/PG)  │
                    └──────────────┘
```

## 파이프라인 흐름

| 단계 | 설명 | 비고 |
|------|------|------|
| **1. 지식 기반 구축** | 주통기 가이드라인 PDF → 청킹 → 임베딩 → Milvus 저장 | 사전 1회 수행 |
| **2. 시스템 정보 수집** | Linux/Windows 보안 정보 자동 수집 → DB 저장 | Python + Shell/PowerShell |
| **3. RAG + LLM 판정** | 수집 항목 임베딩 → VDB 검색 → LLM 양호/취약 판정 | **병렬 처리 (asyncio)** |
| **4. 리포트 생성** | 판정 결과 → PDF/HTML 보고서 자동 생성 | 이전 진단 비교 포함 |

### 병렬 처리

LLM API 호출이 병목이므로 `asyncio` + `Semaphore`로 여러 항목을 동시 처리합니다.

```
순차: 119개 항목 × 5초 = ~11분
병렬: 동시 10개 처리  = ~1분
```

## 점검 대상

| 구분 | 기준 | 항목 수 |
|------|------|---------|
| **Unix/Linux 서버** | 주통기 U-01 ~ U-72 | 72개 |
| **Windows 서버** | 주통기 W-01 ~ W-84 | 47개 (PC 적용 가능) |

점검 분류: 계정 관리, 파일/디렉토리 관리, 서비스 관리, 패치 관리, 로그 관리, 보안 관리

## 기술 스택

| 구분 | 기술 |
|------|------|
| 언어 | Python 3.10+ |
| 수집 | subprocess, PowerShell |
| RDB | SQLite → PostgreSQL |
| Vector DB | Milvus |
| 임베딩 | OpenAI `text-embedding-3-small` / HuggingFace |
| LLM | GPT-4o / Claude |
| RAG | LangChain |
| 리포트 | Jinja2 + WeasyPrint |

## 프로젝트 구조

```
vulnerability-scanner/
├── main.py                  # 진입점
├── config/settings.py       # 환경 설정
├── collectors/              # 시스템 정보 수집
│   ├── linux_collector.py
│   ├── windows_collector.py
│   └── normalizer.py
├── knowledge/               # 가이드라인 & VDB
│   ├── document_parser.py
│   ├── chunker.py
│   ├── embedder.py
│   └── milvus_loader.py
├── database/                # DB 관리
│   ├── models.py
│   └── repository.py
├── engine/                  # RAG + LLM 판정
│   ├── rag_search.py
│   ├── llm_judge.py
│   └── pipeline.py
└── report/                  # 리포트 생성
    ├── generator.py
    ├── comparator.py
    └── templates/
```

## 팀 구성

| 구분 | 이름 | 전공 |
|------|------|------|
| 팀장 | 이서연 | 정보보호학과 |
| 팀원 | 강지혁 | 정보보호학과 |
| 팀원 | 고은이 | 정보보호학과 |
| 팀원 | 백서진 | 정보보호학과 |

> 중부대학교 정보보호학과 | 2026-1 캡스톤디자인 | 취약점 진단 및 평가 | 양환석 교수

## 문서

| 파일 | 내용 |
|------|------|
| [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | 파이프라인, 아키텍처, 병렬처리 설계 |
| [TEAM_ROLES.md](TEAM_ROLES.md) | 필요 역할 4개 상세 |
| [TECH_STACK.md](TECH_STACK.md) | 역할별 기술 및 패키지 |
| [주통기_Unix서버_점검항목.md](주통기_Unix서버_점검항목.md) | U-01~U-72 점검항목 |
| [주통기_Windows서버_점검항목.md](주통기_Windows서버_점검항목.md) | W항목 + PC항목 |

## 일정

| 월 | 주요 활동 |
|----|---------|
| 3월 | 요구사항 분석 / 설계 / 가이드라인 분석 |
| 4월 | 수집 스크립트 / DB 구축 / VDB 구축 |
| 5월 | RAG 검색 / LLM 판정 파이프라인 |
| 6월 | 리포트 생성 / 통합 테스트 / 완성 |
