# 팀 구성 및 역할 분담

## 팀원 정보

| 구분 | 이름 | 학번 | 전공 | 담당 역할 |
|------|------|------|------|---------|
| 팀장 | 이서연 | 92313491 | 정보보호학과 | **Linux 수집 스크립트** |
| 팀원 | 강지혁 | 92313269 | 정보보호학과 | **Windows 수집 스크립트** |
| 팀원 | 고은이 | 92313271 | 정보보호학과 | **RAG 파이프라인 + VDB 구축** |
| 팀원 | 백서진 | 92313386 | 정보보호학과 | **DB 설계 + 웹 대시보드 + 리포트** |

---

## 역할 상세

### 이서연 (팀장): Linux 수집 스크립트 개발

**한줄 요약:** Linux 시스템에서 보안 관련 정보를 자동 수집하는 스크립트 개발

**담당 모듈:** `collectors/linux_collector.py`, `collectors/normalizer.py` (공동)

**주요 업무:**
- Linux 수집 스크립트 개발 (Python + subprocess)
  - 계정 정보: `/etc/passwd`, `/etc/shadow`, `/etc/group` 파싱
  - 파일 권한: 주요 설정 파일 퍼미션 확인 (644, 600 등)
  - 서비스: `systemctl list-units`, 열린 포트 확인
  - 네트워크: `iptables`, `firewalld` 규칙 수집
  - 시스템 설정: `/etc/ssh/sshd_config`, PAM 설정 등
- 주통기 Unix 서버 점검항목(U-01~U-72) 기준으로 수집 항목 정의
- 수집 결과를 통일된 JSON 스키마로 정규화 (강지혁과 공동)
- 팀장으로서 프로젝트 전체 일정 관리 및 조율

**산출물:**
- `collectors/linux_collector.py`
- `collectors/normalizer.py` (강지혁과 공동)
- Linux 수집 항목 정의서 (어떤 항목을 어떤 명령어로 수집하는지)

**필요 역량:** Python, Linux 시스템 명령어 (cat, grep, awk, systemctl 등), 정규표현식

**월별 계획:**
| 월 | 업무 |
|----|------|
| 3월 | 주통기 Unix 서버 가이드라인 분석 → Linux 수집 항목 목록 정의 |
| 4월 | Linux 수집 스크립트 개발 (U-01~U-72 대응) |
| 5월 | 수집 데이터 정규화, DB 저장 모듈(백서진)과 연동 테스트 |
| 6월 | WSL2/VM 환경 테스트, 버그 수정, 발표 준비 |

---

### 강지혁: Windows 수집 스크립트 개발

**한줄 요약:** Windows 시스템에서 보안 관련 정보를 자동 수집하는 스크립트 개발

**담당 모듈:** `collectors/windows_collector.py`, `collectors/normalizer.py` (공동)

**주요 업무:**
- Windows 수집 스크립트 개발 (Python + PowerShell)
  - 계정 정보: `net user`, 로컬 보안 정책 (`secedit`)
  - 레지스트리: 보안 관련 레지스트리 값 조회
  - 서비스: `Get-Service`, 시작 프로그램 목록
  - 방화벽: `Get-NetFirewallRule`
  - 감사 정책: `auditpol /get /category:*`
  - 공유 폴더: `net share`
- 주통기 Windows 서버 점검항목(W-01~W-84) 기준으로 수집 항목 정의
- 수집 결과를 통일된 JSON 스키마로 정규화 (이서연과 공동)

**산출물:**
- `collectors/windows_collector.py`
- `collectors/normalizer.py` (이서연과 공동)
- Windows 수집 항목 정의서

**필요 역량:** Python, PowerShell, Windows 보안 설정 (로컬 보안 정책, 레지스트리)

**월별 계획:**
| 월 | 업무 |
|----|------|
| 3월 | 주통기 Windows 서버 가이드라인 분석 → 수집 항목 목록 정의 |
| 4월 | Windows 수집 스크립트 개발 (W-01~W-84 대응) |
| 5월 | 수집 데이터 정규화, DB 저장 모듈(백서진)과 연동 테스트 |
| 6월 | Windows 10/11 PC 환경 테스트, 버그 수정 |

---

### 고은이: RAG 파이프라인 + 가이드라인 VDB 구축

**한줄 요약:** 주통기 가이드라인을 VDB에 적재하고, RAG + LLM으로 취약점을 판정하는 핵심 파이프라인 개발

**담당 모듈:** `knowledge/`, `engine/`

**주요 업무:**
- **가이드라인 문서 처리 & VDB 구축:**
  - 주통기 가이드라인 PDF 파싱 (PyMuPDF, pdfplumber)
  - 점검항목 단위 청킹 (항목코드, 항목명, 판단기준, 조치방법)
  - 메타데이터 태깅 (os_type: linux/windows, 분류, 중요도)
  - 임베딩 모델로 벡터 변환 후 Milvus에 적재
  - 검색 품질 검증
- **RAG 검색 + LLM 판정 파이프라인:**
  - 수집 항목 임베딩 → VDB에서 관련 가이드라인 검색 (OS별 필터링)
  - LLM 판정 프롬프트 설계 (수집 데이터 + 가이드라인 → 양호/취약)
  - 판정 결과 JSON 파싱
  - asyncio 기반 병렬 처리 (Semaphore로 동시 요청 제어)
- 팀원 간 모듈 인터페이스 정의 및 통합 조율

**산출물:**
- `knowledge/document_parser.py`
- `knowledge/chunker.py`
- `knowledge/embedder.py`
- `knowledge/milvus_loader.py`
- `engine/rag_search.py`
- `engine/llm_judge.py`
- `engine/pipeline.py`
- 프롬프트 템플릿 문서

**필요 역량:** Python, LLM API, RAG 개념, 임베딩/NLP 기본, LangChain, Docker (Milvus), asyncio

**월별 계획:**
| 월 | 업무 |
|----|------|
| 3월 | 가이드라인 문서 분석, 청킹 전략 수립, LLM API 선정 |
| 4월 | PDF 파싱/청킹 구현, Milvus 환경 구축 및 데이터 적재, RAG 파이프라인 설계 |
| 5월 | RAG 검색 + LLM 판정 구현, 프롬프트 튜닝, 병렬 처리 구현 |
| 6월 | 판정 정확도 검증, 전체 통합, 발표 준비 |

---

### 백서진: DB 설계/구축 + 웹 대시보드 + 리포트 생성

**한줄 요약:** 전체 데이터 저장 구조 설계 + 웹 대시보드 UI + 보안 점검 보고서 자동 생성

**담당 모듈:** `database/`, `web/`, `report/`

**주요 업무:**
- **DB 스키마 설계 및 구축:**
  - `scan_results` — 수집 결과 저장
  - `judgments` — LLM 판정 결과 저장
  - `reports` — 생성된 보고서 메타정보
  - `comparisons` — 이전 진단 비교 결과
  - CRUD API 개발 (저장, 조회, 비교 함수)
  - SQLite 기반 개발 → PostgreSQL 전환 고려
- **웹 대시보드 개발 (FastAPI + Jinja2):**
  - FastAPI 라우터 및 API 엔드포인트 구현
  - Jinja2 HTML 템플릿 작성 (대시보드, 업로드, 결과 조회, 비교 등)
  - 정적 파일 (CSS/JS) 작성
  - 파일 업로드 처리, 판정 실행 트리거, 실시간 진행률 표시
- **보고서 자동 생성 (PDF/HTML):**
  - 전체 요약 (양호/취약 비율, 위험도별 분포)
  - 항목별 상세 (판정결과, 위반사유, 조치방법)
  - 이전 진단 대비 변화 추이
- 재진단 시 이전 결과 비교 기능

**산출물:**
- `database/models.py`
- `database/repository.py`
- `web/routes/` (pages.py, upload.py, judge.py, report.py)
- `web/templates/` (HTML 템플릿 8개)
- `web/static/` (CSS, JS)
- `report/generator.py`
- `report/comparator.py`
- DB 설계 문서 (ERD)

**필요 역량:** Python, SQL, ORM(SQLAlchemy), FastAPI, HTML/CSS/JS, Jinja2, WeasyPrint

**월별 계획:**
| 월 | 업무 |
|----|------|
| 3월 | DB 스키마 설계, 웹 UI 와이어프레임, 보고서 포맷 기획 |
| 4월 | DB 구축, CRUD API 개발, 웹 대시보드 기본 구조 구현 |
| 5월 | 판정 결과 저장, 이전 진단 비교, 웹 페이지 기능 완성 |
| 6월 | 리포트 자동 생성 (PDF), 웹 UI 마무리, 통합 테스트 |

---

## 역할 간 협업 흐름

```
이서연 (Linux 수집) ──┐
                      ├──→ 백서진 (DB 저장) ──→ 고은이 (RAG+LLM 판정) ──→ 백서진 (리포트+웹)
강지혁 (Windows 수집) ─┘                              ↑
                                              고은이 (VDB 검색)
```

| 연결 | 주고받는 것 |
|------|-----------|
| 이서연/강지혁 → 백서진 | 수집 결과 JSON (정규화된 시스템 정보) |
| 백서진 → 고은이 | DB에서 수집 항목 조회 API |
| 고은이 (VDB) → 고은이 (RAG) | VDB 검색 인터페이스 (유사도 검색 결과) |
| 고은이 → 백서진 | LLM 판정 결과 JSON |
| 백서진 → 웹/리포트 | 판정 결과 + 이전 비교 → 웹 표시 + 보고서 출력 |

---

## 역할별 난이도

| 담당자 | 역할 | 난이도 | 비고 |
|--------|------|--------|------|
| **이서연** | Linux 수집 | 중 | Linux 명령어, subprocess, 팀장 역할 겸임 |
| **강지혁** | Windows 수집 | 중 | PowerShell, Windows 보안 설정 |
| **고은이** | RAG + VDB | 상 | LLM/RAG/임베딩/Milvus/asyncio — 범위가 넓지만 핵심 |
| **백서진** | DB + 웹 + 리포트 | 중상 | DB/웹/PDF 생성 — 범위가 넓지만 기술 난이도는 중간 |
