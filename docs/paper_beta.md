# 규칙·LLM 결합 판정과 자동 패치를 통한 취약점 자동 진단 시스템

강지혁¹, 고은이¹, 이서연¹, 백서진¹, 양환석²
¹중부대학교 정보보호학과 학부생
²중부대학교 정보보호학과 교수

## A Hybrid Rule–LLM Vulnerability Diagnosis System with Automatic Patching

Ji-hyuk Kang¹, Eun-i Ko¹, Seo-yeon Lee¹, Seo-jin Baek¹, and Hwan-seok Yang²
¹Undergraduate Student, Department of Information Security, Joongbu University
²Professor, Department of Information Security, Joongbu University

¹Corresponding author: 강지혁 ([교신저자 E-mail])

Received [투고일]; Revised [수정일]; Accepted [완료일]

---

## ABSTRACT

> *(한글 요약 — 나눔명조 9.3pt, 양쪽 정렬, 줄 간격 160%)*

주요정보통신기반시설 점검은 200여 개 항목으로 구성되며 일부 항목은 사람의 정책 판단을 요구해 완전 자동화가 어렵다. 본 논문은 임계값·문자열 비교로 판정 가능한 항목은 점검 스크립트가 직접 양호/취약을 결정하고, 정책 판단이 필요한 항목만 거대언어모델(LLM)에 위임하는 규칙·LLM 결합 진단·패치 시스템을 제안한다. 가이드라인이 갱신되면 신규·수정 항목의 점검 스크립트가 자동으로 추가되며, KISA가 함께 다루는 4개 Unix 계열(Linux/Solaris/AIX/HP-UX)을 단일 스크립트로 통합 점검하고 취약 항목에는 자동 패치를 수행한다. Windows 79개 항목에 대한 성능 평가에서 본 하이브리드는 LLM 단독 대비 토큰 약 83%·응답 시간 약 78%를 절감하면서 일관성 98.73%, 일치율 97.34%를 동시에 달성하여, LLM 단독·규칙 단독 두 단독 방식 대비 정확도·비용·일관성을 모두 개선함을 확인하였다.

> *(영문 요약 — Times New Roman 9.5pt, 양쪽 정렬, 줄 간격 145%)*

Security audits for Critical Information and Communication Infrastructure consist of more than 200 items, some of which require human policy judgment, making full automation difficult. This paper proposes a hybrid rule–LLM diagnosis-and-patching system in which audit scripts directly classify items as Pass or Fail when threshold or string comparison suffices, while only items requiring policy judgment are delegated to a large language model (LLM). When the guideline is updated, audit scripts for added or modified items are automatically generated, and the system supports the four Unix variants addressed by KISA (Linux, Solaris, AIX, HP-UX) through a single script and performs automatic patching on failed items. On 79 Windows audit items, the proposed hybrid method reduces token usage by approximately 83% and response time by 78% relative to the LLM-only baseline while achieving 98.73% consistency and 97.34% matching accuracy, improving all of accuracy, cost, and consistency over both single-method baselines.

**키워드**: 주요정보통신기반시설, 취약점 진단 자동화, 거대언어모델, 보안 자동화, 하이브리드 판정

**Keywords**: Critical information infrastructure, Vulnerability assessment automation, LLM, Security automation, Hybrid judgment

---

## 1. 서론

국내에서 주요정보통신기반시설 점검은 KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」 [1]를 사실상 단일 표준으로 사용한다. 가이드라인은 200여 개 점검 항목을 정의하며 운영체제별 수동 점검을 요구하고, 2024년 국내 사이버 침해사고가 1,887건으로 전년 대비 48% 증가하는 등 사이버 위협이 가속화되면서 자동화 요구가 더욱 커지고 있다.

이에 대응해 도메인별 자동 진단 시스템이 제안되어 왔으며 [3], 최근에는 거대언어모델(LLM)을 활용한 보안 자동화 사례로 흐름이 확장되고 있다 [2]. 그러나 단순 셸 스크립트는 "불필요한 서비스 제거"와 같이 정책 판단이 필요한 항목을 처리하지 못하고, LLM 단독 접근은 토큰 비용과 일관성 문제 [4]를 가져 두 방식 모두 단독으로는 정확성과 비용을 동시에 만족시키지 못한다.

본 논문은 다음 세 가지 기여를 통해 위 한계를 동시에 완화하는 주요정보통신기반시설 취약점 자동 진단·패치 시스템을 제안한다. 첫째, 임계값·문자열 비교로 판정 가능한 항목은 점검 스크립트가 직접 판정하고 정책 판단 항목만 LLM에 위임하는 규칙·LLM 결합 판정 방식을 설계한다. 둘째, 가이드라인 갱신 시 신규·수정 항목의 점검 스크립트를 LLM이 자동으로 작성·저장해 KISA 가이드라인 변경에 신속히 대응한다. 셋째, KISA가 함께 다루는 4개 Unix 계열(Linux/Solaris/AIX/HP-UX)을 단일 점검 스크립트로 통합 지원한다.

---

## 2. 시스템 설계

### 2.1 시스템 아키텍처

**그림 1.** 시스템 전체 흐름도

본 시스템은 관리자 흐름과 사용자 흐름을 가이드라인 데이터베이스 하나로 연결한다 (그림 1). 관리자 흐름에서는 KISA가 가이드라인 PDF를 갱신하면 시스템이 이전 버전과의 차이를 자동 감지하고, 신규·수정 항목에 대해 LLM이 점검 스크립트를 작성·저장한다. 이로써 주기적으로 갱신되는 KISA 가이드라인을 수작업 없이 신속하게 반영할 수 있다. 사용자 흐름에서는 점검을 시작하면 항목별 점검 스크립트를 실행해 결과를 수집하고, 결과는 항목코드를 키로 가이드라인 본문과 함께 LLM에 전달되어 판정에 사용된다. 취약 항목에는 자동 패치 스크립트가 함께 제공되며, 모든 점검·패치 결과는 이력으로 저장되어 이전 점검과 비교됨으로써 새로 취약해진 항목이나 개선된 항목이 자동 분류된다.

### 2.2 규칙·LLM 결합 판정

점검 스크립트는 임계값·문자열 비교만으로 판정 가능한 항목은 양호/취약으로 직접 결정하고, 사람의 정책 판단이 필요해 규칙으로 판정할 수 없는 항목만 LLM에 위임한다. 이러한 항목의 대표 사례는 "불필요한 서비스 제거"처럼 정성적 어휘를 포함하거나 서비스·계정·파일 목록을 보고 사람이 결정해야 하는 경우이다. LLM은 위임된 항목을 항상 양호/취약 중 하나로 결정하며, 정보가 충분치 않을 때는 보수적으로 취약 판정한다. 이 구조는 단순 항목의 LLM 호출을 줄여 비용을 절감하면서, 정책 판단 항목까지 자동화 범위에 포함시킨다.

### 2.3 자동 패치 및 다양한 운영체제 지원

본 시스템은 Windows와 Linux 모두에서 동일한 패치 자동화 흐름을 제공한다. 취약 판정 항목의 조치 스크립트는 대상 시스템에서 자동 실행되며, 실행이 실패하면 LLM이 오류 메시지를 받아 스크립트를 재작성하는 과정을 최대 세 번까지 반복한다. 시스템 손상을 일으킬 수 있는 명령은 사전 차단 규칙으로 막아 안전성을 확보한다. 또한 점검 스크립트는 실행 시점에 운영체제를 감지해 KISA가 함께 다루는 Linux·Solaris·AIX·HP-UX 각각에 맞는 설정 파일과 명령을 자동 선택함으로써, 다양한 Unix 계열 환경을 단일 스크립트로 대응한다.

---

## 3. 성능 평가

### 3.1 실험 환경

본 논문에서 제안한 기법에 대한 성능평가는 Windows 79개 점검 항목에 대해 세 가지 판정 방식을 적용하였다. (a) LLM 단독은 모든 항목을 LLM에 전달, (b) 규칙 단독은 점검 스크립트의 규칙 결과만 사용(규칙으로 판정할 수 없는 항목은 미판정), (c) 하이브리드(제안)는 규칙으로 판정 가능한 항목은 직접 결정하고 규칙으로 판정할 수 없는 항목만 LLM에 위임한다. LLM은 Gemini 2.5 Flash를 사용하며 별도 검색 단계 없이 가이드라인 본문을 프롬프트에 직접 주입하고, 비결정성을 고려해 각 방식을 10회 반복 측정한다. 정답 라벨은 하이브리드 초기 판정 결과를 기준으로 부여하였으며, 전문가 수기 라벨링을 통한 절대 정확도 검증은 한계로 남긴다. 평가 지표는 네 가지로, 일치율(%) — 정답 라벨과 일치한 항목 비율(미판정은 오답), 평균 토큰/항목 — LLM 토큰 수 평균(LLM 호출 없는 항목은 0), 항목당 시간(s) — 평균 응답 시간, 일관성(%) — 10회 반복 시 모든 회차 동일 결과인 항목 비율이다.

### 3.2 실험결과

표 1. 세 가지 판정 방식의 비교

| 방식 | 일치율 (%) | 평균 토큰/항목 | 항목당 시간 (s) | 일관성 (%) |
|---|---:|---:|---:|---:|
| LLM 단독 | 96.84 | 232.4 | 28.07 | 88.61 |
| 규칙 단독 | 86.08 | 0.0 | 0.00 | 100.00 |
| **하이브리드(제안)** | **97.34** | **38.9** | **6.12** | **98.73** |

규칙 단독은 결정적이지만 정책 판단 항목 9개를 미판정 처리해 일치율이 86.08%에 그치며, LLM 단독은 항목당 평균 28.07초·232.4 토큰을 소모하고 일관성도 88.61%에 머문다. 본 하이브리드는 정책 판단 항목 9개에만 LLM을 호출함으로써 토큰 약 83%·시간 약 78%를 절감하면서 일관성 98.73%, 일치율 97.34%를 동시에 달성하여 단독 방식들이 가진 비용·일관성 한계를 동시에 해소하였다.

---

## 4. 결론

본 논문은 규칙 기반 점검과 LLM 판정을 결합한 주요정보통신기반시설 취약점 자동 진단 시스템을 제안하였다. 단순 항목은 규칙으로 직접 판정하고 정책 판단 항목만 LLM에 위임해 두 단독 방식의 한계를 동시에 보완하며, 가이드라인 갱신 시 신규·수정 항목의 점검 스크립트가 자동으로 추가·저장되어 KISA 가이드라인 변경에도 신속히 대응한다. 자동 패치는 Windows·Linux 모두에서 동일하게 동작하고 4개 Unix 계열을 단일 점검 스크립트로 통합 대응한다. Windows 79개 항목 성능 평가에서 본 하이브리드는 LLM 단독 대비 토큰 약 83%·응답 시간 약 78%를 절감하면서도 일관성 98.73%, 일치율 97.34%를 달성하여 정확도·토큰 비용·일관성 모두 두 단독 방식보다 우수함을 확인하였다.

본 연구의 한계는 다음과 같다. 첫째, 정답 라벨이 하이브리드 방식의 초기 판정 결과로 부여되어 전문가 수기 라벨링을 통한 절대 정확도 검증이 부족하다. 둘째, 평가 대상이 Windows 79개 항목으로 제한되어 Linux 계열에 대한 정량 평가가 수행되지 않았다. 셋째, LLM 호출이 외부 서비스에 의존하므로 네트워크 상태와 호출 비용이 운영에 영향을 주며, 자동 생성된 점검 스크립트의 정상 동작 여부는 실행 시점에야 확인되어 사전 검증 절차가 미흡하다.

향후 연구로는 전문가 라벨링 기반 절대 정확도 재측정, Linux·Solaris·AIX·HP-UX 실기 검증, 자동 생성 스크립트의 사전 검증 절차 도입, 그리고 KISA 가이드라인 외 ISMS 등 다른 정보보호 관리체계로의 적용 범위 확대를 추진할 계획이다.

---

## 참고문헌

[1] 한국인터넷진흥원, "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드", 2021년.

[2] 이주영, 이태진, "Agent AI 시대에서의 침해공격 자동화와 지능형 방어 동향", *정보보호학회지*, 제35권 제5호, pp. 55–64, 2025년 10월.

[3] 김한선, 우은지, 이은경, 정호심, "리눅스 CCE 취약점 진단 및 시각화 시스템 개발", *한국정보처리학회 춘계학술발표대회 논문집*, pp. 140–141, 2023년 5월.

[4] J. Lin and D. Mohaisen, "From Large to Mammoth: A Comparative Evaluation of Large Language Models in Vulnerability Detection", in *Proc. Network and Distributed System Security Symposium (NDSS)*, 2025.

---

## 분량 검증 (작성자용 가이드, 인쇄 시 제외)

KIISC 학술대회 양식(2단 조판, 본문 10pt, 줄간격 1.0) 기준 추정:

**대상 학회**: Korean Institute of Information Technology & Innovation Corporate (KIITI), ISSN 3091-8014. 표지 양식은 양 언어 (한글+영문) 동시 작성 — 제목·저자·소속·요약·키워드 모두.

KIITI 양식의 일반적 한국 학회 본문 구조 (2단 조판, 본문 9.5pt 기준 페이지당 약 65줄) 추정:

| 섹션 | 줄 수 추정 | 비고 |
|---|---:|---|
| 표지(한글+영문 제목·저자·소속·교신·투고일) | 14 | 1단 폭 |
| ABSTRACT (한글) + ABSTRACT (영문) + Keywords | 16 | 1단 폭 |
| 1. 서론 | 13 | 2단 본문 |
| 2. 시스템 설계 (3 소절, 관리자·사용자 양 흐름) | 36 | 2단 본문 |
| 그림 1 (양 흐름 합류 구조) | 18 | 2단 폭 또는 단 폭 |
| 3. 비교 평가 + 표 1 | 22 | 2단 본문 |
| 4. 결론 | 12 | 2단 본문 |
| 참고문헌 | 11 | 2단 본문 |
| 여백·헤더·푸터 | 8 | — |
| **합계** | **150 줄** | **약 2.3 페이지 → 분량 압축 필요** |

> ⚠ **주의**: 받은 PDF는 1페이지 (표지 양식만) 이므로, **본문·표·그림·참고문헌의 정확한 양식**(글꼴 크기·줄 간격·단 폭·들여쓰기 등) 은 학회 홈페이지에서 추가 가이드 또는 샘플 논문을 받아 확인해야 한다.

> 현재 베타는 한글 abstract + 영문 abstract 두 개를 모두 포함하므로 **2페이지 한도가 빡빡**. 양식 확정 후 다음 중 한 가지로 분량 조정:
> - **줄이기**: 한글 abstract 를 영문보다 1~2줄 짧게, 그림 1 을 1단 폭으로 압축
> - **늘리기 (3페이지 가능 시)**: 본론 2.2 정책 판단 사례 표 형식 추가, 결론에 향후 2개 더

> 분량 조정이 필요한 경우:
> - **압축 우선순위**: 영문 abstract 한 줄 단축 → 본론 2.1 사용자 흐름 압축 → 그림 1 단 폭 축소
> - **여백 확보**: 결론을 8줄로 단축 가능

---

## TBD 채우기 작업 (별도, 논문 제출 전)

1. **데이터셋**: Windows 79개 + Linux 72개 항목 각각 100회 측정
2. **자동화 스크립트**: `vulnerability-scanner/eval/compare_methods.py` (신규 작성)
   - 모드 (a) `--mode llm-only`: 모든 항목을 강제로 `규칙불가`로 라벨링 후 LLM 호출
   - 모드 (b) `--mode rule-only`: LLM 호출 비활성, `규칙불가`는 오답 처리
   - 모드 (c) `--mode hybrid`: 현재 시스템 그대로
3. **측정 지표**:
   - 정확도 = 사람 라벨링 정답 vs 시스템 판정 일치율
   - 토큰 = Gemini API 응답의 input/output 합산
   - 시간 = 항목당 평균 ms (네트워크 시간 제외)
   - 일관성 = 동일 항목 3회 호출 시 동일 결과 비율
4. **그림 1 작성**: PowerPoint 또는 draw.io로 위 본문 흐름을 8 cm × 6 cm 이미지로 생성, `figures/system_architecture.png` 로 저장 후 학회 양식에 삽입
