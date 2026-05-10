"""
vulnerability-scanner/engine/script_generator.py

가이드라인 항목(vs_guideline_items)을 기반으로 OS별 점검 스크립트를
자동 생성하고 MCP를 통해 지정 경로에 배포하는 엔진 모듈.

흐름:
  euni_adapter.py (PDF 파싱 완료)
    → generate_missing_scripts()         # 신규 항목 감지
    → _build_prompt()                    # 프롬프트 구성
    → _call_gemini()                     # 코드 생성
    → _validate_script()                 # 문법·안전성 검증
    → _save_via_mcp()                    # MCP write_file 배포
    → _register_to_db()                  # vs_script_registry 등록
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import textwrap
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Optional

from google import genai              # pip install google-genai  (신규 공식 SDK)
from google.genai import types as genai_types  # GenerateContentConfig 등

# ---------------------------------------------------------------------------
# 로거
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 상수 / 설정
# ---------------------------------------------------------------------------
GEMINI_MODEL = "gemini-2.0-flash"
MAX_RETRIES = 3

# 생성된 스크립트의 상태값 (Human-in-the-loop 지원)
class ScriptStatus(str, Enum):
    PENDING_REVIEW = "pending_review"   # 자동 생성 후 관리자 검토 대기
    APPROVED       = "approved"         # 관리자 승인 완료
    REJECTED       = "rejected"         # 관리자 거부
    DEPLOYED       = "deployed"         # scripts/ 폴더에 실제 배포 완료

# OS별 저장 경로 및 확장자
OS_CONFIG = {
    "Linux":   {"dir": "linux",   "ext": ".py"},
    "Windows": {"dir": "windows", "ext": ".ps1"},
}

SCRIPTS_BASE = "vulnerability-scanner/scripts"


# ---------------------------------------------------------------------------
# 데이터 모델
# ---------------------------------------------------------------------------
@dataclass
class GuidelineItem:
    """vs_guideline_items 테이블의 한 행을 표현."""
    item_code:        str            # e.g. "U-73"
    os_type:          str            # "Linux" | "Windows"
    title:            str
    criteria:         str            # 점검 기준 텍스트
    check_examples:   Optional[str]  # 점검 예시 (optional)
    remediation_guide: Optional[str] # 조치 방법 (optional)


@dataclass
class GeneratedScript:
    item_code: str
    os_type:   str
    code:      str
    file_path: str
    status:    ScriptStatus = ScriptStatus.PENDING_REVIEW


# ---------------------------------------------------------------------------
# 의존성 인터페이스 (실제 구현체로 교체)
# ---------------------------------------------------------------------------
class AbstractRepository:
    """DB 접근 추상 인터페이스. 실제 구현체(SQLAlchemy 등)로 교체하세요."""

    async def get_items_without_scripts(self) -> list[GuidelineItem]:
        """
        스크립트 파일이 아직 없는 가이드라인 항목 목록 반환.

        SQL 예시:
            SELECT gi.*
            FROM vs_guideline_items gi
            LEFT JOIN vs_script_registry sr
                   ON gi.item_code = sr.item_code
                  AND gi.os_type   = sr.os_type
            WHERE sr.item_code IS NULL
               OR sr.status NOT IN ('approved', 'deployed');
        """
        raise NotImplementedError

    async def register_script(self, script: GeneratedScript) -> None:
        """
        vs_script_registry 테이블에 생성된 스크립트 메타데이터 저장.

        INSERT INTO vs_script_registry
            (item_code, os_type, file_path, status, created_at)
        VALUES (...)
        ON CONFLICT (item_code, os_type) DO UPDATE SET ...;
        """
        raise NotImplementedError

    async def get_sample_scripts(self, os_type: str, limit: int = 2) -> list[str]:
        """
        Few-shot 예시용으로 기존 승인된 스크립트 코드 반환.
        vs_script_registry에서 approved/deployed 상태의 파일 경로를 읽어
        실제 파일 내용을 반환하면 됩니다.
        """
        raise NotImplementedError


class AbstractMCPClient:
    """MCP 서버 클라이언트 추상 인터페이스."""

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 프롬프트 빌더
# ---------------------------------------------------------------------------
def _build_prompt(item: GuidelineItem, few_shot_examples: list[str]) -> str:
    """
    가이드라인 항목 + Few-shot 예시를 조합하여 LLM 프롬프트 생성.
    """
    lang = "Python (Linux bash subprocess 활용)" if item.os_type == "Linux" else "PowerShell"

    examples_block = ""
    for i, ex in enumerate(few_shot_examples, 1):
        examples_block += f"\n### 기존 스크립트 예시 {i}\n```\n{ex}\n```\n"

    prompt = textwrap.dedent(f"""
        당신은 보안 설정 점검 스크립트 전문가입니다.
        다음 가이드라인을 바탕으로 {item.os_type}용 점검 스크립트를 작성하세요.

        ## 가이드라인 정보
        - 항목코드 : {item.item_code}
        - 항목명   : {item.title}
        - OS 타입  : {item.os_type}
        - 점검기준 : {item.criteria}
        - 점검예시 : {item.check_examples or '없음'}
        - 조치방법 : {item.remediation_guide or '없음'}

        ## 작성 언어
        {lang}

        ## 출력 규격 (반드시 준수)
        스크립트는 실행 결과를 반드시 아래 JSON 형식으로 표준 출력(stdout)에 출력해야 합니다.
        {{
            "item_code": "{item.item_code}",
            "status": "양호" | "취약",
            "raw_output": "<상세 점검 내용 문자열>"
        }}

        ## 안전 규칙
        - 시스템 설정을 변경하는 코드는 절대 작성 금지 (읽기 전용 점검만)
        - 외부 네트워크 호출 금지
        - 루프는 최대 1,000회 이하
        {examples_block}
        ## 요청
        위 기존 스크립트 예시의 구조·스타일을 반드시 따르되,
        현재 항목({item.item_code})에 맞는 점검 로직을 구현하세요.
        코드만 반환하고 설명·마크다운 코드블록 기호는 제외하세요.
    """).strip()

    return prompt


# ---------------------------------------------------------------------------
# Gemini 호출
# ---------------------------------------------------------------------------
def _parse_retry_delay(exc: Exception) -> float:
    """
    429 응답 본문에서 retry_delay.seconds 값을 파싱.
    파싱 실패 시 기본값(60초) 반환.
    """
    try:
        msg = str(exc)
        # "retry_delay {\n  seconds: 9\n}" 형태 파싱
        m = re.search(r"retry_delay\s*\{[^}]*seconds:\s*(\d+)", msg)
        if m:
            return float(m.group(1)) + 2.0   # 여유 2초 추가
    except Exception:
        pass
    return 60.0   # 파싱 실패 시 안전한 기본값


async def _call_gemini(prompt: str, api_key: str) -> str:
    """
    Gemini 2.0 Flash를 호출하여 스크립트 코드 문자열을 반환.

    - google.genai (신규 SDK) 사용
    - 429 Quota 초과 시 API 응답의 retry_delay를 실제로 대기 후 재시도
    """
    client = genai.Client(api_key=api_key)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info("Gemini 호출 시도 %d/%d", attempt, MAX_RETRIES)
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=GEMINI_MODEL,
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    temperature=0.2,          # 코드 생성은 낮은 온도 권장
                    max_output_tokens=4096,
                ),
            )
            code = response.text.strip()
            # 마크다운 코드블록 제거 (모델이 실수로 붙인 경우 대비)
            code = re.sub(r"^```[\w]*\n?", "", code)
            code = re.sub(r"\n?```$", "", code)
            return code.strip()

        except Exception as exc:
            err_str = str(exc)
            is_quota = "429" in err_str or "RESOURCE_EXHAUSTED" in err_str

            if is_quota:
                wait = _parse_retry_delay(exc)
                logger.warning(
                    "Gemini 호출 실패 (시도 %d/%d) — Quota 초과. %.0f초 대기 후 재시도...",
                    attempt, MAX_RETRIES, wait,
                )
                if attempt == MAX_RETRIES:
                    raise RuntimeError(
                        f"Gemini Quota 초과로 {MAX_RETRIES}회 모두 실패.\n"
                        f"Free Tier 한도가 소진되었습니다. 해결 방법:\n"
                        f"  1) Google AI Studio에서 유료 플랜으로 업그레이드\n"
                        f"  2) 또는 내일(일일 할당량 초기화) 재시도\n"
                        f"  3) 또는 다른 GEMINI_API_KEY 사용"
                    ) from exc
                await asyncio.sleep(wait)
            else:
                logger.warning("Gemini 호출 실패 (시도 %d/%d): %s", attempt, MAX_RETRIES, exc)
                if attempt == MAX_RETRIES:
                    raise RuntimeError(f"Gemini 호출 {MAX_RETRIES}회 모두 실패: {exc}") from exc
                await asyncio.sleep(2 ** attempt)  # 일반 오류는 exponential back-off


# ---------------------------------------------------------------------------
# 검증 (Validation)
# ---------------------------------------------------------------------------
_SAFETY_BLACKLIST = [
    # 파일·설정 변경 금지 패턴
    r"\bos\.remove\b", r"\bshutil\.rmtree\b", r"\bsubprocess\.call\b.*rm\b",
    r"\bSet-ExecutionPolicy\b", r"\bRemove-Item\b", r"\bFormat-Volume\b",
    # 네트워크 호출 금지
    r"\brequests\.get\b", r"\burllib\b", r"\bInvoke-WebRequest\b", r"\bInvoke-RestMethod\b",
]

_REQUIRED_JSON_FIELDS = {"item_code", "status", "raw_output"}


def _validate_script(code: str, os_type: str) -> tuple[bool, str]:
    """
    생성된 코드의 안전성·규격 준수 여부를 검사.

    Returns:
        (is_valid: bool, reason: str)
    """
    # 1. 길이 기본 체크
    if len(code) < 50:
        return False, "코드가 너무 짧습니다 (최소 50자)."

    # 2. 블랙리스트 패턴 검사
    for pattern in _SAFETY_BLACKLIST:
        if re.search(pattern, code, re.IGNORECASE):
            return False, f"안전하지 않은 패턴 감지: {pattern}"

    # 3. JSON 출력 필드 포함 여부 (문자열 기반 휴리스틱)
    for field in _REQUIRED_JSON_FIELDS:
        if field not in code:
            return False, f"필수 출력 필드 누락: '{field}'"

    # 4. Python 문법 검사 (Linux 스크립트)
    if os_type == "Linux":
        try:
            compile(code, "<generated>", "exec")
        except SyntaxError as e:
            return False, f"Python 문법 오류: {e}"

    return True, "OK"


# ---------------------------------------------------------------------------
# MCP 배포
# ---------------------------------------------------------------------------
def _build_file_path(item_code: str, os_type: str) -> str:
    cfg = OS_CONFIG.get(os_type)
    if not cfg:
        raise ValueError(f"지원하지 않는 OS 타입: {os_type}")
    return str(
        PurePosixPath(SCRIPTS_BASE) / cfg["dir"] / f"{item_code}{cfg['ext']}"
    )


def _save_via_mcp(mcp_client: AbstractMCPClient, file_path: str, code: str) -> None:
    """
    MCP write_file 툴을 호출하여 파일을 저장.
    status가 APPROVED인 스크립트만 실제 배포에 사용하세요.
    """
    result = mcp_client.call_tool("write_file", {
        "path": file_path,
        "content": code,
    })
    logger.info("MCP write_file 결과: %s", result)


# ---------------------------------------------------------------------------
# 메인 오케스트레이터
# ---------------------------------------------------------------------------
class ScriptGenerator:
    """
    에이전틱 워크플로우의 메인 오케스트레이터.

    사용 예시:
        generator = ScriptGenerator(
            repository=MyRepository(),
            mcp_client=MyMCPClient(),
            gemini_api_key=os.environ["GEMINI_API_KEY"],
        )
        await generator.generate_missing_scripts()
    """

    def __init__(
        self,
        repository: AbstractRepository,
        mcp_client: AbstractMCPClient,
        gemini_api_key: str,
        auto_deploy: bool = False,   # True 시 승인 없이 즉시 배포 (개발 환경 전용)
    ):
        self.repo            = repository
        self.mcp             = mcp_client
        self.gemini_api_key  = gemini_api_key
        self.auto_deploy     = auto_deploy

    async def generate_missing_scripts(self) -> list[GeneratedScript]:
        """
        스크립트가 없는 가이드라인 항목 전체를 처리하고
        GeneratedScript 목록을 반환합니다.
        """
        items = await self.repo.get_items_without_scripts()
        if not items:
            logger.info("생성이 필요한 신규 항목이 없습니다.")
            return []

        logger.info("신규 항목 %d개 감지됨. 스크립트 생성 시작.", len(items))
        results: list[GeneratedScript] = []

        for item in items:
            try:
                script = await self._process_item(item)
                results.append(script)
            except Exception as exc:
                logger.error("[%s] 처리 실패: %s", item.item_code, exc)

        logger.info("완료: 성공 %d / 전체 %d", len(results), len(items))
        return results

    async def _process_item(self, item: GuidelineItem) -> GeneratedScript:
        logger.info("[%s] 처리 시작 (OS: %s)", item.item_code, item.os_type)

        # Step 1: Few-shot 예시 로드
        examples = await self.repo.get_sample_scripts(item.os_type, limit=2)

        # Step 2: 프롬프트 구성
        prompt = _build_prompt(item, examples)

        # Step 3: Gemini로 코드 생성
        code = await _call_gemini(prompt, self.gemini_api_key)

        # Step 4: 검증
        is_valid, reason = _validate_script(code, item.os_type)
        if not is_valid:
            raise ValueError(f"[{item.item_code}] 검증 실패: {reason}")

        # Step 5: 파일 경로 결정
        file_path = _build_file_path(item.item_code, item.os_type)

        # Step 6: 상태 결정 (Human-in-the-loop vs 즉시 배포)
        status = ScriptStatus.DEPLOYED if self.auto_deploy else ScriptStatus.PENDING_REVIEW

        script = GeneratedScript(
            item_code=item.item_code,
            os_type=item.os_type,
            code=code,
            file_path=file_path,
            status=status,
        )

        # Step 7: DB 등록 (검토 대기 상태로)
        await self.repo.register_script(script)

        # Step 8: 즉시 배포 모드이면 MCP로 파일 저장
        if self.auto_deploy:
            _save_via_mcp(self.mcp, file_path, code)
            logger.info("[%s] 자동 배포 완료 → %s", item.item_code, file_path)
        else:
            logger.info(
                "[%s] 검토 대기 상태로 DB 등록 완료. "
                "Admin UI에서 승인 후 deploy_approved_scripts()를 호출하세요.",
                item.item_code,
            )

        return script

    async def deploy_approved_scripts(self) -> None:
        """
        Admin UI에서 승인(APPROVED)된 스크립트를 MCP를 통해 실제 파일로 배포.
        euni_adapter가 아닌 Admin 승인 이벤트에 의해 호출됩니다.

        실제 구현 시 repository에서 status=APPROVED 항목을 조회하여
        _save_via_mcp() 후 status를 DEPLOYED로 업데이트하세요.
        """
        raise NotImplementedError("repository.get_approved_scripts() 구현 후 연결하세요.")


# ---------------------------------------------------------------------------
# 진입점 (단독 실행 테스트용)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    # ── 간단한 Mock 구현 (실제 DB·MCP 연결 전 로컬 테스트용) ─────────────
    class MockRepository(AbstractRepository):
        async def get_items_without_scripts(self):
            return [
                GuidelineItem(
                    item_code="U-73",
                    os_type="Linux",
                    title="불필요한 서비스 비활성화 여부",
                    criteria="telnet, ftp, rsh 등 불필요한 서비스가 비활성화되어야 한다.",
                    check_examples="systemctl is-enabled telnet",
                    remediation_guide="systemctl disable <service>",
                )
            ]

        async def register_script(self, script: GeneratedScript):
            logger.info("[Mock DB] 등록: %s → %s", script.item_code, script.status)

        async def get_sample_scripts(self, os_type: str, limit: int = 2):
            # 실제로는 DB에서 기존 스크립트 파일 내용을 반환
            return [
                textwrap.dedent("""
                    import subprocess, json
                    result = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True)
                    print(json.dumps({
                        'item_code': 'U-01',
                        'status': '양호' if result.returncode == 0 else '취약',
                        'raw_output': result.stdout[:500]
                    }))
                """).strip()
            ]

    class MockMCPClient(AbstractMCPClient):
        def call_tool(self, tool_name: str, arguments: dict):
            logger.info("[Mock MCP] %s → path=%s", tool_name, arguments.get("path"))
            return {"success": True}

    async def main():
        generator = ScriptGenerator(
            repository=MockRepository(),
            mcp_client=MockMCPClient(),
            gemini_api_key=os.environ.get("GEMINI_API_KEY", "YOUR_KEY_HERE"),
            auto_deploy=False,   # 운영에서는 False 유지 (Human-in-the-loop)
        )
        scripts = await generator.generate_missing_scripts()
        for s in scripts:
            print(f"\n{'='*60}")
            print(f"항목: {s.item_code} | OS: {s.os_type} | 상태: {s.status}")
            print(f"경로: {s.file_path}")
            print(f"코드 미리보기:\n{s.code[:300]}...")

    asyncio.run(main())
