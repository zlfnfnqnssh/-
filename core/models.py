"""
models.py — 공통 데이터 모델
타팀 통합 시 이 파일 구조를 기준으로 맞춰주세요.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Literal
from datetime import datetime
import json


# ──────────────────────────────────────────────
# 스크립트 실행 결과
# ──────────────────────────────────────────────

@dataclass
class SubCheckResult:
    sub_check: str
    config_file: str
    collected_value: str
    raw_output: str
    service_status: str
    source_command: str


@dataclass
class CheckItem:
    category: str
    item_code: str
    item_name: str
    check_results: List[SubCheckResult] = field(default_factory=list)


@dataclass
class ScanResult:
    scan_id: str
    scan_date: str
    target_os: str
    os_name: str
    items: List[CheckItem] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict, max_raw_lines: int = 5) -> "ScanResult":
        items = []
        for it in d.get("items", []):
            sub_results = []
            for sr in it.get("check_results", []):
                # raw_output을 max_raw_lines 줄로 제한 (토큰 절약)
                raw = sr.get("raw_output", "")
                lines = [l for l in raw.splitlines() if l.strip() and not l.strip().startswith("#")]
                if len(lines) > max_raw_lines:
                    lines = lines[:max_raw_lines] + [f"...(+{len(raw.splitlines())-max_raw_lines}줄 생략)"]
                sr = dict(sr)
                sr["raw_output"] = "\n".join(lines)
                sub_results.append(SubCheckResult(**sr))
            items.append(CheckItem(
                category=it["category"],
                item_code=it["item_code"],
                item_name=it["item_name"],
                check_results=sub_results,
            ))
        return cls(
            scan_id=d["scan_id"],
            scan_date=d["scan_date"],
            target_os=d["target_os"],
            os_name=d["os_name"],
            items=items,
        )

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────
# LLM 판정 결과
# ──────────────────────────────────────────────

@dataclass
class JudgeResult:
    scan_id: str
    item_code: str
    item_name: str
    guideline_ref: str
    result: Literal["취약", "양호", "해당없음"]
    reason: str
    remediation: str
    confidence: float
    os_name: str = ""
    category: str = ""
    severity: str = ""
    judge_mode: str = "hybrid"
    judged_at: str = field(default_factory=lambda: datetime.now().isoformat())
    collected_json: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────
# 패치 스크립트 (실행 전 — 웹 버튼 단위)
# ──────────────────────────────────────────────

@dataclass
class PatchScript:
    """
    LLM이 생성한 패치 스크립트 1건.
    웹 UI에서 항목별로 버튼을 눌러 개별 실행합니다.
    DB의 patch_scripts 테이블과 매핑됩니다.

    status 값:
      ready      — 생성됨, 실행 대기 중
      running    — 현재 실행 중
      success    — 실행 성공 + 재점검 양호 확인
      failed     — 실행 실패 또는 재점검도 취약
      rewriting  — LLM이 스크립트 재작성 중
    """
    patch_id: str                    # 웹 버튼 식별자 (UUID)
    scan_id: str
    item_code: str
    item_name: str
    script_content: str              # bash 스크립트 전체 내용
    description: str                 # 이 패치가 무엇을 하는지 한 줄 요약
    status: str = "ready"
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────
# 패치 실행 결과 (실행 후)
# ──────────────────────────────────────────────

@dataclass
class PatchResult:
    """패치 스크립트 1회 실행 결과"""
    patch_id: str                    # PatchScript.patch_id 와 연결
    scan_id: str
    item_code: str
    patch_script: str
    patch_stdout: str
    patch_stderr: str
    patch_exit_code: int
    verify_result: Optional["JudgeResult"] = None
    attempt: int = 1
    patched_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.verify_result:
            d["verify_result"] = self.verify_result.to_dict()
        return d


# ──────────────────────────────────────────────
# DB 저장용 최종 레코드
# ──────────────────────────────────────────────

@dataclass
class FinalRecord:
    """
    이전 결과 비교 포함 최종 레코드.
    result 값:
      취약 / 양호 / 해당없음 / 개선 (이전 취약 → 현재 양호)
    status_change 값:
      신규 / 유지 / 개선 / 악화 / 없음
    """
    scan_id: str
    item_code: str
    item_name: str
    result: str
    previous_result: Optional[str]
    status_change: str
    reason: str
    remediation: str
    confidence: float
    patch_attempted: bool
    patch_success: bool
    scan_date: str
    guideline_ref: str
    os_name: str = ""
    category: str = ""
    severity: str = ""
    judge_mode: str = "hybrid"
    collected_json: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
