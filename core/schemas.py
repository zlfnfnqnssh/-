from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime
import uuid


@dataclass
class CheckSubResult:
    sub_check:       str
    config_file:     str
    collected_value: str
    raw_output:      str
    service_status:  str
    source_command:  str


@dataclass
class JudgePayload:
    scan_id:       str
    item_code:     str
    item_name:     str
    check_results: List[CheckSubResult]
    os_name:       str = "Linux"
    category:      str = ""

    def to_prompt_context(self, max_raw_lines: int = 12) -> str:
        lines = [f"[{self.item_code}] {self.item_name}"]
        for c in self.check_results:
            lines.append(
                f"  • {c.sub_check} | {c.config_file} | "
                f"수집값={c.collected_value} | 서비스={c.service_status}"
            )
            raw_core = [
                l for l in c.raw_output.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ][:max_raw_lines]
            if raw_core:
                lines.append("    파일내용: " + " / ".join(raw_core[:5]))
        return "\n".join(lines)


@dataclass
class JudgeResult:
    scan_id:       str
    item_code:     str
    item_name:     str
    guideline_ref: str
    result:        str
    reason:        str
    remediation:   str
    confidence:    float
    judged_at:     str     = field(default_factory=lambda: datetime.now().isoformat())
    os_name:       str     = ""
    category:      str     = ""
    severity:      str     = ""
    judge_mode:    str     = "hybrid"
    collected_json: str    = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PatchScript:
    patch_id:       str
    scan_id:        str
    item_code:      str
    item_name:      str
    script_content: str
    description:    str
    status:         str  = "ready"
    rollback_script_content: str = ""
    generated_at:   str  = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class JudgeAndPatchResult:
    scan_id:       str
    item_code:     str
    item_name:     str
    guideline_ref: str
    result:        str
    reason:        str
    attack_vector: str
    remediation:   str
    confidence:    float
    rule_score:    int  = 0
    llm_score:     int  = -1
    final_score:   int  = 0
    patch_script_content:    str  = ""
    rollback_script_content: str  = ""
    patch_id:     str  = field(default_factory=lambda: str(uuid.uuid4()))
    judged_at:    str  = field(default_factory=lambda: datetime.now().isoformat())
    llm_called:   bool = False
    batch_judged: bool = False

    def to_judge_result(self) -> JudgeResult:
        return JudgeResult(
            scan_id=self.scan_id, item_code=self.item_code,
            item_name=self.item_name, guideline_ref=self.guideline_ref,
            result=self.result, reason=self.reason,
            remediation=self.remediation, confidence=self.confidence,
        )

    def to_patch_script(self) -> Optional[PatchScript]:
        if self.result != "취약" or not self.patch_script_content:
            return None
        ps = PatchScript(
            patch_id=self.patch_id, scan_id=self.scan_id,
            item_code=self.item_code, item_name=self.item_name,
            script_content=self.patch_script_content,
            description=self.remediation[:200], status="ready",
            rollback_script_content=self.rollback_script_content,
        )
        return ps

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "JudgeAndPatchResult":
        valid = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        valid.pop("judged_at", None)
        return cls(**valid)


@dataclass
class FinalRecord:
    scan_id:         str
    item_code:       str
    item_name:       str
    result:          str
    previous_result: Optional[str]
    status_change:   str
    reason:          str
    remediation:     str
    confidence:      float
    patch_attempted: bool
    patch_success:   bool
    scan_date:       str
    guideline_ref:   str

    def to_dict(self) -> dict:
        return asdict(self)
