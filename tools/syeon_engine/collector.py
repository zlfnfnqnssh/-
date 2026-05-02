"""
collector.py
------------
runner.py 가 반환한 ScanResult 목록을 LLM 판정용 JudgePayload로 변환합니다.

토큰 절약 설계:
  - raw_output: 핵심 줄만 15줄로 제한 (전체 파일 내용 제외)
  - 판정에 불필요한 주석 줄 제거
  - collected_value(grep 결과)를 우선 사용
"""

import json
import os
import re
from typing import List, Dict, Any
from models import ScanResult, CheckItem, SubCheckResult


# raw_output 최대 줄 수 (토큰 절약: batch_judge는 collected_value만 쓰므로 5면 충분)
RAW_OUTPUT_MAX_LINES = int(os.getenv("RAW_OUTPUT_MAX_LINES", "5"))


class JudgePayload:
    """LLM 판정 1회 요청 단위 (item_code 1건)"""

    def __init__(self, scan_id: str, os_name: str, item: CheckItem):
        self.scan_id     = scan_id
        self.os_name     = os_name
        self.item_code   = item.item_code
        self.item_name   = item.item_name
        self.category    = item.category
        self.check_results = item.check_results

    def to_prompt_context(self) -> str:
        """
        LLM 프롬프트에 삽입할 점검 결과 텍스트.
        토큰을 최소화하기 위해:
          1. raw_output에서 주석(#으로 시작)·빈 줄 제거 후 15줄만 사용
          2. collected_value(grep 결과)를 먼저 표시
        """
        lines = [
            f"OS: {self.os_name}",
            f"항목: {self.item_code} - {self.item_name}",
            "=== 점검 결과 ===",
        ]

        for idx, sub in enumerate(self.check_results, 1):
            lines.append(f"[{idx}] {sub.sub_check}")
            lines.append(f"  파일: {sub.config_file}")
            lines.append(f"  수집값: {sub.collected_value}")
            lines.append(f"  서비스: {sub.service_status}")

            # raw_output: 주석·빈줄 제거 후 핵심 줄만
            raw_lines = sub.raw_output.splitlines()
            # 주석(#으로 시작)·공백 줄 제거
            meaningful = [
                l for l in raw_lines
                if l.strip() and not l.strip().startswith("#")
            ]
            # 그래도 너무 많으면 자르기
            if len(meaningful) > RAW_OUTPUT_MAX_LINES:
                meaningful = meaningful[:RAW_OUTPUT_MAX_LINES]
                meaningful.append(f"  ... (생략)")

            if meaningful:
                lines.append("  파일내용(핵심):")
                lines.extend(f"    {l}" for l in meaningful)

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "os_name": self.os_name,
            "item_code": self.item_code,
            "item_name": self.item_name,
            "category": self.category,
            "prompt_context": self.to_prompt_context(),
        }


class Collector:
    @staticmethod
    def prepare(scan_results: List[ScanResult]) -> List[JudgePayload]:
        payloads = []
        for scan in scan_results:
            for item in scan.items:
                payloads.append(
                    JudgePayload(scan_id=scan.scan_id, os_name=scan.os_name, item=item)
                )
        return payloads

    @staticmethod
    def from_json_files(json_paths: List[str]) -> List[JudgePayload]:
        results = []
        for path in json_paths:
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                results.append(ScanResult.from_dict(data))
            except Exception as e:
                print(f"[Collector] JSON 로드 실패: {path} → {e}")
        return Collector.prepare(results)
