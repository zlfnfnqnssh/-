"""
debug_prompt.py
---------------
LLM 호출 없이 실제 프롬프트만 출력하는 디버그 스크립트.
u01_result_*.json 파일을 읽어서 프롬프트를 확인합니다.

파일 검색 순서:
  1. 현재 디렉토리 (u01_result_*.json)
  2. /tmp/scan_results/ (runner 가 저장하는 기본 위치)
"""

import json
import glob
import os
import sys
from schemas import JudgePayload, CheckSubResult as CheckResult
from batch_judge import debug_print_prompt, debug_print_batch_prompt

FALLBACK_DIR = "/tmp/scan_results"


def _find_files(pattern: str) -> list[str]:
    """현재 디렉토리 → /tmp/scan_results 순으로 파일 검색."""
    local = sorted(glob.glob(pattern))
    if local:
        return local
    remote = sorted(glob.glob(os.path.join(FALLBACK_DIR, pattern)))
    return remote


def _raw_checks(data: dict) -> list[dict]:
    """flat(sub_checks) / nested(items[].check_results) 양쪽 포맷 지원."""
    # flat 포맷: sub_checks 키
    if "sub_checks" in data:
        return data["sub_checks"]
    # nested 포맷: items[0].check_results
    items = data.get("items", [])
    if items:
        return items[0].get("check_results", [])
    return []


def _item_meta(data: dict) -> dict:
    """flat / nested 포맷 모두에서 item_code / item_name / category 추출."""
    if "item_code" in data:
        return {
            "item_code": data.get("item_code", ""),
            "item_name": data.get("item_name", ""),
            "category":  data.get("category", ""),
        }
    items = data.get("items", [{}])
    it = items[0] if items else {}
    return {
        "item_code": it.get("item_code", ""),
        "item_name": it.get("item_name", ""),
        "category":  it.get("category", ""),
    }


def load_result_file(filepath: str) -> JudgePayload:
    """스캔 결과 JSON 파일 → JudgePayload 변환 (flat/nested 양 포맷 지원)."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    meta   = _item_meta(data)
    checks = []
    for c in _raw_checks(data):
        checks.append(CheckResult(
            sub_check       = c.get("sub_check", ""),
            config_file     = c.get("config_file", ""),
            collected_value = c.get("collected_value", ""),
            raw_output      = c.get("raw_output", ""),
            service_status  = c.get("service_status", "N/A"),
            source_command  = c.get("source_command", ""),
        ))

    return JudgePayload(
        scan_id       = data.get("scan_id", "debug"),
        item_code     = meta["item_code"],
        item_name     = meta["item_name"],
        os_name       = data.get("os_name", "Ubuntu/Debian"),
        category      = meta["category"],
        check_results = checks,
    )


if __name__ == "__main__":
    # ── 사용법 ──────────────────────────────────────────────
    # 단일 항목:  python3 debug_prompt.py u01
    # 배치 출력:  python3 debug_prompt.py batch u01 u02 u03
    # raw 포함:   python3 debug_prompt.py raw u01
    # 전체 항목:  python3 debug_prompt.py all
    # ────────────────────────────────────────────────────────

    args = sys.argv[1:]

    if not args:
        print("사용법:")
        print("  단일 항목:  python3 debug_prompt.py u01")
        print("  raw 포함:   python3 debug_prompt.py raw u01")
        print("  배치 출력:  python3 debug_prompt.py batch u01 u02 u03")
        print("  전체 항목:  python3 debug_prompt.py all")
        sys.exit(0)

    mode = args[0].lower()

    # ── 전체 항목 출력 ──────────────────────────────────────
    if mode == "all":
        files = _find_files("u*_result_*.json")
        if not files:
            print(f"[오류] u*_result_*.json 파일을 찾을 수 없습니다. (현재 디렉토리 및 {FALLBACK_DIR})")
            sys.exit(1)
        print(f"총 {len(files)}개 항목 프롬프트 출력\n")
        for fp in files:
            try:
                payload = load_result_file(fp)
                debug_print_prompt(payload, include_raw=False)
                print()
            except Exception as e:
                print(f"[오류] {fp}: {e}")
        sys.exit(0)

    # ── 배치 출력 ────────────────────────────────────────────
    if mode == "batch":
        targets = args[1:]
        if not targets:
            print("[오류] 배치 대상 항목을 지정하세요. 예: python3 debug_prompt.py batch u01 u02")
            sys.exit(1)
        payloads = []
        for t in targets:
            files = _find_files(f"{t}_result_*.json")
            if not files:
                print(f"[경고] {t}_result_*.json 파일 없음, 건너뜀")
                continue
            try:
                payloads.append(load_result_file(sorted(files)[-1]))
            except Exception as e:
                print(f"[오류] {t}: {e}")
        if payloads:
            debug_print_batch_prompt(payloads)
        sys.exit(0)

    # ── raw 포함 단일 출력 ───────────────────────────────────
    if mode == "raw":
        targets = args[1:]
        if not targets:
            print("[오류] 항목을 지정하세요. 예: python3 debug_prompt.py raw u01")
            sys.exit(1)
        for t in targets:
            files = _find_files(f"{t}_result_*.json")
            if not files:
                print(f"[경고] {t}_result_*.json 파일 없음")
                continue
            try:
                payload = load_result_file(sorted(files)[-1])
                debug_print_prompt(payload, include_raw=True)
            except Exception as e:
                print(f"[오류] {t}: {e}")
        sys.exit(0)

    # ── 단일 항목 출력 ───────────────────────────────────────
    for target in args:
        files = _find_files(f"{target}_result_*.json")
        if not files:
            print(f"[경고] {target}_result_*.json 파일을 찾을 수 없습니다. (현재 디렉토리 및 {FALLBACK_DIR})")
            continue
        try:
            payload = load_result_file(sorted(files)[-1])
            debug_print_prompt(payload, include_raw=False)
        except Exception as e:
            print(f"[오류] {target}: {e}")
