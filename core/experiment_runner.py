"""
experiment_runner.py
--------------------
논문 실험용: 동일한 스캔 결과를 3가지 판정 모드로 실행하여 비교합니다.

모드:
  hybrid    : 규칙×0.6 + LLM×0.4  (기본, 배치 LLM)
  rule_only : 규칙 점수만 (LLM 호출 없음)
  llm_only  : LLM 점수만 (배치 LLM, 규칙 무시)

사용법:
  python3 core/experiment_runner.py --json-dir /tmp/scan_results --modes all
  python3 core/experiment_runner.py --json-dir /tmp/scan_results --modes rule_only hybrid

출력:
  results/experiment_{timestamp}/
    ├── hybrid_results.json
    ├── rule_only_results.json
    ├── llm_only_results.json
    └── comparison.csv       ← 3모드 결과 비교표
"""

import argparse
import asyncio
import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

from collector import Collector
from batch_judge import BatchJudge
from models import JudgeResult

OUTPUT_BASE = Path("./results/experiments")


async def _run_mode(
    payloads, mode: str, api_key: Optional[str]
) -> list[JudgeResult]:
    print(f"\n{'='*50}")
    print(f"[실험] 모드: {mode.upper()}")
    print(f"{'='*50}")
    return await BatchJudge.run(payloads, api_key=api_key, mode=mode)


def _save_mode_result(results: list[JudgeResult], out_dir: Path, mode: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    data = [
        {
            "item_code": r.item_code,
            "item_name": r.item_name,
            "result": r.result,
            "confidence": r.confidence,
            "reason": r.reason,
            "remediation": r.remediation,
        }
        for r in results
    ]
    path = out_dir / f"{mode}_results.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[저장] {path}")
    return data


def _save_comparison(all_results: dict[str, list[dict]], out_dir: Path):
    """모드별 결과를 항목 단위로 비교하는 CSV 생성."""
    out_dir.mkdir(parents=True, exist_ok=True)
    modes = list(all_results.keys())

    # item_code → {mode: result} 매핑
    by_code: dict[str, dict] = {}
    for mode, results in all_results.items():
        for r in results:
            code = r["item_code"]
            if code not in by_code:
                by_code[code] = {"item_name": r["item_name"]}
            by_code[code][f"{mode}_result"]     = r["result"]
            by_code[code][f"{mode}_confidence"] = r["confidence"]

    # 모드 간 불일치 여부 표시
    for code, row in by_code.items():
        results_vals = [row.get(f"{m}_result") for m in modes if f"{m}_result" in row]
        row["agreement"] = "일치" if len(set(results_vals)) == 1 else "불일치"

    csv_path = out_dir / "comparison.csv"
    fieldnames = ["item_code", "item_name"]
    for mode in modes:
        fieldnames += [f"{mode}_result", f"{mode}_confidence"]
    fieldnames.append("agreement")

    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for code in sorted(by_code.keys()):
            writer.writerow({"item_code": code, **by_code[code]})

    print(f"[저장] 비교표: {csv_path}")
    _print_stats(all_results, by_code, modes)


def _print_stats(
    all_results: dict[str, list[dict]],
    by_code: dict[str, dict],
    modes: list[str],
):
    print("\n[실험 결과 요약]")
    print(f"{'모드':<12} {'취약':>6} {'양호':>6} {'해당없음':>8}")
    print("-" * 36)
    for mode in modes:
        res = all_results[mode]
        v = sum(1 for r in res if r["result"] == "취약")
        o = sum(1 for r in res if r["result"] == "양호")
        n = sum(1 for r in res if r["result"] == "해당없음")
        print(f"{mode:<12} {v:>6} {o:>6} {n:>8}")

    disagree = [c for c, row in by_code.items() if row.get("agreement") == "불일치"]
    if disagree:
        print(f"\n[불일치 항목 {len(disagree)}개]: {', '.join(sorted(disagree))}")


async def _main_async(args):
    # JSON 파일 수집
    json_dir = Path(args.json_dir)
    if not json_dir.exists():
        sys.exit(f"디렉토리 없음: {json_dir}")

    # 같은 항목의 가장 최신 JSON만 사용
    latest: dict[str, Path] = {}
    for p in json_dir.glob("u*_result_*.json"):
        stem = p.stem.split("_result_")[0]  # "u01"
        if stem not in latest or p.stat().st_mtime > latest[stem].stat().st_mtime:
            latest[stem] = p

    json_paths = sorted(latest.values(), key=lambda p: p.name)
    if not json_paths:
        sys.exit(f"JSON 결과 파일 없음: {json_dir}")

    print(f"[실험] JSON 파일 {len(json_paths)}개 로드")
    payloads = Collector.from_json_files([str(p) for p in json_paths])
    print(f"[실험] 페이로드 {len(payloads)}개 준비")

    modes = ["hybrid", "rule_only", "llm_only"] if args.modes == ["all"] else args.modes
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = OUTPUT_BASE / f"exp_{ts}"

    all_results: dict[str, list[dict]] = {}
    for mode in modes:
        results = await _run_mode(payloads, mode, api_key)
        all_results[mode] = _save_mode_result(results, out_dir, mode)

    if len(all_results) > 1:
        _save_comparison(all_results, out_dir)

    print(f"\n[완료] 결과 저장 경로: {out_dir}")


def main():
    parser = argparse.ArgumentParser(description="논문 실험: 3가지 판정 모드 비교")
    parser.add_argument(
        "--json-dir", default="/tmp/scan_results",
        help="스캔 결과 JSON 폴더 (기본: /tmp/scan_results)"
    )
    parser.add_argument(
        "--modes", nargs="+", default=["all"],
        choices=["all", "hybrid", "rule_only", "llm_only"],
        help="실행할 모드 (기본: all)"
    )
    args = parser.parse_args()
    asyncio.run(_main_async(args))


if __name__ == "__main__":
    main()
