"""
main.py
-------
전체 점검 파이프라인 진입점.

환경변수:
    GEMINI_API_KEY        Gemini API 키 (AIzaSy... 형태)
    GEMINI_MODEL          모델 (기본: gemini-2.5-flash-preview-04-17)
    SCRIPTS_BASE          점검 스크립트 루트 (기본: ./scripts)
    DB_PATH               결과 DB 경로 (기본: ./db/results.db)
    GUIDELINE_DB_PATH     주통기 가이드라인 DB (기본: ./db/guidelines.db)
    OUTPUT_DIR            스크립트 JSON 임시 저장 (기본: /tmp/scan_results)
    GEMINI_REQUEST_DELAY  요청 간 딜레이 초 (기본: 6)
    GEMINI_RETRY_DELAY    429 재시도 대기 초 (기본: 65)

CLI:
    python main.py --password <sudo_pw>               # 전체 점검
    python main.py --password <sudo_pw> --items U-01  # 특정 항목만
    python main.py --password <sudo_pw> --patch       # 패치 스크립트도 생성
    python main.py --password <sudo_pw> --output result.json
"""

import asyncio
import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).parent / "core"))

from runner import ScriptRunner
from collector import Collector
from batch_judge import BatchJudge          # ← JudgeAndPatcher 대체
from db_writer import DBWriter
from models import FinalRecord


SCRIPTS_BASE = os.getenv("SCRIPTS_BASE", "./scripts")
DB_PATH      = os.getenv("DB_PATH", "./db/results.db")
OUTPUT_DIR   = os.getenv("OUTPUT_DIR", "/tmp/scan_results")
API_KEY      = os.getenv("GEMINI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")


async def run_pipeline(
    sudo_password: str,
    item_codes: Optional[List[str]] = None,
    generate_patch: bool = False,
) -> List[FinalRecord]:
    """
    전체 점검 파이프라인.
    반환: FinalRecord 목록 (웹 서버 / 리포트에 전달)
    """
    print("=" * 60)
    print("  주통기 취약점 점검 시작")
    print("=" * 60)

    # ── STEP 1: 점검 스크립트 실행 ──
    print("\n[STEP 1] 점검 스크립트 실행")
    runner = ScriptRunner(
        scripts_base=SCRIPTS_BASE,
        sudo_password=sudo_password,
        output_dir=OUTPUT_DIR,
    )
    scan_results = runner.run_items(item_codes) if item_codes else runner.run_all()

    if not scan_results:
        print("  점검 결과 없음. 종료합니다.")
        return []

    # ── STEP 2: 결과 수집 ──
    print("\n[STEP 2] 결과 수집 및 정규화")
    payloads = Collector.prepare(scan_results)
    print(f"  수집된 항목: {len(payloads)}건")

    # ── STEP 3: 판정 (규칙 → 배치 LLM) ──
    # COMPACT_OUTPUT=1 로 설정하여 스크립트 raw_output 제거 (토큰 절약)
    os.environ["COMPACT_OUTPUT"] = "1"
    judge_mode = os.getenv("JUDGE_MODE", "hybrid")   # hybrid / rule_only / llm_only
    print(f"\n[STEP 3] 판정 (mode={judge_mode})")
    judge_results = await BatchJudge.run(payloads, api_key=API_KEY, mode=judge_mode)

    # ── STEP 4: DB 저장 ──
    print("\n[STEP 4] DB 저장")
    db = DBWriter(DB_PATH)
    db.init_schema()
    final_records = db.save_results(judge_results)

    # ── 결과 요약 ──
    print("\n" + "=" * 60)
    print("  점검 완료 요약")
    print("=" * 60)
    vuln     = [r for r in final_records if r.result == "취약"]
    ok       = [r for r in final_records if r.result in ("양호", "개선")]
    improved = [r for r in final_records if r.status_change == "개선"]
    worsened = [r for r in final_records if r.status_change == "악화"]

    print(f"  전체: {len(final_records)}건")
    print(f"  취약: {len(vuln)}건  /  양호: {len(ok)}건")
    if improved:
        print(f"  개선: {[r.item_code for r in improved]}")
    if worsened:
        print(f"  악화: {[r.item_code for r in worsened]}")
    print("=" * 60)

    return final_records


# 웹 서버 연동 함수
def get_scan_records(scan_id: str) -> List[dict]:
    """웹 서버: scan_id 결과 조회 → FinalRecord dict 목록"""
    return DBWriter(DB_PATH).get_final_records_by_scan(scan_id)


def get_all_scans() -> List[dict]:
    """웹 서버: 전체 스캔 이력 조회"""
    return DBWriter(DB_PATH).get_all_scans()


# CLI
def _parse_args():
    parser = argparse.ArgumentParser(description="주통기 취약점 점검")
    parser.add_argument("--password", "-p", default=None, help="sudo 비밀번호")
    parser.add_argument("--items", "-i", nargs="+", default=None,
                        help="점검 항목 (예: U-01 U-02). 미입력 시 전체")
    parser.add_argument("--patch", action="store_true",
                        help="(기본 동작과 동일, 항상 패치 스크립트 생성됨)")
    parser.add_argument("--output", "-o", default=None, help="결과 JSON 저장 경로")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if not API_KEY:
        print("[오류] GEMINI_API_KEY 환경변수를 설정하세요.")
        print("  export GEMINI_API_KEY='AIzaSy...'")
        sys.exit(1)

    password = args.password or getpass.getpass("sudo 비밀번호: ")

    records = asyncio.run(run_pipeline(
        sudo_password=password,
        item_codes=args.items,
        generate_patch=True,
    ))

    if args.output and records:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in records], f, ensure_ascii=False, indent=2)
        print(f"\n결과 저장됨: {args.output}")
