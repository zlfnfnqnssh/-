"""
db_writer.py
------------
판정 결과와 패치 결과를 DB에 저장하고,
이전 스캔 결과와 비교하여 status_change(개선/악화/유지 등)를 결정합니다.

SQLite 기본 사용. 추후 PostgreSQL 등으로 교체 가능하도록
DBWriter 클래스 인터페이스로 추상화되어 있습니다.

사용법:
    writer = DBWriter("./db/results.db")
    writer.init_schema()
    records = writer.save_results(judge_results, patch_results)
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict

from models import JudgeResult, PatchResult, FinalRecord


# ──────────────────────────────────────────────
# 상태 변화 결정 로직
# ──────────────────────────────────────────────

def _determine_status_change(
    current: str, previous: Optional[str]
) -> tuple[str, str]:
    """
    현재 결과와 이전 결과를 비교하여
    (표시할 result, status_change) 를 반환합니다.

    표시 result 규칙:
      - 이전 취약 → 현재 양호: "개선"
      - 나머지: 그대로

    status_change 값:
      - "신규": 이전 결과 없음
      - "유지": 이전과 동일
      - "개선": 취약 → 양호
      - "악화": 양호 → 취약
      - "없음": 해당없음 유지
    """
    if previous is None:
        return current, "신규"

    # "개선" 표시된 이전 결과를 "양호"로 정규화
    prev_norm = "양호" if previous == "개선" else previous

    if prev_norm == "취약" and current == "양호":
        return "개선", "개선"
    if prev_norm == "양호" and current == "취약":
        return current, "악화"
    if current == previous or (prev_norm == current):
        return current, "유지"
    return current, "유지"


# ──────────────────────────────────────────────
# DBWriter
# ──────────────────────────────────────────────

class DBWriter:
    """
    SQLite 기반 결과 저장소.

    테이블:
      - judge_results  : LLM 판정 원본
      - patch_results  : 패치 실행 결과
      - final_records  : 이전 결과 비교 포함 최종 레코드 (웹/리포트 기준)
    """

    def __init__(self, db_path: str = "./db/results.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    # ── 연결 헬퍼 ──
    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row   # dict처럼 접근 가능
        return conn

    # ──────────────────────────────────────────
    # 스키마 초기화
    # ──────────────────────────────────────────

    def init_schema(self):
        """테이블이 없으면 생성합니다. 서버 시작 시 1회 호출."""
        sql = """
        CREATE TABLE IF NOT EXISTS judge_results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      TEXT NOT NULL,
            item_code    TEXT NOT NULL,
            item_name    TEXT,
            guideline_ref TEXT,
            result       TEXT,           -- 취약 / 양호 / 해당없음
            reason       TEXT,
            remediation  TEXT,
            confidence   REAL,
            judged_at    TEXT,
            UNIQUE(scan_id, item_code)
        );

        CREATE TABLE IF NOT EXISTS patch_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         TEXT NOT NULL,
            item_code       TEXT NOT NULL,
            patch_script    TEXT,
            patch_stdout    TEXT,
            patch_stderr    TEXT,
            patch_exit_code INTEGER,
            verify_result   TEXT,        -- JSON: JudgeResult
            attempt         INTEGER,
            patched_at      TEXT,
            patch_success   INTEGER      -- 0 or 1
        );

        CREATE TABLE IF NOT EXISTS final_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         TEXT NOT NULL,
            item_code       TEXT NOT NULL,
            item_name       TEXT,
            result          TEXT,        -- 취약 / 양호 / 해당없음 / 개선
            previous_result TEXT,
            status_change   TEXT,        -- 신규 / 유지 / 개선 / 악화 / 없음
            reason          TEXT,
            remediation     TEXT,
            confidence      REAL,
            patch_attempted INTEGER,     -- 0 or 1
            patch_success   INTEGER,     -- 0 or 1
            scan_date       TEXT,
            guideline_ref   TEXT,
            os_name         TEXT,
            category        TEXT,
            severity        TEXT,
            judge_mode      TEXT,
            collected_json  TEXT,
            UNIQUE(scan_id, item_code)
        );
        """
        with self._conn() as conn:
            conn.executescript(sql)
        # 기존 DB 마이그레이션 (컬럼 누락 시 추가)
        with self._conn() as conn:
            for col, typ in [("os_name","TEXT"),("category","TEXT"),
                              ("severity","TEXT"),("judge_mode","TEXT"),
                              ("collected_json","TEXT")]:
                try:
                    conn.execute(f"ALTER TABLE final_records ADD COLUMN {col} {typ}")
                    conn.commit()
                except Exception:
                    pass
        print(f"[DB] 스키마 초기화 완료: {self.db_path}")

    # ──────────────────────────────────────────
    # 이전 결과 조회
    # ──────────────────────────────────────────

    def get_latest_result(self, item_code: str) -> Optional[str]:
        """
        특정 항목 코드의 가장 최근 final_record result 반환.
        없으면 None.
        """
        sql = """
        SELECT result FROM final_records
        WHERE item_code = ?
        ORDER BY scan_date DESC
        LIMIT 1
        """
        with self._conn() as conn:
            row = conn.execute(sql, (item_code,)).fetchone()
        return row["result"] if row else None

    # ──────────────────────────────────────────
    # 저장
    # ──────────────────────────────────────────

    def _save_judge_results(
        self, conn: sqlite3.Connection, results: List[JudgeResult]
    ):
        sql = """
        INSERT OR REPLACE INTO judge_results
            (scan_id, item_code, item_name, guideline_ref, result,
             reason, remediation, confidence, judged_at)
        VALUES
            (:scan_id, :item_code, :item_name, :guideline_ref, :result,
             :reason, :remediation, :confidence, :judged_at)
        """
        conn.executemany(sql, [r.to_dict() for r in results])

    def _save_patch_results(
        self, conn: sqlite3.Connection, results: List[PatchResult]
    ):
        sql = """
        INSERT INTO patch_results
            (scan_id, item_code, patch_script, patch_stdout, patch_stderr,
             patch_exit_code, verify_result, attempt, patched_at, patch_success)
        VALUES
            (:scan_id, :item_code, :patch_script, :patch_stdout, :patch_stderr,
             :patch_exit_code, :verify_result, :attempt, :patched_at, :patch_success)
        """
        rows = []
        for r in results:
            d = r.to_dict()
            verify_json = json.dumps(d.get("verify_result") or {}, ensure_ascii=False)
            success = (
                1
                if r.verify_result and r.verify_result.result == "양호"
                else 0
            )
            rows.append({
                "scan_id": r.scan_id,
                "item_code": r.item_code,
                "patch_script": r.patch_script,
                "patch_stdout": r.patch_stdout,
                "patch_stderr": r.patch_stderr,
                "patch_exit_code": r.patch_exit_code,
                "verify_result": verify_json,
                "attempt": r.attempt,
                "patched_at": r.patched_at,
                "patch_success": success,
            })
        conn.executemany(sql, rows)

    def _save_final_records(
        self,
        conn: sqlite3.Connection,
        judge_results: List[JudgeResult],
        patch_map: Dict[str, PatchResult],
    ) -> List[FinalRecord]:
        """
        judge_results + patch_map 을 합쳐 final_records 저장.
        이전 결과와 비교 후 FinalRecord 목록 반환.
        """
        records = []
        for jr in judge_results:
            previous = self.get_latest_result(jr.item_code)
            
            # 패치가 성공했으면 최종 결과를 "양호"로 덮어씀
            patch = patch_map.get(jr.item_code)
            current_result = jr.result
            if patch and patch.verify_result and patch.verify_result.result == "양호":
                current_result = "양호"

            display_result, status_change = _determine_status_change(
                current_result, previous
            )

            patch_attempted = patch is not None
            patch_success = (
                patch is not None
                and patch.verify_result is not None
                and patch.verify_result.result == "양호"
            )

            record = FinalRecord(
                scan_id=jr.scan_id,
                item_code=jr.item_code,
                item_name=jr.item_name,
                result=display_result,
                previous_result=previous,
                status_change=status_change,
                reason=jr.reason,
                remediation=jr.remediation,
                confidence=jr.confidence,
                patch_attempted=patch_attempted,
                patch_success=patch_success,
                scan_date=jr.judged_at,
                guideline_ref=jr.guideline_ref,
                os_name=getattr(jr, "os_name", ""),
                category=getattr(jr, "category", ""),
                severity=getattr(jr, "severity", ""),
                judge_mode=getattr(jr, "judge_mode", "hybrid"),
                collected_json=getattr(jr, "collected_json", ""),
            )
            records.append(record)

        sql = """
        INSERT OR REPLACE INTO final_records
            (scan_id, item_code, item_name, result, previous_result,
             status_change, reason, remediation, confidence,
             patch_attempted, patch_success, scan_date, guideline_ref,
             os_name, category, severity, judge_mode, collected_json)
        VALUES
            (:scan_id, :item_code, :item_name, :result, :previous_result,
             :status_change, :reason, :remediation, :confidence,
             :patch_attempted, :patch_success, :scan_date, :guideline_ref,
             :os_name, :category, :severity, :judge_mode, :collected_json)
        """
        conn.executemany(
            sql,
            [
                {**r.to_dict(), "patch_attempted": int(r.patch_attempted),
                 "patch_success": int(r.patch_success)}
                for r in records
            ],
        )
        return records

    # ──────────────────────────────────────────
    # 메인 저장 메서드
    # ──────────────────────────────────────────

    def save_results(
        self,
        judge_results: List[JudgeResult],
        patch_results: Optional[List[PatchResult]] = None,
    ) -> List[FinalRecord]:
        """
        판정 결과와 패치 결과를 DB에 저장하고 FinalRecord 목록을 반환합니다.
        웹 서버나 리포트 생성 모듈은 이 반환값을 사용하면 됩니다.

        Parameters
        ----------
        judge_results : List[JudgeResult]
        patch_results : List[PatchResult] | None

        Returns
        -------
        List[FinalRecord]
        """
        patch_map: Dict[str, PatchResult] = {}
        if patch_results:
            patch_map = {r.item_code: r for r in patch_results}

        with self._conn() as conn:
            self._save_judge_results(conn, judge_results)
            if patch_results:
                self._save_patch_results(conn, patch_results)
            records = self._save_final_records(conn, judge_results, patch_map)
            conn.commit()

        print(f"[DB] 저장 완료: {len(records)}건")
        for r in records:
            change_icon = {
                "신규": "🆕", "유지": "→", "개선": "✅", "악화": "⚠️", "없음": "-"
            }.get(r.status_change, "")
            print(f"     {r.item_code}: {r.result} {change_icon} (이전: {r.previous_result})")
        return records

    # ──────────────────────────────────────────
    # 조회 메서드 (웹 서버에서 사용)
    # ──────────────────────────────────────────

    def get_final_records_by_scan(self, scan_id: str) -> List[dict]:
        """scan_id 기준 최종 레코드 전체 조회"""
        sql = "SELECT * FROM final_records WHERE scan_id = ? ORDER BY item_code"
        with self._conn() as conn:
            rows = conn.execute(sql, (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_all_scans(self) -> List[dict]:
        """전체 scan_id 목록과 항목 수 조회"""
        sql = """
        SELECT scan_id, scan_date, COUNT(*) as item_count,
               SUM(CASE WHEN result IN ('취약') THEN 1 ELSE 0 END) as vuln_count,
               SUM(CASE WHEN result IN ('양호','개선') THEN 1 ELSE 0 END) as ok_count
        FROM final_records
        GROUP BY scan_id
        ORDER BY scan_date DESC
        """
        with self._conn() as conn:
            rows = conn.execute(sql).fetchall()
        return [dict(r) for r in rows]
