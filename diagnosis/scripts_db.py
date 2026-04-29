from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Iterable

import psycopg
from psycopg.rows import dict_row

# ── 기본 DSN (환경변수로 오버라이드 가능) ─────────────────────────
DEFAULT_DSN = "postgresql://admin:admin123@localhost:5432/jtk_db"

# ── DDL ───────────────────────────────────────────────────────────

SESSION_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS diagnosis_sessions (
    session_id      TEXT PRIMARY KEY,
    os_type         TEXT        NOT NULL,               -- windows / linux
    prefix          TEXT        NOT NULL DEFAULT '',    -- PC, W, U 등 (전체면 빈 문자열)
    category        TEXT        NOT NULL DEFAULT '',    -- 계정 관리 등 필터 시
    total           INTEGER     NOT NULL DEFAULT 0,
    ok_count        INTEGER     NOT NULL DEFAULT 0,
    vuln_count      INTEGER     NOT NULL DEFAULT 0,
    unknown_count   INTEGER     NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at     TIMESTAMPTZ,
    memo            TEXT        NOT NULL DEFAULT ''     -- 4월 정기점검 등
);
"""

RESULTS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS diagnosis_results (
    id              BIGSERIAL   PRIMARY KEY,
    code            TEXT        NOT NULL UNIQUE,        -- PC-01 기준 최신 1개 유지
    session_id      TEXT        NOT NULL,
    os_type         TEXT        NOT NULL,
    result_1st      TEXT        NOT NULL,               -- 양호 / 취약 / 규칙불가
    result_2nd      TEXT,                               -- LLM 2차 판정
    collected_value TEXT        NOT NULL DEFAULT '',
    raw_output      TEXT        NOT NULL DEFAULT '',
    llm_reason      TEXT,                               -- LLM 판정 근거
    llm_action      TEXT,                               -- LLM 조치 방법
    llm_prompt      TEXT,                               -- 디버깅용 프롬프트
    diagnosed_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_dr_session ON diagnosis_results (session_id);
CREATE INDEX IF NOT EXISTS ix_dr_result1 ON diagnosis_results (result_1st);
"""

HISTORY_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS diagnosis_results_history (
    id              BIGSERIAL   PRIMARY KEY,
    session_id      TEXT        NOT NULL,               -- 진단 세션 묶음
    code            TEXT        NOT NULL,
    os_type         TEXT        NOT NULL,
    result_1st      TEXT        NOT NULL,
    result_2nd      TEXT,
    collected_value TEXT        NOT NULL DEFAULT '',
    raw_output      TEXT        NOT NULL DEFAULT '',
    llm_reason      TEXT,
    llm_action      TEXT,
    diagnosed_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_drh_session  ON diagnosis_results_history (session_id);
CREATE INDEX IF NOT EXISTS ix_drh_code     ON diagnosis_results_history (code);
CREATE INDEX IF NOT EXISTS ix_drh_date     ON diagnosis_results_history (diagnosed_at);
"""

# ── UPSERT / INSERT SQL ───────────────────────────────────────────

UPSERT_RESULT_SQL = """
INSERT INTO diagnosis_results (
    code, session_id, os_type, result_1st,
    collected_value, raw_output
)
VALUES (
    %(code)s, %(session_id)s, %(os_type)s, %(result_1st)s,
    %(collected_value)s, %(raw_output)s
)
ON CONFLICT (code) DO UPDATE SET
    session_id      = EXCLUDED.session_id,
    os_type         = EXCLUDED.os_type,
    result_1st      = EXCLUDED.result_1st,
    result_2nd      = NULL,             -- 재진단 시 LLM 판정 초기화
    collected_value = EXCLUDED.collected_value,
    raw_output      = EXCLUDED.raw_output,
    llm_reason      = NULL,
    llm_action      = NULL,
    llm_prompt      = NULL,
    diagnosed_at    = CURRENT_TIMESTAMP,
    updated_at      = CURRENT_TIMESTAMP;
"""

INSERT_HISTORY_SQL = """
INSERT INTO diagnosis_results_history (
    session_id, code, os_type, result_1st,
    collected_value, raw_output
)
VALUES (
    %(session_id)s, %(code)s, %(os_type)s, %(result_1st)s,
    %(collected_value)s, %(raw_output)s
);
"""

UPDATE_LLM_SQL = """
UPDATE diagnosis_results
SET
    result_2nd  = %(result_2nd)s,
    llm_reason  = %(llm_reason)s,
    llm_action  = %(llm_action)s,
    llm_prompt  = %(llm_prompt)s,
    updated_at  = CURRENT_TIMESTAMP
WHERE session_id = %(session_id)s
  AND code       = %(code)s;
"""

UPDATE_HISTORY_LLM_SQL = """
UPDATE diagnosis_results_history
SET
    result_2nd = %(result_2nd)s,
    llm_reason = %(llm_reason)s,
    llm_action = %(llm_action)s
WHERE session_id = %(session_id)s
  AND code       = %(code)s;
"""

FETCH_PENDING_LLM_SQL = """
SELECT
    d.code,
    d.session_id,
    d.result_1st,
    d.collected_value,
    d.raw_output,
    v.title,
    v.severity,
    v.category,
    v.check_content,
    v.check_purpose,
    v.criteria_good,
    v.criteria_bad,
    v.security_threat,
    v.action        AS guide_action,
    v.action_impact
FROM diagnosis_results d
LEFT JOIN vulnerabilities v ON v.code = d.code
WHERE d.session_id = %(session_id)s
  AND d.result_1st IN ('취약', '규칙불가')
  AND d.result_2nd IS NULL
ORDER BY
    CASE v.severity WHEN '상' THEN 1 WHEN '중' THEN 2 WHEN '하' THEN 3 ELSE 4 END,
    d.code;
"""

FETCH_SESSION_SQL = """
SELECT
    d.*,
    v.title,
    v.severity,
    v.category,
    v.criteria_good,
    v.criteria_bad,
    v.action        AS guide_action,
    v.security_threat
FROM diagnosis_results d
LEFT JOIN vulnerabilities v ON v.code = d.code
WHERE d.session_id = %(session_id)s
ORDER BY d.code;
"""

COMPARE_SESSIONS_SQL = """
SELECT
    COALESCE(a.code, b.code)    AS code,
    v.title,
    v.severity,
    a.result_1st                AS prev_result,
    b.result_1st                AS cur_result,
    CASE
        WHEN a.result_1st IN ('취약','규칙불가') AND b.result_1st = '양호' THEN '개선'
        WHEN a.result_1st = '양호' AND b.result_1st IN ('취약','규칙불가') THEN '악화'
        WHEN a.code IS NULL                                                 THEN '신규'
        WHEN b.code IS NULL                                                 THEN '삭제'
        ELSE '유지'
    END                         AS change_type
FROM diagnosis_results_history a
FULL OUTER JOIN diagnosis_results_history b
    ON a.code = b.code
LEFT JOIN vulnerabilities v
    ON v.code = COALESCE(a.code, b.code)
WHERE a.session_id = %(session_a)s
  AND b.session_id = %(session_b)s
ORDER BY
    CASE
        WHEN a.result_1st IN ('취약','규칙불가') AND b.result_1st = '양호' THEN 1
        WHEN a.result_1st = '양호' AND b.result_1st IN ('취약','규칙불가') THEN 2
        ELSE 3
    END,
    COALESCE(a.code, b.code);
"""


class DiagnosisRepository:
    def __init__(self, dsn: str = DEFAULT_DSN):
        self.dsn = dsn

    # ── 초기화 ───────────────────────────────────────────────────

    def initialize(self) -> None:
        """테이블 3개 생성 (없으면 생성, 있으면 스킵)"""
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(SESSION_SCHEMA_SQL)
                cur.execute(RESULTS_SCHEMA_SQL)
                cur.execute(HISTORY_SCHEMA_SQL)
            conn.commit()

    # ── 세션 ─────────────────────────────────────────────────────

    def create_session(
        self,
        os_type: str,
        prefix: str = "",
        category: str = "",
        memo: str = "",
        session_id: str | None = None,
    ) -> str:
        """세션 생성 후 session_id 반환"""
        sid = session_id or str(uuid.uuid4())
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO diagnosis_sessions
                        (session_id, os_type, prefix, category, memo)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (sid, os_type, prefix, category, memo),
                )
            conn.commit()
        return sid

    def finish_session(self, session_id: str) -> None:
        """진단 완료 시 finished_at + 카운트 업데이트"""
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE diagnosis_sessions
                    SET
                        finished_at   = CURRENT_TIMESTAMP,
                        total         = (SELECT COUNT(*)    FROM diagnosis_results_history WHERE session_id = %s),
                        ok_count      = (SELECT COUNT(*)    FROM diagnosis_results_history WHERE session_id = %s AND result_1st = '양호'),
                        vuln_count    = (SELECT COUNT(*)    FROM diagnosis_results_history WHERE session_id = %s AND result_1st = '취약'),
                        unknown_count = (SELECT COUNT(*)    FROM diagnosis_results_history WHERE session_id = %s AND result_1st = '규칙불가')
                    WHERE session_id = %s
                    """,
                    (session_id, session_id, session_id, session_id, session_id),
                )
            conn.commit()

    def list_sessions(self, limit: int = 20) -> list[dict]:
        """최근 세션 목록 조회"""
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT * FROM diagnosis_sessions
                    ORDER BY started_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return [dict(r) for r in cur.fetchall()]

    # ── 결과 저장 ────────────────────────────────────────────────

    def save_results(self, session_id: str, os_type: str, results: Iterable[dict]) -> int:
        """
        스크립트 실행 결과 저장.
        diagnosis_results (최신 1개 upsert) + diagnosis_results_history (누적) 동시 저장.
        """
        rows = [self._to_row(session_id, os_type, r) for r in results]
        if not rows:
            return 0

        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.executemany(UPSERT_RESULT_SQL, rows)
                cur.executemany(INSERT_HISTORY_SQL, rows)
            conn.commit()
        return len(rows)

    def _to_row(self, session_id: str, os_type: str, result: dict) -> dict:
        """스크립트 출력 dict → DB row dict 변환"""
        raw = result.get("raw_output", "")

        # PostgreSQL은 \x00 허용 안 함 → sanitize
        def sanitize(v: object) -> object:
            if isinstance(v, str):
                return v.replace("\x00", "")
            if isinstance(v, dict):
                return {k: sanitize(val) for k, val in v.items()}
            if isinstance(v, list):
                return [sanitize(i) for i in v]
            return v

        return {
            "session_id":      session_id,
            "code":            sanitize(result.get("item_code", "")),
            "os_type":         os_type,
            "result_1st":      sanitize(result.get("result", "규칙불가")),
            "collected_value": sanitize(result.get("collected_value", "")),
            "raw_output":      sanitize(raw) if isinstance(raw, str) else sanitize(json.dumps(raw, ensure_ascii=False)),
        }

    # ── LLM 결과 업데이트 ────────────────────────────────────────

    def update_llm_result(
        self,
        session_id: str,
        code: str,
        result_2nd: str,
        llm_reason: str,
        llm_action: str,
        llm_prompt: str = "",
    ) -> None:
        """analyzer.py가 Gemini 응답 받은 후 호출"""
        params = {
            "session_id": session_id,
            "code":       code,
            "result_2nd": result_2nd,
            "llm_reason": llm_reason,
            "llm_action": llm_action,
            "llm_prompt": llm_prompt,
        }
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(UPDATE_LLM_SQL, params)
                cur.execute(UPDATE_HISTORY_LLM_SQL, params)
            conn.commit()

    # ── 조회 ─────────────────────────────────────────────────────

    def fetch_pending_llm(self, session_id: str) -> list[dict]:
        """
        취약/규칙불가 중 LLM 판정 안 된 항목.
        주통기 vulnerabilities 테이블과 JOIN해서 반환.
        analyzer.py가 이걸 받아서 Gemini API 호출.
        """
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(FETCH_PENDING_LLM_SQL, {"session_id": session_id})
                return [dict(r) for r in cur.fetchall()]

    def fetch_session(self, session_id: str) -> list[dict]:
        """세션 전체 결과 + 가이드라인 JOIN 조회"""
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(FETCH_SESSION_SQL, {"session_id": session_id})
                return [dict(r) for r in cur.fetchall()]

    def compare_sessions(self, session_a: str, session_b: str) -> list[dict]:
        """
        두 세션 비교.
        session_a: 이전 세션
        session_b: 현재 세션
        change_type: 개선 / 악화 / 신규 / 삭제 / 유지
        """
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    COMPARE_SESSIONS_SQL,
                    {"session_a": session_a, "session_b": session_b},
                )
                return [dict(r) for r in cur.fetchall()]

    def fetch_latest_two_sessions(self, os_type: str = "windows") -> tuple[str | None, str | None]:
        """
        가장 최근 두 세션 ID 반환 → compare_sessions에 바로 사용 가능.
        반환: (이전 세션, 최신 세션)
        """
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT session_id FROM diagnosis_sessions
                    WHERE os_type = %s
                      AND finished_at IS NOT NULL
                    ORDER BY started_at DESC
                    LIMIT 2
                    """,
                    (os_type,),
                )
                rows = cur.fetchall()

        if len(rows) == 2:
            return rows[1]["session_id"], rows[0]["session_id"]  # (이전, 최신)
        if len(rows) == 1:
            return None, rows[0]["session_id"]
        return None, None