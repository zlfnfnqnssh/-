from __future__ import annotations

import json
import logging
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from .scripts_db import DiagnosisRepository

logger = logging.getLogger(__name__)

DEFAULT_DSN   = "postgresql://admin:admin123@localhost:5432/jtk_db"
SCRIPTS_ROOT  = Path(__file__).parent.parent / "scripts"


class ScriptExecutor:
    def __init__(self, dsn: str = DEFAULT_DSN):
        self.dsn  = dsn
        self.repo = DiagnosisRepository(dsn)
        self.repo.initialize()

    # ── 외부에서 호출하는 메인 함수 ──────────────────────────────
    def run(
        self,
        os_type:  str = "windows",
        prefix:   str = "",
        category: str = "",
        severity: str = "",
        memo:     str = "",
    ) -> str:
        """
        웹 담당자가 진단 버튼 클릭 시 호출하는 함수.

        1. 주통기 DB에서 조건에 맞는 코드 목록 조회
        2. scripts/ 폴더와 1대1 매핑 → 있는 것만 필터링
        3. 일괄 실행 → DB 저장
        4. session_id 반환

        사용 예:
            executor = ScriptExecutor()
            session_id = executor.run(os_type="windows", prefix="PC")
        """
        started_at = datetime.now(timezone.utc)

        # 1. 가이드라인 기반 코드 목록 조회
        all_codes = self._fetch_guide_codes(os_type, prefix, category, severity)
        if not all_codes:
            logger.warning("[Executor] 조건에 맞는 가이드라인 항목 없음")
            return ""

        # 2. 스크립트 있는 것 / 없는 것 분리
        executable, missing = self._match_scripts(all_codes, os_type)

        if missing:
            logger.warning("[Executor] 스크립트 없는 항목 %d개: %s", len(missing), missing)
        if not executable:
            logger.error("[Executor] 실행 가능한 스크립트 없음")
            return ""

        # 3. 세션 생성
        session_id = str(uuid.uuid4())
        self.repo.create_session(
            session_id=session_id,
            os_type=os_type,
            prefix=prefix,
            category=category,
            memo=memo or f"{started_at.strftime('%Y-%m-%d %H:%M')} 자동 진단",
        )

        logger.info(
            "[Executor] 세션 %s 시작 | 전체 %d개 | 실행 %d개 | 스크립트없음 %d개",
            session_id, len(all_codes), len(executable), len(missing),
        )

        # 4. 일괄 실행
        results = [self._run_one(code, os_type) for code in executable]

        # 5. DB 저장
        self.repo.save_results(session_id, os_type, results)
        self.repo.finish_session(session_id)

        ok      = sum(1 for r in results if r.get("result") == "양호")
        vuln    = sum(1 for r in results if r.get("result") == "취약")
        unknown = sum(1 for r in results if r.get("result") == "규칙불가")

        logger.info(
            "[Executor] 완료 | session=%s | 양호 %d | 취약 %d | 규칙불가 %d",
            session_id, ok, vuln, unknown,
        )

        return session_id

    # ── 가이드라인 DB 조회 ────────────────────────────────────────
    def _fetch_guide_codes(
        self,
        os_type:  str,
        prefix:   str,
        category: str,
        severity: str,
    ) -> list[str]:
        """주통기 DB에서 조건에 맞는 코드 목록 조회"""
        conditions: list[str] = []
        params: list[str] = []

        if prefix:
            conditions.append("prefix = %s")
            params.append(prefix)
        if category:
            conditions.append("category ILIKE %s")
            params.append(f"%{category}%")
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if not prefix:
            # prefix 미지정 시 os_type 기반 자동 필터
            conditions.append("os_type = %s")
            params.append(os_type)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT code FROM vulnerabilities {where} ORDER BY code"

        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return [r["code"] for r in cur.fetchall()]

    # ── 스크립트 매칭 ─────────────────────────────────────────────
    def _match_scripts(
        self,
        codes:   list[str],
        os_type: str,
    ) -> tuple[list[str], list[str]]:
        """
        코드 목록을 스크립트 있는 것 / 없는 것으로 분리.
        1대1 매핑으로 파일 존재 여부만 확인.
        """
        folder = SCRIPTS_ROOT / os_type
        has_script:     list[str] = []
        missing_script: list[str] = []

        for code in codes:
            if (folder / f"{code}.py").exists():
                has_script.append(code)
            else:
                missing_script.append(code)

        return has_script, missing_script

    # ── 스크립트 단건 실행 ────────────────────────────────────────
    def _run_one(self, code: str, os_type: str) -> dict:
        """스크립트 하나 실행 후 결과 dict 반환"""
        script = SCRIPTS_ROOT / os_type / f"{code}.py"

        try:
            proc = subprocess.run(
                ["python", str(script)],
                capture_output=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            logger.error("[Executor] 타임아웃: %s", code)
            return self._error_result(code, "타임아웃 (30초 초과)")
        except Exception as e:
            logger.error("[Executor] 실행 오류: %s | %s", code, e)
            return self._error_result(code, f"실행 오류: {e}")

        raw = proc.stdout.strip()
        text = self._decode(raw)

        if not text:
            stderr = self._decode(proc.stderr.strip())
            logger.warning("[Executor] 출력 없음: %s | stderr: %s", code, stderr)
            return self._error_result(code, f"출력 없음 | stderr: {stderr}")

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning("[Executor] JSON 파싱 실패: %s", code)
            return self._error_result(code, "JSON 파싱 실패", raw_output=text)

    @staticmethod
    def _error_result(
        code:       str,
        reason:     str,
        raw_output: str = "",
    ) -> dict:
        return {
            "item_code":       code,
            "result":          "규칙불가",
            "collected_value": reason,
            "raw_output":      raw_output,
        }

    @staticmethod
    def _decode(raw: bytes) -> str:
        """PowerShell stdout 인코딩 자동 감지"""
        if not raw:
            return ""
        if raw.startswith(b"\xff\xfe"):
            return raw.decode("utf-16-le", errors="replace")
        if raw.startswith(b"\xfe\xff"):
            return raw.decode("utf-16-be", errors="replace")
        for enc in ("utf-8", "cp949"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")
    
if __name__ == "__main__":
    executor = ScriptExecutor()
    session_id = executor.run(os_type="windows", prefix="PC")
    print(f"session_id: {session_id}")