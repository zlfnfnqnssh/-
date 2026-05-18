from __future__ import annotations

import json
import os
import platform
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

WINDOWS_PREFIXES = {"W", "PC"}
LINUX_PREFIXES = {"U"}


@dataclass
class ScriptRunResult:
    code: str
    script_path: str
    return_code: int
    stdout: str
    stderr: str


class ScriptRunner:
    """Run and manage jutonggi check scripts with OS routing and Gemini generation."""

    def __init__(
        self,
        dsn: str,
        repo_root: str | Path = ".",
        gemini_cli_cmd: str | None = None,
    ):
        self.dsn = dsn
        self.repo_root = Path(repo_root).resolve()
        self.scripts_root = self.repo_root / "scripts"
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    def get_vulnerability(self, code: str) -> dict[str, Any] | None:
        sql = """
        SELECT code, prefix, domain, domain_name, os_type, category, severity, title,
               target, check_content, check_purpose, security_threat, criteria_good,
               criteria_bad, action, action_impact, note, page_start, pdf_version,
               content_hash, raw_json
        FROM vulnerabilities
        WHERE code = %s;
        """
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (code,))
                row = cur.fetchone()
                return dict(row) if row else None

    def list_missing_scripts(self) -> list[str]:
        sql = "SELECT code FROM vulnerabilities ORDER BY code;"
        missing: list[str] = []
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                for row in cur.fetchall():
                    code = row["code"]
                    if not self.resolve_script_path(code).exists():
                        missing.append(code)
        return missing

    def resolve_script_path(self, code: str, target_os: str | None = None) -> Path:
        prefix = code.split("-", 1)[0].upper()
        folder = self._folder_for_prefix(prefix, target_os)
        return self.scripts_root / folder / f"{code}.py"

    def run_script(self, code: str, extra_args: list[str] | None = None, timeout: int = 120) -> ScriptRunResult:
        script_path = self.resolve_script_path(code)
        if not script_path.exists():
            raise FileNotFoundError(f"Script not found for {code}: {script_path}")

        cmd = ["python", str(script_path)]
        if extra_args:
            cmd.extend(extra_args)

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(self.repo_root),
            check=False,
        )
        return ScriptRunResult(
            code=code,
            script_path=str(script_path),
            return_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def generate_script_with_gemini(
        self,
        code: str,
        target_os: str | None = None,
        overwrite: bool = False,
        gemini_api_key: str | None = None,
        gemini_model: str | None = None,
    ) -> dict[str, Any]:
        vuln = self.get_vulnerability(code)
        if not vuln:
            raise ValueError(f"No vulnerability found in DB for code={code}")

        script_path = self.resolve_script_path(code, target_os=target_os)
        script_path.parent.mkdir(parents=True, exist_ok=True)

        if script_path.exists() and not overwrite:
            return {
                "code": code,
                "script_path": str(script_path),
                "generated": False,
                "reason": "already_exists",
            }

        prompt = self._build_gemini_prompt(vuln, script_path)
        code_block = self._extract_python_code(
            self._call_gemini_api(
                prompt,
                api_key=gemini_api_key or os.getenv("GEMINI_API_KEY", ""),
                model=gemini_model or self.gemini_model,
            )
        )
        script_path.write_text(code_block, encoding="utf-8")

        return {
            "code": code,
            "script_path": str(script_path),
            "generated": True,
            "gemini_model": gemini_model or self.gemini_model,
        }

    def _folder_for_prefix(self, prefix: str, target_os: str | None) -> str:
        if target_os:
            normalized = target_os.lower()
            if normalized.startswith("win"):
                return "windows"
            if normalized.startswith("lin"):
                return "linux"

        if prefix in WINDOWS_PREFIXES:
            return "windows"
        if prefix in LINUX_PREFIXES:
            return "linux"

        current = platform.system().lower()
        return "windows" if current.startswith("win") else "linux"

    def _build_gemini_prompt(self, vuln: dict[str, Any], script_path: Path) -> str:
        clean = {k: v for k, v in vuln.items() if k != "raw_json"}
        return (
            "You are generating a production-safe Python audit script for a jutonggi vulnerability check.\n"
            "Return only executable Python code. Do not include markdown fences.\n"
            "Script requirements:\n"
            "- stdout must be JSON\n"
            "- fields: code, status(pass/fail/error), evidence(list), recommendation\n"
            "- no destructive action (read-only checks only)\n"
            "- handle exceptions and output status=error with message in evidence\n"
            f"- save target path conceptually: {script_path}\n\n"
            "VULNERABILITY_RECORD:\n"
            f"{json.dumps(clean, ensure_ascii=False, indent=2)}\n"
        )

    @staticmethod
    def _extract_python_code(raw: str) -> str:
        text = raw.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            return "\n".join(lines).strip() + "\n"
        return text + ("\n" if not text.endswith("\n") else "")

    @staticmethod
    def _call_gemini_api(prompt: str, api_key: str, model: str) -> str:
        if not api_key or api_key == "YOUR_GEMINI_KEY_HERE":
            raise RuntimeError("GEMINI_API_KEY environment variable or gemini_api_key argument is required.")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096},
        }
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Gemini API connection failed: {exc}") from exc

        candidates = data.get("candidates") or []
        if not candidates:
            raise RuntimeError(f"Gemini API response has no candidates: {data}")
        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(part.get("text", "") for part in parts).strip()
        if not text:
            raise RuntimeError(f"Gemini API response has no generated text: {data}")
        return text
