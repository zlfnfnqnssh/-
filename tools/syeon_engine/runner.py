"""
runner.py
---------
OS를 자동 탐지하고, scripts/{os}/ 폴더의 점검 스크립트를
sudo로 실행한 뒤 각 스크립트의 JSON 결과를 반환합니다.

사용법:
    runner = ScriptRunner(scripts_base="./scripts", sudo_password="pw")
    results = runner.run_all()           # 모든 스크립트 실행
    results = runner.run_items(["U-01"]) # 특정 항목만 실행
"""

import os
import sys
import json
import subprocess
import platform
import glob
import re
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime

from models import ScanResult


# ──────────────────────────────────────────────
# OS 탐지
# ──────────────────────────────────────────────

def detect_os() -> tuple[str, str]:
    """
    현재 시스템의 OS를 탐지합니다.
    반환: (os_type, os_name)
      - os_type: "linux" | "windows" | "aix" | "solaris" | "hpux"
      - os_name: "Ubuntu" | "CentOS" | "Windows Server 2019" 등
    """
    system = platform.system().lower()

    if system == "windows":
        version = platform.version()
        return "windows", f"Windows {version}"

    if system == "linux":
        os_name = "Linux"
        try:
            with open("/etc/os-release", encoding="utf-8") as f:
                content = f.read().lower()
            if "ubuntu" in content:
                os_name = "Ubuntu"
            elif "debian" in content:
                os_name = "Debian"
            elif any(x in content for x in ["rhel", "centos", "red hat"]):
                os_name = "RHEL/CentOS"
            elif "rocky" in content:
                os_name = "Rocky Linux"
        except Exception:
            pass
        return "linux", os_name

    if system == "sunos":
        return "solaris", "Solaris"
    if system == "aix":
        return "aix", "AIX"
    if "hp-ux" in system:
        return "hpux", "HP-UX"

    return system, system.capitalize()


# ──────────────────────────────────────────────
# 스크립트 실행기
# ──────────────────────────────────────────────

class ScriptRunner:
    """
    scripts/{os_type}/ 아래의 점검 스크립트(u01.py, u02.py ...)를
    sudo로 실행하고 ScanResult 목록을 반환합니다.

    Parameters
    ----------
    scripts_base : str
        스크립트 루트 디렉토리. 기본값 "./scripts"
    sudo_password : str | None
        sudo 비밀번호. None이면 비밀번호 없이 실행 시도
    output_dir : str
        각 스크립트가 JSON을 저장할 폴더. 기본값 "/tmp/scan_results"
    timeout : int
        스크립트 1개당 최대 실행 시간(초). 기본값 60
    """

    def __init__(
        self,
        scripts_base: str = "./scripts",
        sudo_password: Optional[str] = None,
        output_dir: str = "/tmp/scan_results",
        timeout: int = 60,
        progress_callback=None,
    ):
        self.scripts_base = Path(scripts_base)
        self.sudo_password = sudo_password
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.progress_callback = progress_callback  # fn(current, total, label)

        self.os_type, self.os_name = detect_os()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        print(f"[Runner] 탐지된 OS: {self.os_name} ({self.os_type})")

    # --------------------------------------------------
    def _get_script_paths(self, item_codes: Optional[List[str]] = None) -> List[Path]:
        """
        실행할 스크립트 경로 목록 반환.
        item_codes가 None이면 해당 OS 폴더의 모든 스크립트.
        """
        script_dir = self.scripts_base / self.os_type

        if not script_dir.exists():
            print(f"[Runner] 경고: 스크립트 폴더 없음 → {script_dir}")
            return []

        # u01.py, u02.py ... 파일 수집
        all_scripts = sorted(script_dir.glob("u*.py"))

        if item_codes is None:
            return all_scripts

        # 필터링: "U-01" → "u01" 매핑
        def normalize(code: str) -> str:
            return code.lower().replace("-", "")

        targets = {normalize(c) for c in item_codes}
        return [
            p for p in all_scripts
            if normalize(p.stem) in targets
        ]

    # --------------------------------------------------
    def _run_single(self, script_path: Path) -> Optional[ScanResult]:
        """
        스크립트 1개를 sudo로 실행하고 ScanResult를 반환합니다.
        실패 시 None 반환.
        """
        item_code = script_path.stem.upper()           # "u01" → "U01" (표시용)
        item_label = re.sub(r"(u)(\d+)", r"U-\2", script_path.stem, flags=re.IGNORECASE)
        print(f"[Runner] 실행 중: {item_label}  ({script_path})")

        # JSON 저장 경로를 환경변수로 전달
        scan_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_filename = f"{script_path.stem}_result_scan_{scan_ts}.json"
        env = os.environ.copy()
        env["OUTPUT_DIR"] = str(self.output_dir)
        env["OUTPUT_FILENAME"] = out_filename

        # sudo 명령어 조립
        if self.sudo_password:
            # echo "pw" | sudo -S python3 script.py
            cmd = (
                f'echo {self._escape(self.sudo_password)} | '
                f'sudo -S python3 {script_path}'
            )
        else:
            # 비밀번호 없으면 sudo 없이 실행 (데모/테스트용)
            cmd = f"python3 {script_path}"

        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            print(f"[Runner] 타임아웃: {item_label}")
            return None
        except Exception as e:
            print(f"[Runner] 실행 오류: {item_label} → {e}")
            return None

        if proc.returncode not in (0, None):
            print(f"[Runner] 스크립트 오류 (exit={proc.returncode}): {item_label}")
            if proc.stderr:
                print(f"         stderr: {proc.stderr[:200]}")

        # 저장된 JSON 파일 읽기
        json_path = self.output_dir / out_filename
        if json_path.exists():
            return self._load_json(json_path, item_label)

        # 파일이 없으면 stdout에서 직접 파싱 시도
        return self._parse_stdout(proc.stdout, item_label)

    # --------------------------------------------------
    def _load_json(self, path: Path, label: str) -> Optional[ScanResult]:
        """저장된 JSON 파일 → ScanResult"""
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return ScanResult.from_dict(data)
        except Exception as e:
            print(f"[Runner] JSON 파싱 실패 ({label}): {e}")
            return None

    def _parse_stdout(self, stdout: str, label: str) -> Optional[ScanResult]:
        """stdout에서 JSON 추출 시도 (파일 저장 실패 fallback)"""
        try:
            start = stdout.find("{")
            if start == -1:
                return None

            # ★ 수정: JSON 블록의 끝 중괄호를 직접 찾아서 잘라냄
            # JSON 뒤에 "[+] 결과가 저장되었습니다" 같은 텍스트가 붙어도 처리 가능
            end = stdout.rfind("}") + 1
            if end == 0:
                return None

            data = json.loads(stdout[start:end])
            return ScanResult.from_dict(data)
        except Exception as e:
            print(f"[Runner] stdout 파싱 실패 ({label}): {e}")
            return None

    @staticmethod
    def _escape(pw: str) -> str:
        """셸 인젝션 방지: 비밀번호에서 위험 문자 이스케이프"""
        return "'" + pw.replace("'", "'\\''") + "'"

    # --------------------------------------------------
    def run_all(self) -> List[ScanResult]:
        """해당 OS의 모든 점검 스크립트 실행"""
        scripts = self._get_script_paths()
        return self._execute(scripts)

    def run_items(self, item_codes: List[str]) -> List[ScanResult]:
        """지정한 항목 코드(["U-01", "U-02"]) 만 실행"""
        scripts = self._get_script_paths(item_codes)
        return self._execute(scripts)

    def _execute(self, scripts: List[Path]) -> List[ScanResult]:
        """스크립트 목록 순차 실행 → 결과 목록 반환 (공통 scan_id 사용)"""
        if not scripts:
            print("[Runner] 실행할 스크립트가 없습니다.")
            return []

        # 전체 실행에 공통 scan_id 부여 (스크립트 실행 전 1회 생성)
        common_scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.environ["SCAN_ID"] = common_scan_id

        results = []
        total = len(scripts)
        for i, script in enumerate(scripts):
            label = re.sub(r"(u)(\d+)", r"U-\2", script.stem, flags=re.IGNORECASE)
            if self.progress_callback:
                self.progress_callback(i, total, label)
            result = self._run_single(script)
            if result:
                result.scan_id = common_scan_id   # 강제 통일
                results.append(result)

        if self.progress_callback:
            self.progress_callback(total, total, "완료")
        print(f"[Runner] 완료: {len(results)}/{total} 성공 (scan_id={common_scan_id})")
        return results


# ──────────────────────────────────────────────
# 단독 실행 테스트
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import getpass

    password = getpass.getpass("sudo 비밀번호: ")
    runner = ScriptRunner(
        scripts_base="./scripts",
        sudo_password=password,
        output_dir="/tmp/scan_results",
    )
    results = runner.run_all()
    for r in results:
        print(f"  → {r.scan_id} | {r.os_name} | 항목수: {len(r.items)}")
