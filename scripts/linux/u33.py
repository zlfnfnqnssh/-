#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-33 DNS 보안 버전 패치 점검 스크립트
- raw_output은 실제 명령어 실행 결과 그대로
- collected_value는 import re를 활용한 정규표현식 파싱 결과 (핵심 한 줄만)
- 판단 로직(양호/취약/설정 없음/미설치 등) 절대 포함하지 않음
- OS별 동일 명령어 사용 (SOLARIS, LINUX, AIX, HP-UX 공통)
"""
import subprocess
import json
import os
import platform
import re
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u33_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except Exception as e:
        return f"ERROR: {str(e)}"


def get_os_info() -> tuple:
    system = platform.system().lower()
    if system == "linux":
        os_type = "linux"
        os_name = "Linux"
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", encoding="utf-8") as f:
                    content = f.read().lower()
                    if "ubuntu" in content or "debian" in content:
                        os_name = "Debian/Ubuntu"
                    elif any(x in content for x in ["rhel", "centos", "fedora", "red hat"]):
                        os_name = "RHEL/CentOS"
            except:
                pass
        return os_type, os_name
    elif system == "sunos":
        return "solaris", "Solaris"
    elif system == "aix":
        return "aix", "AIX"
    elif system == "hp-ux":
        return "hpux", "HP-UX"
    else:
        return system, system.capitalize()


def save_json(result: Dict, output_dir: str, filename: str):
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[+] U-33 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    # 1. named 프로세스 확인 (주통기와 완전 동일)
    ps_cmd = "ps -ef | grep [n]amed"
    ps_raw = run_shell(ps_cmd)

    # 정규표현식으로 핵심 named 프로세스 라인만 추출 (collected_value)
    if ps_raw:
        # named 프로세스 라인만 매칭 (PID, 사용자, 명령어 포함)
        match = re.search(r'^\S+\s+\d+\s+.*named', ps_raw, re.MULTILINE)
        collected_ps = match.group(0).strip() if match else "NOT FOUND"
    else:
        collected_ps = "FILE NOT FOUND"

    check_results.append({
        "sub_check": "DNS 서비스 (named)",
        "config_file": "프로세스",
        "collected_value": collected_ps,
        "raw_output": ps_raw if ps_raw else "NOT FOUND",
        "service_status": "RUNNING" if ps_raw else "NOT_RUNNING",
        "source_command": ps_cmd
    })

    # 2. BIND 버전 확인 (named -v)
    version_cmd = "named -v 2>/dev/null || echo 'COMMAND NOT FOUND'"
    version_raw = run_shell(version_cmd)

    # 정규표현식으로 BIND 버전만 정교하게 추출 (예: BIND 9.10.3-P2)
    if version_raw and "COMMAND NOT FOUND" not in version_raw.upper():
        # BIND + 버전 번호 패턴 매칭 (주통기에서 확인하는 핵심 버전 정보)
        match = re.search(r'BIND\s+([0-9]+\.[0-9]+\.[0-9]+(-P[0-9]+)?)', version_raw, re.IGNORECASE)
        collected_version = match.group(0).strip() if match else version_raw.strip()
    else:
        collected_version = "FILE NOT FOUND"

    check_results.append({
        "sub_check": "BIND 버전",
        "config_file": "named",
        "collected_value": collected_version,
        "raw_output": version_raw if version_raw else "NOT FOUND",
        "service_status": "RUNNING" if ps_raw else "NOT_RUNNING",
        "source_command": version_cmd
    })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "서비스 관리",
                "item_code": "U-33",
                "item_name": "DNS 보안 버전 패치",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
