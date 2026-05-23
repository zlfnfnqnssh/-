#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-55 (하) hosts.lpd 파일 소유자 및 권한 설정 점검 스크립트
- /etc/hosts.lpd 파일의 존재 여부, 소유자(root), 권한(600) 점검
"""
import subprocess
import json
import os
import platform
import stat
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u55_result_{scan_id}.json")


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
                        os_name = "Ubuntu/Debian"
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
        print(f"[+] U-55 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 서비스 실행 여부 확인 (LPD/CUPS 프린터)
    _lpd_active = run_shell("systemctl is-active cups 2>/dev/null || systemctl is-active lpd 2>/dev/null")
    _lpd_which  = run_shell("which lpd cupsd 2>/dev/null | head -1")
    lpd_svc = "RUNNING" if _lpd_active.strip() == "active" else               ("NOT_INSTALLED" if not _lpd_which else "NOT_RUNNING")


    hosts_lpd = "/etc/hosts.lpd"

    if os.path.exists(hosts_lpd):
        # ls -l 명령어로 권한 및 소유자 확인 (주통기와 동일)
        ls_cmd = f"ls -l {hosts_lpd}"
        ls_result = run_shell(ls_cmd)

        # stat을 이용해 소유자와 권한 상세 정보 수집
        try:
            st = os.stat(hosts_lpd)
            owner = st.st_uid
            mode = stat.filemode(st.st_mode)
            perm_octal = oct(st.st_mode)[-3:]  # 600 형태
            owner_name = run_shell(f"ls -ld {hosts_lpd} | awk '{{print $3}}'").strip()
        except:
            owner_name = "UNKNOWN"
            perm_octal = "UNKNOWN"
            mode = "UNKNOWN"

        # collected_value: 핵심 판단 정보 (소유자 + 권한)
        collected_value = f"owner={owner_name}, permission={perm_octal} ({mode})"

        check_results.append({
            "sub_check": "hosts.lpd 파일 존재 및 권한 점검",
            "config_file": "/etc/hosts.lpd",
            "collected_value": collected_value,
            "raw_output": ls_result if ls_result else "NOT FOUND",
            "service_status": lpd_svc,
            "source_command": "ls -l /etc/hosts.lpd"
        })

        # 추가로 소유자 및 권한 상세 분리 (판단에 유리)
        check_results.append({
            "sub_check": "hosts.lpd 소유자 및 권한 상세",
            "config_file": "/etc/hosts.lpd",
            "collected_value": f"owner: {owner_name}, permission: {perm_octal}",
            "raw_output": ls_result if ls_result else "NOT FOUND",
            "service_status": lpd_svc,
            "source_command": "ls -l /etc/hosts.lpd && stat -c 'owner=%U perm=%a' /etc/hosts.lpd 2>/dev/null || echo 'stat not available'"
        })

    else:
        # 파일이 존재하지 않는 경우 (양호 조건 충족)
        check_results.append({
            "sub_check": "hosts.lpd 파일 존재 및 권한 점검",
            "config_file": "/etc/hosts.lpd",
            "collected_value": "FILE NOT FOUND (deleted)",
            "raw_output": "NOT FOUND",
            "service_status": lpd_svc,
            "source_command": "ls -l /etc/hosts.lpd"
        })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "파일 및 디렉토리 관리",
                "item_code": "U-55",
                "item_name": "hosts.lpd 파일 소유자 및 권한 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
