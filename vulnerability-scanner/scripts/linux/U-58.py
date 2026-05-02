#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-58 (중) 홈디렉토리로 지정한 디렉토리의 존재 관리 점검 스크립트
- /etc/passwd에 등록된 사용자 계정의 홈 디렉토리가 실제로 존재하는지 점검
- 홈 디렉토리가 존재하지 않는 계정을 중점적으로 수집
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u58_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
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
        print(f"[+] U-58 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    passwd_file = "/etc/passwd"

    if os.path.exists(passwd_file):
        # 1. /etc/passwd 전체 내용 (raw_output용)
        raw_passwd = run_shell("cat /etc/passwd")

        # 2. 홈 디렉토리가 실제로 존재하지 않는 계정만 추출 (판단 핵심)
        missing_cmd = r"""
awk -F: '
    {
        user = $1;
        uid = $3;
        home = $6;
        if (home != "" && home != "/" && home != "/root") {
            if (system("test -d " home " 2>/dev/null") != 0) {
                print user ":" uid ":" home " (MISSING)";
            }
        }
    }
' /etc/passwd
"""

        missing_result = run_shell(missing_cmd).strip()

        if missing_result:
            collected_value = missing_result
        else:
            collected_value = "All home directories exist"

        # 주요 점검 결과
        check_results.append({
            "sub_check": "홈디렉토리 존재 여부 점검",
            "config_file": "/etc/passwd",
            "collected_value": collected_value,
            "raw_output": raw_passwd if raw_passwd else "NOT FOUND",
            "service_status": "N/A",
            "source_command": "cat /etc/passwd && awk -F: '$6 != \"\" && $6 != \"/\" {print $1 \":\" $6}' /etc/passwd | xargs -I {} sh -c 'test -d {} || echo {} MISSING'"
        })

        # 상세 정보 (문제 계정이 있을 경우)
        if missing_result:
            check_results.append({
                "sub_check": "홈디렉토리가 존재하지 않는 계정 목록",
                "config_file": "/etc/passwd",
                "collected_value": missing_result,
                "raw_output": missing_result,
                "service_status": "N/A",
                "source_command": "awk -F: '$6 != \"\" {if (system(\"test -d \" $6) != 0) print $1 \":\" $6}' /etc/passwd"
            })

        # 추가로 루트 디렉토리(/)를 홈으로 가진 계정도 확인 (보안상 위험)
        root_home_cmd = r"""
awk -F: '$6 == "/" || $6 == "" {print $1 ":" $3 ":" $6 " (ROOT HOME)"}' /etc/passwd
"""
        root_home_result = run_shell(root_home_cmd).strip()
        if root_home_result:
            check_results.append({
                "sub_check": "루트 디렉토리를 홈으로 사용하는 계정",
                "config_file": "/etc/passwd",
                "collected_value": root_home_result,
                "raw_output": root_home_result,
                "service_status": "N/A",
                "source_command": "awk -F: '$6 == \"/\" || $6 == \"\" {print $1 \":\" $6}' /etc/passwd"
            })

    else:
        check_results.append({
            "sub_check": "홈디렉토리 존재 여부 점검",
            "config_file": "/etc/passwd",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "cat /etc/passwd"
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
                "item_code": "U-58",
                "item_name": "홈디렉토리로 지정한 디렉토리의 존재 관리",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
