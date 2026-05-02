#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-42 최신 보안패치 및 벤더 권고사항 적용 점검 스크립트
- OS별로 다른 패치 확인 명령어 실행
- source_command: 실제 실행된 명령어를 그대로 저장
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u42_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
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
        print(f"[+] U-42 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    # ====================== OS별 패치 확인 ======================
    if target_os == "linux":
        # Linux (Ubuntu/Debian 중심)
        cmds = [
            ("OS 버전", "cat /etc/os-release | head -10"),
            ("커널 버전", "uname -r"),
            ("설치된 패키지 수", "dpkg -l | wc -l 2>/dev/null || rpm -qa | wc -l"),
            ("최신 패키지 업데이트 확인", "apt list --upgradable 2>/dev/null | head -20 || yum check-update 2>/dev/null | head -10")
        ]
        
        for sub_check, cmd in cmds:
            raw_output = run_shell(cmd)
            # 핵심 값만 추출 (너무 길면 앞부분만)
            collected = raw_output.splitlines()[0] if raw_output and len(raw_output.splitlines()) > 0 else "NOT FOUND"
            check_results.append({
                "sub_check": sub_check,
                "config_file": "패치 관리",
                "collected_value": collected,
                "raw_output": raw_output if raw_output else "NOT FOUND",
                "service_status": "N/A",
                "source_command": cmd
            })

    elif target_os == "solaris":
        # Solaris
        cmd = "showrev -p | head -30"
        raw = run_shell(cmd)
        collected = raw.splitlines()[0] if raw else "NOT FOUND"
        check_results.append({
            "sub_check": "Solaris 패치 리스트",
            "config_file": "패치 관리",
            "collected_value": collected,
            "raw_output": raw if raw else "NOT FOUND",
            "service_status": "N/A",
            "source_command": "showrev -p"
        })

    elif target_os == "aix":
        # AIX
        cmds = [
            ("AIX 버전", "oslevel -s"),
            ("Maintenance Level", "instfix -i | grep ML"),
            ("Service Pack", "instfix -i | grep SP")
        ]
        for sub, cmd in cmds:
            raw = run_shell(cmd)
            collected = raw.splitlines()[0] if raw else "NOT FOUND"
            check_results.append({
                "sub_check": sub,
                "config_file": "패치 관리",
                "collected_value": collected,
                "raw_output": raw if raw else "NOT FOUND",
                "service_status": "N/A",
                "source_command": cmd
            })

    elif target_os == "hpux":
        # HP-UX
        cmd = "swlist -l product | head -30"
        raw = run_shell(cmd)
        collected = raw.splitlines()[0] if raw else "NOT FOUND"
        check_results.append({
            "sub_check": "HP-UX 패치 리스트",
            "config_file": "패치 관리",
            "collected_value": collected,
            "raw_output": raw if raw else "NOT FOUND",
            "service_status": "N/A",
            "source_command": "swlist -l product"
        })

    else:
        # 기타 OS
        check_results.append({
            "sub_check": "패치 확인",
            "config_file": "패치 관리",
            "collected_value": "지원되지 않는 OS",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "uname -a"
        })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "패치 관리",
                "item_code": "U-42",
                "item_name": "최신 보안패치 및 벤더 권고사항 적용",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
