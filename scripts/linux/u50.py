#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-50 관리자 그룹에 최소한의 계정 포함 점검 스크립트
- root 그룹 (Linux, Solaris, HP-UX) 또는 system 그룹 (AIX) 확인
- 관리자 그룹에 root 외 불필요한 계정이 포함되어 있는지 점검
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u50_result_{scan_id}.json")


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
        print(f"[+] U-50 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    group_file = "/etc/group"

    if os.path.exists(group_file):
        group_raw = run_shell("cat /etc/group")

        # OS별 관리자 그룹 이름 결정
        if target_os == "aix":
            admin_group_name = "system"
        else:
            admin_group_name = "root"

        # 관리자 그룹 라인 추출
        admin_group_line = re.search(rf'^{admin_group_name}:.*$', group_raw, re.MULTILINE | re.IGNORECASE)

        if admin_group_line:
            line = admin_group_line.group(0).strip()
            
            # 그룹 멤버 추출 (마지막 필드)
            members_match = re.search(r':([^:]*)$', line)
            members = members_match.group(1).strip() if members_match else ""

            # 멤버를 쉼표로 분리
            member_list = [m.strip() for m in members.split(',') if m.strip()]

            collected_value = f"그룹: {admin_group_name} | 멤버: {', '.join(member_list) if member_list else '없음'}"

            check_results.append({
                "sub_check": f"관리자 그룹 ({admin_group_name})",
                "config_file": "/etc/group",
                "collected_value": collected_value,
                "raw_output": line,                    # 관리자 그룹 라인만
                "service_status": "N/A",
                "source_command": f"grep '^{admin_group_name}:' /etc/group"
            })
        else:
            check_results.append({
                "sub_check": f"관리자 그룹 ({admin_group_name})",
                "config_file": "/etc/group",
                "collected_value": f"{admin_group_name} 그룹 없음",
                "raw_output": "NOT FOUND",
                "service_status": "N/A",
                "source_command": f"grep '^{admin_group_name}:' /etc/group"
            })

        # 전체 /etc/group도 참고용으로 추가 (필요 시 전체 확인 가능)
        check_results.append({
            "sub_check": "전체 그룹 파일 확인",
            "config_file": "/etc/group",
            "collected_value": "전체 그룹 내용 (참고용)",
            "raw_output": group_raw,
            "service_status": "N/A",
            "source_command": "cat /etc/group"
        })

    else:
        check_results.append({
            "sub_check": "관리자 그룹 확인",
            "config_file": "/etc/group",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "cat /etc/group"
        })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "계정관리",
                "item_code": "U-50",
                "item_name": "관리자 그룹에 최소한의 계정 포함",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
