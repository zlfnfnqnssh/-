#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-39 웹서비스 링크 사용금지 점검 스크립트
- FollowSymLinks 옵션 사용 여부 점검
- source_command: 실제 grep 명령어를 그대로 저장
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u39_result_{scan_id}.json")


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
        print(f"[+] U-39 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    # 서비스 실행 여부 확인
    _svc_active = run_shell("systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null")
    apache_svc = "RUNNING" if _svc_active.strip() == "active" else                  ("NOT_INSTALLED" if not run_shell("which apache2 httpd 2>/dev/null | head -1") else "NOT_RUNNING")


    # Ubuntu/Debian 중심 실제 Apache 설정 파일 경로
    apache_conf_paths = [
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-available/000-default.conf",
        "/etc/apache2/sites-enabled/000-default.conf",
        "/etc/httpd/conf/httpd.conf",
        "/usr/local/apache2/conf/httpd.conf",
        "/usr/local/apache/conf/httpd.conf"
    ]

    found = False

    for conf_path in apache_conf_paths:
        if os.path.exists(conf_path):
            found = True
            conf_raw = run_shell(f"cat {conf_path}")

            # 실제 collected_value 추출에 사용한 grep 명령어
            grep_cmd = f"grep -E 'Options' {conf_path}"

            # 정규표현식으로 Options 지시자에서 FollowSymLinks 관련 라인만 추출
            options_lines = re.findall(r'^\s*Options\s+.*$', conf_raw, re.MULTILINE | re.IGNORECASE)
            
            followsymlinks_parts = []
            for line in options_lines:
                # FollowSymLinks, -FollowSymLinks, +FollowSymLinks 패턴 매칭
                if re.search(r'(?<!\w)([-+]?FollowSymLinks)(?!\w)', line, re.IGNORECASE):
                    followsymlinks_parts.append(line.strip())

            collected_value = "\n".join(followsymlinks_parts) if followsymlinks_parts else "FollowSymLinks 옵션 없음"

            check_results.append({
                "sub_check": "Apache FollowSymLinks (링크 사용 제한)",
                "config_file": conf_path,
                "collected_value": collected_value,
                "raw_output": conf_raw,
                "service_status": apache_svc,
                "source_command": grep_cmd          # 실제 사용한 명령어 그대로 저장
            })
            break

    # 설정 파일을 찾지 못한 경우
    if not found:
        check_results.append({
            "sub_check": "Apache FollowSymLinks (링크 사용 제한)",
            "config_file": "/etc/apache2/apache2.conf",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NOT FOUND",
            "service_status": apache_svc,
            "source_command": "grep -E 'Options' /etc/apache2/apache2.conf"
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
                "item_code": "U-39",
                "item_name": "웹서비스 링크 사용금지",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
