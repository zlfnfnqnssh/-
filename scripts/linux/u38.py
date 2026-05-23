#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-38 웹서비스 불필요한 파일 제거 점검 스크립트
- source_command: 실제로 collected_value를 추출할 때 사용한 명령어를 그대로 저장
- 불필요한 매뉴얼 디렉터리(/manual, /htdocs/manual 등) 존재 여부 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u38_result_{scan_id}.json")


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
        print(f"[+] U-38 결과가 저장되었습니다: {filepath}")
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


    # Apache에서 흔히 존재하는 불필요한 매뉴얼 디렉터리 목록 (주통기 기준)
    manual_dirs = [
        "/usr/local/apache/htdocs/manual",
        "/usr/local/apache2/htdocs/manual",
        "/usr/local/apache/manual",
        "/usr/local/apache2/manual",
        "/opt/apache/htdocs/manual",
        "/opt/apache2/htdocs/manual",
        "/etc/apache2/manual",
        "/var/www/html/manual",
        "/var/www/manual"
    ]

    for dir_path in manual_dirs:
        if os.path.exists(dir_path):
            # 실제 ls 명령어 실행 (주통기와 동일)
            ls_cmd = f"ls -ld {dir_path}"
            ls_raw = run_shell(ls_cmd)

            # collected_value: 디렉토리 존재 정보 (ls 결과의 첫 줄)
            collected_value = ls_raw.splitlines()[0].strip() if ls_raw else "NOT FOUND"

            check_results.append({
                "sub_check": "불필요한 매뉴얼 디렉터리",
                "config_file": dir_path,
                "collected_value": collected_value,
                "raw_output": ls_raw if ls_raw else "NOT FOUND",
                "service_status": apache_svc,
                "source_command": ls_cmd                     # 실제 사용한 명령어 그대로
            })
        else:
            check_results.append({
                "sub_check": "불필요한 매뉴얼 디렉터리",
                "config_file": dir_path,
                "collected_value": "FILE NOT FOUND",
                "raw_output": "NOT FOUND",
                "service_status": apache_svc,
                "source_command": f"ls -ld {dir_path}"
            })

    # 추가로 htdocs 내 일반적인 샘플/테스트 파일들도 확인 (주통기에서 언급된 불필요 파일)
    extra_check_paths = [
        "/usr/local/apache/htdocs/index.html",
        "/usr/local/apache2/htdocs/index.html",
        "/var/www/html/index.html"
    ]

    for path in extra_check_paths:
        if os.path.exists(path):
            ls_cmd = f"ls -ld {path}"
            ls_raw = run_shell(ls_cmd)
            collected_value = ls_raw.splitlines()[0].strip() if ls_raw else "NOT FOUND"

            check_results.append({
                "sub_check": "기본 샘플 파일 (index.html)",
                "config_file": path,
                "collected_value": collected_value,
                "raw_output": ls_raw if ls_raw else "NOT FOUND",
                "service_status": apache_svc,
                "source_command": ls_cmd
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
                "item_code": "U-38",
                "item_name": "웹서비스 불필요한 파일 제거",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
