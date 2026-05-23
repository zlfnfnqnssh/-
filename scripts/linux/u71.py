#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-71 (중) Apache 웹 서비스 정보 숨김 점검 스크립트
- ServerTokens Prod와 ServerSignature Off 설정 여부 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u71_result_{scan_id}.json")


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
        print(f"[+] U-71 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # Apache 설정 파일 가능한 경로 목록
    apache_config_files = [
        "/etc/httpd/conf/httpd.conf",
        "/etc/apache2/httpd.conf",
        "/etc/apache2/apache2.conf",
        "/usr/local/apache/conf/httpd.conf",
        "/usr/local/apache2/conf/httpd.conf",
        "/opt/apache/conf/httpd.conf",
        "/opt/apache2/conf/httpd.conf",
        "/etc/httpd/conf.d/00-server.conf",   # 일부 배포판
    ]

    found_config = False

    for config_file in apache_config_files:
        if os.path.exists(config_file):
            found_config = True
            raw_content = run_shell(f"cat {config_file} 2>/dev/null")

            # ServerTokens 설정 찾기
            tokens_cmd = f"grep -E '^[[:space:]]*ServerTokens' {config_file} 2>/dev/null || true"
            tokens_line = run_shell(tokens_cmd).strip()

            # ServerSignature 설정 찾기
            signature_cmd = f"grep -E '^[[:space:]]*ServerSignature' {config_file} 2>/dev/null || true"
            signature_line = run_shell(signature_cmd).strip()

            # collected_value 구성
            collected = []
            if tokens_line:
                collected.append(tokens_line)
            if signature_line:
                collected.append(signature_line)
            
            collected_value = "\n".join(collected) if collected else "ServerTokens/ServerSignature not set"

            check_results.append({
                "sub_check": f"Apache 정보 숨김 설정 ({config_file})",
                "config_file": config_file,
                "collected_value": collected_value,
                "raw_output": raw_content if raw_content else "NOT FOUND",
                "service_status": "N/A",
                "source_command": f"grep -E 'ServerTokens|ServerSignature' {config_file}"
            })

    # Apache 설정 파일이 전혀 없는 경우
    if not found_config:
        check_results.append({
            "sub_check": "Apache 설정파일 존재 여부",
            "config_file": "httpd.conf / apache2.conf",
            "collected_value": "No Apache configuration file found",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "ls -l /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /usr/local/apache*/conf/httpd.conf 2>/dev/null"
        })

    # Apache 프로세스 실행 여부 확인 (참고용)
    apache_ps = run_shell("ps -ef | grep -E '[h]ttpd|[a]pache2' | grep -v grep")

    check_results.append({
        "sub_check": "Apache 웹 서비스 실행 현황",
        "config_file": "Apache process",
        "collected_value": "Apache is RUNNING" if apache_ps else "Apache is NOT RUNNING",
        "raw_output": apache_ps if apache_ps else "No Apache process",
        "service_status": "RUNNING" if apache_ps else "NOT_RUNNING",
        "source_command": "ps -ef | grep -E '[h]ttpd|[a]pache2'"
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
                "item_code": "U-71",
                "item_name": "Apache 웹 서비스 정보 숨김",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
