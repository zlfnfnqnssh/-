#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-05 root PATH 환경변수 점검 스크립트
- collected_value는 판단 문구 없이 순수 파싱 결과만 저장
- echo $PATH 결과를 별도 항목으로 추가
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u05_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except:
        return ""


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


def extract_keyword_with_cmd(content: str, keyword: str, filepath: str) -> tuple:
    """순수 파싱: keyword 관련 라인만 추출"""
    if not content:
        return "설정 없음", f"cat {filepath}"
    
    pattern = re.compile(rf'^.*{re.escape(keyword)}.*$', re.IGNORECASE | re.MULTILINE)
    matches = pattern.findall(content)
    
    if matches:
        collected = " | ".join(line.strip() for line in matches if line.strip())
    else:
        collected = f"{keyword} 설정 없음"
    
    return collected, f"grep -iE '{keyword}' {filepath}"


def save_json(result: Dict, output_dir: str, filename: str):
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[+] U-05 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== 1. echo $PATH (순수 값만 저장) ====================
    path_value = run_shell("'echo $PATH' 2>/dev/null || echo $PATH")

    check_results.append({
        "sub_check": "root echo $PATH",
        "config_file": "root $PATH",
        "collected_value": path_value,                    # ← 판단 문구 없이 실제 PATH 값 그대로
        "raw_output": path_value,
        "service_status": "N/A",
        "source_command": "echo $PATH"
    })

    # ==================== 2. 주요 환경설정 파일 점검 ====================
    env_files = [
        "/etc/profile",
        "/root/.profile",
        "/root/.bash_profile",
        "/root/.bashrc",
        "/root/.cshrc",
        "/root/.login",
    ]

    for filepath in env_files:
        if not os.path.exists(filepath):
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                raw_output = f.read()
        except Exception:
            raw_output = "파일 읽기 실패"

        # PATH 관련 라인만 단순 파싱
        collected_value, source_command = extract_keyword_with_cmd(raw_output, "PATH", filepath)

        check_results.append({
            "sub_check": f"설정 파일 ({os.path.basename(filepath)})",
            "config_file": filepath,
            "collected_value": collected_value,          # 판단 문구 없음, 순수 파싱 결과만
            "raw_output": raw_output,
            "service_status": "N/A",
            "source_command": source_command
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
                "item_code": "U-05",
                "item_name": "root홈, 패스 디렉터리 권한 및 패스 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
