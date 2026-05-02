#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-03 계정 잠금 임계값 설정 점검 스크립트
- Linux, Solaris, AIX, HP-UX 모두 지원
- JSON 파일 자동 저장 + 환경변수로 출력 경로 제어 가능
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u03_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except subprocess.TimeoutExpired:
        return "ERROR: Command timeout"
    except Exception as e:
        return f"ERROR: {str(e)}"


def get_os_info() -> tuple:
    """OS 정보 반환 (Debian/Ubuntu 구분 포함)"""
    system = platform.system().lower()
    
    if system == "linux":
        os_type = "linux"
        os_name = "Linux"
        family = "redhat"

        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", encoding="utf-8") as f:
                    content = f.read().lower()
                    if "ubuntu" in content or "debian" in content:
                        os_name = "Debian/Ubuntu"
                        family = "debian"
                    elif any(x in content for x in ["rhel", "centos", "fedora", "red hat"]):
                        os_name = "RHEL/CentOS"
                        family = "redhat"
            except:
                pass
        return os_type, os_name, family

    elif system == "sunos":
        return "solaris", "Solaris", "solaris"
    elif system == "aix":
        return "aix", "AIX", "aix"
    elif system == "hp-ux":
        return "hpux", "HP-UX", "hpux"
    else:
        return system, system.capitalize(), system


def check_file_content(filepath: str) -> tuple:
    """파일 존재 여부와 전체 내용 반환"""
    if not os.path.exists(filepath):
        return "파일 없음", f"{filepath} 파일이 존재하지 않음"
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return "파일 존재", content
    except PermissionError:
        return "권한 없음", f"{filepath} 파일 읽기 권한 없음"
    except Exception as e:
        return "오류", str(e)


def extract_keyword_with_cmd(content: str, keyword: str, filepath: str) -> tuple:
    """키워드 추출 + 실제 사용된 grep 명령어 반환"""
    if not content or "파일" in content[:30]:
        return "설정 없음", f"cat {filepath}"
    
    grep_cmd = f"grep -iE '{keyword}' {filepath}"
    
    pattern = re.compile(rf'^.*{re.escape(keyword)}.*$', re.IGNORECASE | re.MULTILINE)
    matches = pattern.findall(content)
    
    if matches:
        collected = " | ".join(line.strip() for line in matches if line.strip())
    else:
        collected = f"{keyword} 설정 없음"
    
    return collected, grep_cmd


def save_json(result: Dict, output_dir: str, filename: str):
    """JSON 파일로 저장"""
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        print(f"[+] U-03 결과가 저장되었습니다: {filepath}")
        return True
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")
        return False


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name, os_family = get_os_info()

    # ==================== U-03 OS별 점검 정의 ====================
    os_checks: Dict[str, List[tuple]] = {
        "linux": [
            ("PAM system-auth / common-auth", "/etc/pam.d/system-auth", "pam_tally|pam_tally2|pam_faillock|deny=", "login"),
            ("PAM common-auth (Debian/Ubuntu)", "/etc/pam.d/common-auth", "pam_tally|pam_tally2|pam_faillock|deny=", "login"),
            ("PAM common-password (Debian/Ubuntu)", "/etc/pam.d/common-password", "pam_tally|pam_tally2|pam_faillock", "login"),
        ],
        "solaris": [
            ("default/login (RETRIES)", "/etc/default/login", "RETRIES", "login"),
            ("policy.conf (LOCK_AFTER_RETRIES)", "/etc/security/policy.conf", "LOCK_AFTER_RETRIES", "login"),
        ],
        "aix": [
            ("security/user (loginretries)", "/etc/security/user", "loginretries", "login"),
        ],
        "hpux": [
            ("tcb/files/auth/system/default (u_maxtries)", "/tcb/files/auth/system/default", "u_maxtries", "login"),
            ("default/security (AUTH_MAXTRIES)", "/etc/default/security", "AUTH_MAXTRIES", "login"),
        ]
    }

    checks = os_checks.get(target_os, [])

    check_results: List[Dict[str, Any]] = []

    for sub_check, config_file, keyword, svc in checks:
        # 서비스 상태 판단 (Linux는 login 관련, 다른 OS는 간단히)
        if target_os == "linux":
            installed = "INSTALLED" if run_shell("command -v login >/dev/null 2>&1 && echo 1 || echo 0") else "NOT_INSTALLED"
            service_status = f"{installed}, UNKNOWN" if installed == "INSTALLED" else "NOT_INSTALLED"
        else:
            service_status = "UNKNOWN"

        # 파일 내용 가져오기
        file_status, raw_output = check_file_content(config_file)
        
        # collected_value + 실제 grep 명령어
        if "파일 존재" in file_status:
            collected_value, source_command = extract_keyword_with_cmd(raw_output, keyword, config_file)
        else:
            collected_value = f"{file_status} ({config_file})"
            source_command = f"cat {config_file}"

        check_results.append({
            "sub_check": sub_check,
            "config_file": config_file,
            "collected_value": collected_value,
            "raw_output": ("" if os.getenv("COMPACT_OUTPUT","0")=="1" else (raw_output if "파일 존재" in file_status else f"{config_file} 파일이 존재하지 않음")),
            "service_status": service_status,
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
                "category": "계정관리",
                "item_code": "U-03",
                "item_name": "계정 잠금 임계값 설정",
                "check_results": check_results
            }
        ]
    }

    # 화면에 출력
    print(json.dumps(result, ensure_ascii=False, indent=2))

    # JSON 파일 저장
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
