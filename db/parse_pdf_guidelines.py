#!/usr/bin/env python3
"""
parse_pdf_guidelines.py
-----------------------
주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 PDF를
파싱하여 guidelines.db에 저장합니다.

실행:
    python3 db/parse_pdf_guidelines.py
    python3 db/parse_pdf_guidelines.py --pdf /path/to/guide.pdf
"""

import argparse
import re
import sqlite3
import sys
from pathlib import Path

try:
    import fitz  # pymupdf
except ImportError:
    sys.exit("pymupdf가 설치되어 있지 않습니다: pip install pymupdf")

DEFAULT_PDF = Path(__file__).parent.parent / "주요정보통신기반시설_기술적_취약점_분석_평가_방법_상세가이드.pdf"
DB_PATH = Path(__file__).parent / "guidelines.db"

# ──────────────────────────────────────────────────────────
# 스키마
# ──────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS guidelines (
    item_code     TEXT PRIMARY KEY,
    item_name     TEXT,
    category      TEXT,
    content       TEXT,
    check_point   TEXT,
    standard      TEXT,
    severity      TEXT,
    vuln_keywords TEXT,
    ok_keywords   TEXT,
    remediation   TEXT
);
"""


# ──────────────────────────────────────────────────────────
# PDF에서 Unix 서버 U-XX 항목 페이지 범위 수집
# ──────────────────────────────────────────────────────────

def collect_item_pages(doc) -> list[dict]:
    """
    U-XX 항목의 시작 페이지를 찾고 범위를 반환.
    반환: [{"code": "U-01", "severity": "상", "start": 12, "end": 16}, ...]  (0-indexed)
    """
    items = []
    PATTERN = re.compile(r'U-(\d+)\s*[（(]\s*([상중하])\s*[)）]')

    for i in range(len(doc)):
        t = doc[i].get_text()
        m = PATTERN.search(t)
        if m and '점검내용' in t:
            items.append({
                "code": f"U-{int(m.group(1)):02d}",
                "severity": m.group(2),
                "start": i,
            })

    # end 범위: 다음 항목 시작 전까지
    for idx in range(len(items) - 1):
        items[idx]["end"] = items[idx + 1]["start"]
    if items:
        items[-1]["end"] = items[-1]["start"] + 6  # 마지막 항목은 최대 6페이지

    return items


# ──────────────────────────────────────────────────────────
# 텍스트 추출 헬퍼
# ──────────────────────────────────────────────────────────

def _extract_section(text: str, start_kw: str, end_kws: list[str]) -> str:
    """start_kw 이후 ~ end_kws 중 하나 이전 텍스트 반환."""
    idx = text.find(start_kw)
    if idx == -1:
        return ""
    snippet = text[idx + len(start_kw):]
    for ew in end_kws:
        ei = snippet.find(ew)
        if ei != -1:
            snippet = snippet[:ei]
    return snippet.strip()


def _clean(s: str) -> str:
    # 제어문자 제거
    s = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', s)
    s = re.sub(r'\s+', ' ', s).strip()
    s = re.sub(r'주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드', '', s)
    s = re.sub(r'01\. Unix 서버 보안', '', s)
    s = re.sub(r'UNIX 서버\s*U-\d+\s*[（(][상중하][)）]', '', s)
    return s.strip()


def _gen_keywords(full_text: str, standard_text: str) -> tuple[str, str]:
    """
    점검 사례(OS별 설정값 예시)에서 취약/양호 키워드 추출.
    수정 전(취약) → 수정 후(양호) 패턴을 우선 파싱하고,
    없으면 full_text의 설정값 패턴에서 보완.
    """
    # 수정 전/후 패턴 (취약→양호 방향)
    before_vals, after_vals = [], []
    for m in re.finditer(r'수정\s*전\s*[）)]\s*#?([^\n]+)', full_text):
        before_vals.append(m.group(1).strip().lower())
    for m in re.finditer(r'수정\s*후\s*[）)]\s*([^\n]+)', full_text):
        after_vals.append(m.group(1).strip().lower())

    # key=value (설정 파일 예시): PermitRootLogin no, deny=5 등
    # 양호: 보안이 강화된 값 (no, false, 낮은 숫자 등)
    kv_all = re.findall(r'([A-Za-z_][A-Za-z0-9_]{3,})\s*[= ]\s*(\S+)', full_text)
    kv_vuln, kv_ok = [], []
    VULN_VALS = {'yes', 'true', '1', 'enable', 'on', 'allow', 'any'}
    OK_VALS   = {'no', 'false', '0', 'disable', 'off', 'deny', 'none', 'prohibit-password'}
    for key, val in kv_all:
        kw = f"{key.lower()} {val.lower()}"
        if val.lower() in VULN_VALS:
            kv_vuln.append(kw)
        elif val.lower() in OK_VALS:
            kv_ok.append(kw)

    vuln_kws = list(dict.fromkeys(before_vals + kv_vuln))[:6]
    ok_kws   = list(dict.fromkeys(after_vals  + kv_ok))[:6]

    return ",".join(vuln_kws), ",".join(ok_kws)


# ──────────────────────────────────────────────────────────
# 항목별 파싱
# ──────────────────────────────────────────────────────────

def parse_item(doc, info: dict) -> dict:
    # 모든 관련 페이지 텍스트 합치기
    full_text = ""
    for pg in range(info["start"], min(info["end"], len(doc))):
        full_text += "\n" + doc[pg].get_text()

    # 카테고리 & 항목명
    cat_m = re.search(r'(\d+)\.\s*([\w\s및디렉토리]+?)\s*>\s*[\d\.]+\s*(.+?)(?:\n|$)', full_text)
    category  = cat_m.group(2).strip() if cat_m else "기타"
    item_name = cat_m.group(3).strip() if cat_m else info["code"]
    # 항목명 정제: 불필요한 수식어 제거
    item_name = re.sub(r'\s+', ' ', item_name).strip()

    # 점검내용 (핵심 1~2문장만)
    content_raw = _extract_section(full_text, "점검내용", ["점검목적", "보안위협", "참고"])
    content = _clean(content_raw)[:200]

    # 판단기준
    standard_raw = _extract_section(full_text, "판단기준\n양호", ["조치방법", "점검 및 조치"])
    if not standard_raw:
        standard_raw = _extract_section(full_text, "판단기준\n양호", ["OS별 점검"])
    # 두 번째 "판단기준" 이후 찾기 (첫 번째는 "점검대상 및 판단기준" 제목)
    standard_blocks = re.findall(r'(?:양호\s*:.*?)(?=조치방법|점검 및 조치|OS별|$)', full_text, re.DOTALL)
    standard = ""
    for blk in standard_blocks:
        if '취약' in blk or '양호' in blk:
            standard = _clean(blk)[:300]
            break
    if not standard:
        standard = _clean(standard_raw)[:300]

    # 조치방법 (핵심만)
    remediation_raw = _extract_section(full_text, "조치방법\n", ["점검 및 조치사례", "OS별 점검"])
    remediation = _clean(remediation_raw)[:200]

    # 점검방법 요약 (OS별 점검 파일 첫 번째 섹션만)
    check_raw = _extract_section(full_text, "OS별 점검 파일", ["■", "위에 제시한", "Step 1"])
    check_point = _clean(check_raw)[:300]

    vuln_kws, ok_kws = _gen_keywords(full_text, standard)

    return {
        "item_code":     info["code"],
        "item_name":     item_name,
        "category":      category,
        "content":       content,
        "check_point":   check_point,
        "standard":      standard,
        "severity":      info["severity"],
        "vuln_keywords": vuln_kws,
        "ok_keywords":   ok_kws,
        "remediation":   remediation,
    }


# ──────────────────────────────────────────────────────────
# DB 저장
# ──────────────────────────────────────────────────────────

def save_to_db(records: list[dict], db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(DDL)
    inserted = updated = 0
    for r in records:
        existing = conn.execute(
            "SELECT item_code FROM guidelines WHERE item_code = ?", (r["item_code"],)
        ).fetchone()
        if existing:
            conn.execute("""
                UPDATE guidelines SET
                    item_name=?, category=?, content=?, check_point=?,
                    standard=?, severity=?, vuln_keywords=?, ok_keywords=?, remediation=?
                WHERE item_code=?
            """, (r["item_name"], r["category"], r["content"], r["check_point"],
                  r["standard"], r["severity"], r["vuln_keywords"], r["ok_keywords"],
                  r["remediation"], r["item_code"]))
            updated += 1
        else:
            conn.execute("""
                INSERT INTO guidelines
                    (item_code,item_name,category,content,check_point,standard,
                     severity,vuln_keywords,ok_keywords,remediation)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (r["item_code"], r["item_name"], r["category"], r["content"],
                  r["check_point"], r["standard"], r["severity"],
                  r["vuln_keywords"], r["ok_keywords"], r["remediation"]))
            inserted += 1
    conn.commit()
    conn.close()
    print(f"[DB] 저장 완료: 신규={inserted} 업데이트={updated} (총 {len(records)}건)")


# ──────────────────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="주통기 PDF → guidelines.db 저장")
    parser.add_argument("--pdf", default=str(DEFAULT_PDF), help="PDF 파일 경로")
    parser.add_argument("--db", default=str(DB_PATH), help="DB 파일 경로")
    parser.add_argument("--dry-run", action="store_true", help="DB 저장 없이 파싱 결과만 출력")
    args = parser.parse_args()

    pdf_path = Path(args.pdf)
    if not pdf_path.exists():
        sys.exit(f"PDF 파일 없음: {pdf_path}")

    print(f"[Parser] PDF 열기: {pdf_path.name}")
    doc = fitz.open(str(pdf_path))
    print(f"[Parser] 총 {len(doc)}페이지")

    items_info = collect_item_pages(doc)
    # 중복 코드 제거 (같은 item_code가 두 번 나오면 첫 번째만 사용)
    seen_codes: set[str] = set()
    deduped = []
    for info in items_info:
        if info["code"] not in seen_codes:
            seen_codes.add(info["code"])
            deduped.append(info)
    items_info = deduped
    print(f"[Parser] Unix 서버 항목 발견: {len(items_info)}개")

    records = []
    for info in items_info:
        rec = parse_item(doc, info)
        records.append(rec)
        print(f"  {rec['item_code']} ({rec['severity']}) {rec['item_name'][:35]}")

    if args.dry_run:
        import json
        print("\n[Dry-run] 첫 3건 결과:")
        for r in records[:3]:
            print(json.dumps(r, ensure_ascii=False, indent=2))
        return

    save_to_db(records, Path(args.db))
    print(f"\n[완료] {args.db} 에 {len(records)}개 항목 저장됨")


if __name__ == "__main__":
    main()
