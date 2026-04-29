from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Optional

import pdfplumber

logger = logging.getLogger(__name__)

ITEM_HDR_RE = re.compile(r"^([A-Z]{1,4})-(\d{2,3})\s+(.+)$")
SEVERITY_RE = re.compile(r"^\(([상중하])\)\s*(.+)$")
GOOD_RE = re.compile(r"^양호\s*:\s*(.+)$")
BAD_RE = re.compile(r"^취약\s*:\s*(.+)$")

FIELD_KEYS = [
    "점검 내용",
    "점검 목적",
    "보안 위협",
    "참고",
    "대상",
    "판단 기준",
    "조치 방법",
    "조치 시 영향",
]

_FIELD_KEY_RE = re.compile(r"^(" + "|".join(re.escape(k) for k in FIELD_KEYS) + r")\s*(.*)?$")
END_SECTION_RE = re.compile(r"^점검\s*및\s*조치\s*사례")

NOISE_RE = re.compile(
    r"^(\|?\s*한국인터넷진흥원\s*\|?"
    r"|주요정보통신기반시설.*가이드"
    r"|\d{2,3}\.\s*(Unix|Windows|DBMS|네트워크|보안|가상화|웹|클라우드|PC|이동|제어)"
    r"|\d+$"
    r"|개요$"
    r"|점검\s*대상\s*및\s*판단\s*기준$"
    r"|2026$|2025$"
    r")"
)

PREFIX_MAP: dict[str, tuple[str, str, str]] = {
    "U": ("UNIX", "Unix 서버", "linux"),
    "W": ("Windows", "Windows 서버", "windows"),
    "D": ("DBMS", "DBMS", "other"),
    "N": ("네트워크 장비", "네트워크 장비", "other"),
    "S": ("보안 장비", "보안 장비", "other"),
    "WEB": ("웹 서비스", "웹 서비스", "other"),
    "HV": ("가상화 장비", "가상화 장비", "other"),
    "PC": ("PC", "PC", "other"),
    "CA": ("클라우드", "클라우드", "other"),
    "C": ("제어시스템", "제어시스템", "other"),
    "M": ("이동통신", "이동통신", "other"),
}

KEY_TO_FIELD: dict[str, str] = {
    "점검 내용": "check_content",
    "점검 목적": "check_purpose",
    "보안 위협": "security_threat",
    "참고": "note",
    "대상": "target",
    "판단 기준": "_판단기준_sentinel",
    "조치 방법": "action",
    "조치 시 영향": "action_impact",
}


def _is_noise(line: str) -> bool:
    return bool(NOISE_RE.match(line.strip()))


def _parse_field_key(line: str) -> tuple[Optional[str], str]:
    m = _FIELD_KEY_RE.match(line.strip())
    if m:
        return m.group(1), (m.group(2) or "").strip()
    return None, line.strip()


def _extract_category(breadcrumb: str) -> str:
    parts = breadcrumb.split(">")
    raw = parts[-1].strip() if len(parts) > 1 else breadcrumb.strip()
    return re.sub(r"^\d+\.\s*", "", raw)


def _extract_pdf_version(text: str) -> str:
    m = re.search(r"\b(20\d{2})\b", text)
    return m.group(1) if m else ""


def _compute_hash(item: dict) -> str:
    fields = [
        "title",
        "check_content",
        "check_purpose",
        "security_threat",
        "criteria_good",
        "criteria_bad",
        "action",
        "action_impact",
        "target",
    ]
    raw = "|".join(item.get(k, "") for k in fields)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _finalize(item: dict) -> dict:
    item["criteria_good"] = item.pop("_criteria_good", "")
    item["criteria_bad"] = item.pop("_criteria_bad", "")
    item["content_hash"] = _compute_hash(item)
    return item


class JutonggiParser:
    def __init__(self, pdf_path: str | Path):
        self.pdf_path = Path(pdf_path)
        self._items: list[dict] = []
        self._pdf_version: str = ""

    def parse(self) -> list[dict]:
        logger.info("[Parser] 파싱 시작: %s", self.pdf_path)
        self._items = self._run()
        logger.info("[Parser] 총 %s개 항목 추출 완료", len(self._items))
        return self._items

    def save(self, output_path: str | Path = "parsed_items.json") -> Path:
        if not self._items:
            raise RuntimeError("parse()를 먼저 호출하세요.")
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self._items, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("[Parser] 저장 완료: %s", out)
        return out

    def stats(self) -> dict:
        if not self._items:
            return {}
        from collections import Counter

        empty: dict[str, int] = {}
        check_fields = [
            "title",
            "check_content",
            "check_purpose",
            "security_threat",
            "criteria_good",
            "criteria_bad",
            "action",
            "action_impact",
        ]
        for field in check_fields:
            empty[field] = sum(1 for i in self._items if not i.get(field))
        return {
            "total": len(self._items),
            "pdf_version": self._pdf_version,
            "by_prefix": dict(Counter(i["prefix"] for i in self._items)),
            "by_os": dict(Counter(i["os_type"] for i in self._items)),
            "by_severity": dict(Counter(i["severity"] for i in self._items)),
            "empty_fields": empty,
        }

    def _run(self) -> list[dict]:
        items: list[dict] = []
        current: Optional[dict] = None
        active_field: Optional[str] = None
        pending_lines: list[str] = []
        skip_section = False

        def _flush_pending(field: str) -> None:
            if pending_lines and current is not None and field:
                pre = " ".join(pending_lines)
                existing = current.get(field, "")
                current[field] = (pre + " " + existing).strip() if existing else pre
            pending_lines.clear()

        def _append(field: str, text: str) -> None:
            if current is None or not field:
                return
            existing = current.get(field, "")
            current[field] = (existing + " " + text).strip() if existing else text

        with pdfplumber.open(self.pdf_path) as pdf:
            for page in pdf.pages[:5]:
                version = _extract_pdf_version(page.extract_text() or "")
                if version:
                    self._pdf_version = version
                    break

            for page_num, page in enumerate(pdf.pages, start=1):
                raw_text = page.extract_text()
                if not raw_text:
                    continue

                for line in raw_text.split("\n"):
                    stripped = line.strip()
                    if not stripped:
                        continue

                    hdr = ITEM_HDR_RE.match(stripped)
                    if hdr:
                        if current:
                            if active_field:
                                _flush_pending(active_field)
                            items.append(_finalize(current))

                        prefix = hdr.group(1)
                        domain, domain_name, os_type = PREFIX_MAP.get(prefix, (prefix, prefix, "other"))
                        current = {
                            "code": f"{prefix}-{hdr.group(2)}",
                            "prefix": prefix,
                            "domain": domain,
                            "domain_name": domain_name,
                            "os_type": os_type,
                            "category": _extract_category(hdr.group(3)),
                            "severity": "",
                            "title": "",
                            "target": "",
                            "check_content": "",
                            "check_purpose": "",
                            "security_threat": "",
                            "note": "",
                            "_criteria_good": "",
                            "_criteria_bad": "",
                            "action": "",
                            "action_impact": "",
                            "page_start": page_num,
                            "pdf_version": self._pdf_version,
                        }
                        active_field = None
                        pending_lines = []
                        skip_section = False
                        continue

                    if current is None:
                        continue

                    sev = SEVERITY_RE.match(stripped)
                    if sev and not current["severity"]:
                        current["severity"] = sev.group(1)
                        current["title"] = sev.group(2).strip()
                        active_field = None
                        pending_lines = []
                        continue

                    if END_SECTION_RE.match(stripped):
                        if active_field:
                            _flush_pending(active_field)
                        skip_section = True
                        active_field = None
                        pending_lines = []
                        continue

                    if skip_section or _is_noise(stripped):
                        continue

                    gm = GOOD_RE.match(stripped)
                    if gm:
                        if active_field and active_field != "_criteria_good":
                            _flush_pending(active_field)
                        current["_criteria_good"] = gm.group(1).strip()
                        active_field = "_criteria_good"
                        pending_lines = []
                        continue

                    bm = BAD_RE.match(stripped)
                    if bm:
                        if active_field and active_field != "_criteria_bad":
                            _flush_pending(active_field)
                        current["_criteria_bad"] = bm.group(1).strip()
                        active_field = "_criteria_bad"
                        pending_lines = []
                        continue

                    field_key, remainder = _parse_field_key(stripped)
                    if field_key:
                        mapped = KEY_TO_FIELD.get(field_key)
                        if field_key == "판단 기준":
                            pending_lines = []
                            continue

                        if active_field:
                            _flush_pending(active_field)

                        active_field = mapped
                        if active_field and remainder:
                            _append(active_field, remainder)
                        elif not active_field:
                            pending_lines = []
                        continue

                    if active_field:
                        _flush_pending(active_field)
                        _append(active_field, stripped)
                    else:
                        pending_lines.append(stripped)

            if current:
                if active_field:
                    _flush_pending(active_field)
                items.append(_finalize(current))

        return items


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="주통기 PDF -> 구조화 JSON")
    parser.add_argument("pdf", help="PDF 파일 경로")
    parser.add_argument("-o", "--out", default="parsed_items.json", help="JSON 출력 경로")
    parser.add_argument("--filter-prefix", help="특정 prefix만 출력 (예: U, W)")
    parser.add_argument("--filter-severity", choices=["상", "중", "하"])
    return parser


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = _build_cli().parse_args()

    parser = JutonggiParser(args.pdf)
    items = parser.parse()
    if args.filter_prefix:
        items = [i for i in items if i["prefix"] == args.filter_prefix]
    if args.filter_severity:
        items = [i for i in items if i["severity"] == args.filter_severity]

    Path(args.out).write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

    stats = parser.stats()
    print(f"PDF 버전: {stats.get('pdf_version', '')}")
    print(f"총 항목 수: {len(items)}")
    print(f"출력 파일: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())