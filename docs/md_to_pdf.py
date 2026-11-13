"""paper_beta.md → PDF 변환 (reportlab + 맑은 고딕).

작성자 가이드 섹션 (분량 검증 / TBD 채우기 작업) 은 자동 제외.
한국 학회 KIITI 양식 비슷한 모양 (단일 칼럼, A4, 한글 본문 9.5pt).
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)


# ── 한글 폰트 등록 (맑은 고딕) ──────────────────────────────
FONT_DIR = Path("C:/Windows/Fonts")
pdfmetrics.registerFont(TTFont("Malgun", str(FONT_DIR / "malgun.ttf")))
pdfmetrics.registerFont(TTFont("MalgunBd", str(FONT_DIR / "malgunbd.ttf")))


# ── 스타일 ─────────────────────────────────────────────────
styles = {
    "title_kr": ParagraphStyle(
        "title_kr", fontName="MalgunBd", fontSize=15, leading=20,
        spaceBefore=8, spaceAfter=8, alignment=0,
    ),
    "title_en": ParagraphStyle(
        "title_en", fontName="MalgunBd", fontSize=12, leading=16,
        spaceBefore=4, spaceAfter=8, alignment=0,
    ),
    "authors": ParagraphStyle(
        "authors", fontName="Malgun", fontSize=9.5, leading=13,
        spaceAfter=2, alignment=0,
    ),
    "affil": ParagraphStyle(
        "affil", fontName="Malgun", fontSize=8.5, leading=11,
        spaceAfter=2, alignment=0,
    ),
    "meta": ParagraphStyle(
        "meta", fontName="Malgun", fontSize=8.5, leading=11,
        spaceBefore=4, spaceAfter=4, alignment=0, textColor=colors.grey,
    ),
    "abstract_label": ParagraphStyle(
        "abstract_label", fontName="MalgunBd", fontSize=10, leading=14,
        spaceBefore=8, spaceAfter=4,
    ),
    "abstract": ParagraphStyle(
        "abstract", fontName="Malgun", fontSize=9.3, leading=13,
        spaceAfter=4, alignment=4,
    ),
    "abstract_en": ParagraphStyle(
        "abstract_en", fontName="Malgun", fontSize=9.3, leading=12.5,
        spaceAfter=4, alignment=4,
    ),
    "keywords": ParagraphStyle(
        "keywords", fontName="MalgunBd", fontSize=9.3, leading=13,
        spaceBefore=4, spaceAfter=8, alignment=0,
    ),
    "h1": ParagraphStyle(
        "h1", fontName="MalgunBd", fontSize=11, leading=14,
        spaceBefore=6, spaceAfter=3,
    ),
    "h2": ParagraphStyle(
        "h2", fontName="MalgunBd", fontSize=10, leading=13,
        spaceBefore=4, spaceAfter=2,
    ),
    "body": ParagraphStyle(
        "body", fontName="Malgun", fontSize=9.5, leading=12.8,
        spaceAfter=4, alignment=4,
    ),
    "figure_box": ParagraphStyle(
        "figure_box", fontName="Malgun", fontSize=8.5, leading=12,
        spaceBefore=4, spaceAfter=4, alignment=1,  # center
        textColor=colors.grey,
    ),
    "table_caption": ParagraphStyle(
        "table_caption", fontName="MalgunBd", fontSize=9, leading=12,
        spaceBefore=4, spaceAfter=4,
    ),
    "ref": ParagraphStyle(
        "ref", fontName="Malgun", fontSize=9, leading=12,
        spaceAfter=2, leftIndent=14, firstLineIndent=-14,
    ),
}


def md_inline(text: str) -> str:
    """Markdown 인라인 → reportlab HTML 변환."""
    # 백틱 코드 → 회색
    text = re.sub(r"`([^`]+?)`", r'<font face="Malgun" color="#444"><b>\1</b></font>', text)
    # **bold**
    text = re.sub(r"\*\*([^*]+?)\*\*", r"<b>\1</b>", text)
    # *italic*
    text = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", r"<i>\1</i>", text)
    # 링크 [text](url) → text
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
    return text


def parse_table(lines: list[str], start: int) -> tuple[list[list[str]], int]:
    """Markdown 표 파싱. (rows, end_index)."""
    rows = []
    i = start
    while i < len(lines):
        line = lines[i].strip()
        if not line.startswith("|"):
            break
        # 구분자 행 (---|---) 건너뛰기
        cells = [c.strip() for c in line.strip("|").split("|")]
        if all(re.fullmatch(r":?-+:?", c) for c in cells if c):
            i += 1
            continue
        rows.append(cells)
        i += 1
    return rows, i


def main():
    # CLI 인자 — 옵션. python md_to_pdf.py [--loose] [--dst FILE]
    args = sys.argv[1:]
    loose = "--loose" in args
    dst_name = "paper_beta.pdf"
    src_name = "paper_beta.md"
    if "--dst" in args:
        idx = args.index("--dst")
        dst_name = args[idx + 1]
    if "--src" in args:
        idx = args.index("--src")
        src_name = args[idx + 1]

    src = Path(__file__).parent / src_name
    dst = Path(__file__).parent / dst_name

    # loose 모드: 학회 양식보다 넉넉한 여백·줄간격 (3페이지 분량용)
    if loose:
        styles["body"].leading = 15
        styles["body"].spaceAfter = 7
        styles["abstract"].leading = 16
        styles["abstract_en"].leading = 15
        styles["h1"].spaceBefore = 12
        styles["h1"].spaceAfter = 7
        styles["h2"].spaceBefore = 8
        styles["h2"].spaceAfter = 5
    text = src.read_text(encoding="utf-8")
    lines = text.split("\n")

    elements: list = []
    skip_section = False
    skip_header = False  # 표지 metadata (저자·소속·영문 제목·교신·투고일) PDF 제외
    in_blockquote = False
    blockquote_buf: list[str] = []

    def flush_blockquote():
        nonlocal blockquote_buf
        if blockquote_buf:
            content = "<br/>".join(md_inline(t) for t in blockquote_buf if t)
            elements.append(Paragraph(content, styles["figure_box"]))
            blockquote_buf = []

    title_seen = 0  # 0=한글 제목, 1=영문 제목 후
    abstract_state = 0  # 0=전, 1=한글 abstract, 2=영문 abstract
    keywords_seen = False
    in_authors = False
    author_lines: list[str] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # 작성자 가이드 섹션 skip
        if stripped.startswith("## 분량 검증") or stripped.startswith("## TBD 채우기"):
            skip_section = True
            i += 1
            continue
        if skip_section:
            if stripped.startswith("## ") and "분량" not in stripped and "TBD" not in stripped:
                skip_section = False
            else:
                i += 1
                continue

        # 표지 metadata skip (저자·소속·영문 제목·교신·투고일) — ABSTRACT 전까지
        if skip_header:
            if stripped == "## ABSTRACT":
                skip_header = False
                # ABSTRACT 헤더는 정상 처리 (fallthrough)
            else:
                i += 1
                continue

        # 수평선
        if stripped == "---":
            flush_blockquote()
            elements.append(Spacer(1, 4 * mm))
            i += 1
            continue

        # blockquote — 양식 가이드 (이탤릭 안내) 는 PDF 에서 제외
        if stripped.startswith(">"):
            content = stripped.lstrip("> ").strip()
            # 양식 안내 (`*(한글 요약 — ...)*` 같은 이탤릭) 는 인쇄 X
            is_format_hint = (
                content.startswith("*(") and content.endswith(")*")
            ) or content.startswith("*(한글 요약") or content.startswith("*(영문 요약")
            if not is_format_hint:
                blockquote_buf.append(content)
            i += 1
            continue
        else:
            flush_blockquote()

        # 헤더
        if stripped.startswith("# "):
            text_only = stripped[2:].strip()
            elements.append(Paragraph(md_inline(text_only), styles["title_kr"]))
            title_seen = 0
            skip_header = True  # 한글 제목 이후 ABSTRACT 까지 스킵
            i += 1
            continue

        if stripped.startswith("## "):
            text_only = stripped[3:].strip()
            # 영문 제목 식별
            if re.search(r"[A-Za-z]{4,}", text_only) and not text_only.startswith(
                ("ABSTRACT", "References", "참고", "결론", "비교", "시스템", "서론")
            ) and title_seen == 0:
                # 영문 제목
                elements.append(Paragraph(md_inline(text_only), styles["title_en"]))
                title_seen = 1
                in_authors = True
                i += 1
                continue
            # ABSTRACT
            if text_only == "ABSTRACT":
                elements.append(Paragraph("ABSTRACT", styles["abstract_label"]))
                abstract_state = 1
                in_authors = False
                i += 1
                continue
            # 일반 섹션 헤더
            elements.append(Paragraph(md_inline(text_only), styles["h1"]))
            in_authors = False
            i += 1
            continue

        if stripped.startswith("### "):
            text_only = stripped[4:].strip()
            elements.append(Paragraph(md_inline(text_only), styles["h2"]))
            i += 1
            continue

        # 표
        if stripped.startswith("|"):
            rows, end = parse_table(lines, i)
            if rows:
                # 컬럼 폭: 본문 영역 (A4 폭 - 좌우 마진 44mm = 약 166mm) 균등 분배
                ncols = len(rows[0])
                avail_width = 166 * mm
                col_widths = [avail_width / ncols] * ncols
                # 첫 컬럼이 라벨 성격이면 약간 좁게
                if ncols >= 3:
                    col_widths[0] = avail_width * 0.30
                    rest = (avail_width - col_widths[0]) / (ncols - 1)
                    for k in range(1, ncols):
                        col_widths[k] = rest

                tbl_data = [[Paragraph(md_inline(c), styles["body"]) for c in row] for row in rows]
                tbl = Table(tbl_data, hAlign="CENTER", colWidths=col_widths)
                tbl.setStyle(TableStyle([
                    ("FONT", (0, 0), (-1, -1), "Malgun", 9),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                elements.append(tbl)
                elements.append(Spacer(1, 4 * mm))
            i = end
            continue

        # 빈 줄
        if not stripped:
            if in_authors and author_lines:
                # 저자 그룹 종료
                for al in author_lines:
                    style = styles["affil"] if al.startswith(("¹", "²", "³")) else styles["authors"]
                    elements.append(Paragraph(md_inline(al), style))
                author_lines = []
            i += 1
            continue

        # 저자/소속 영역
        if in_authors:
            author_lines.append(stripped)
            i += 1
            continue

        # ABSTRACT 본문
        if abstract_state == 1:
            elements.append(Paragraph(md_inline(stripped), styles["abstract"]))
            abstract_state = 2
            i += 1
            continue
        if abstract_state == 2:
            if stripped.startswith("**Keywords"):
                elements.append(Paragraph(md_inline(stripped), styles["keywords"]))
                abstract_state = 0
                keywords_seen = True
                i += 1
                continue
            elements.append(Paragraph(md_inline(stripped), styles["abstract_en"]))
            i += 1
            continue

        # 참고문헌 항목
        if re.match(r"^\[\d+\]", stripped):
            elements.append(Paragraph(md_inline(stripped), styles["ref"]))
            i += 1
            continue

        # 일반 본문
        elements.append(Paragraph(md_inline(stripped), styles["body"]))
        i += 1

    # 마무리 저자 라인 비우기
    if author_lines:
        for al in author_lines:
            style = styles["affil"] if al.startswith(("¹", "²", "³")) else styles["authors"]
            elements.append(Paragraph(md_inline(al), style))

    # PDF 생성
    margin_lr = 25 * mm if loose else 16 * mm
    margin_tb = 22 * mm if loose else 11 * mm
    doc = SimpleDocTemplate(
        str(dst), pagesize=A4,
        leftMargin=margin_lr, rightMargin=margin_lr,
        topMargin=margin_tb, bottomMargin=margin_tb,
        title="주통기 취약점 자동 진단 시스템",
        author="강지혁, 고은이, 이서연, 백서진, 양환석",
    )
    doc.build(elements)
    print(f"OK: {dst} ({dst.stat().st_size:,} bytes)")


if __name__ == "__main__":
    sys.exit(main() or 0)
