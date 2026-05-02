"""
시스템 구조도 PNG 생성 — 흑백 선화 스타일
주통기 취약점 진단 플랫폼 — 2026-1 캡스톤
"""
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle, Circle, Polygon, Arc, Ellipse

plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False

# ===== 색상 (흑백 + 미세 회색만) =====
BLACK = "#111111"
DARK  = "#333333"
GRAY  = "#888888"
LIGHT = "#CCCCCC"
BG    = "#FFFFFF"

fig, ax = plt.subplots(figsize=(16, 11))
ax.set_xlim(0, 160)
ax.set_ylim(0, 110)
ax.axis('off')
fig.patch.set_facecolor(BG)

# ===== 아이콘 그리기 함수 =====
def icon_document(ax, cx, cy, size=5, color=BLACK, lw=2.2):
    """문서 아이콘 (접힌 모서리 + 가로줄)"""
    w, h = size*0.78, size
    x, y = cx - w/2, cy - h/2
    fold = size * 0.22
    # 외곽 (접힌 모서리 제외하고 그리기)
    pts = [
        (x, y), (x, y+h), (x+w-fold, y+h),
        (x+w, y+h-fold), (x+w, y), (x, y),
    ]
    ax.plot([p[0] for p in pts], [p[1] for p in pts], color=color, lw=lw, solid_capstyle='round')
    # 접힌 부분
    ax.plot([x+w-fold, x+w-fold, x+w], [y+h, y+h-fold, y+h-fold], color=color, lw=lw, solid_capstyle='round')
    # 가로줄
    for i, frac in enumerate([0.7, 0.55, 0.4, 0.25]):
        ax.plot([x+w*0.18, x+w*0.82], [y+h*frac, y+h*frac], color=color, lw=lw*0.55)

def icon_code(ax, cx, cy, size=5, color=BLACK, lw=2.2):
    """코드 아이콘 (둥근 사각형 + </>)"""
    w, h = size*1.15, size*0.78
    rect = FancyBboxPatch((cx-w/2, cy-h/2), w, h,
                          boxstyle="round,pad=0.05,rounding_size=0.6",
                          fill=False, linewidth=lw, edgecolor=color)
    ax.add_patch(rect)
    ax.text(cx, cy, "</>", ha='center', va='center',
            fontsize=size*3.2, fontweight='bold', color=color, family='monospace')

def icon_user(ax, cx, cy, size=5, color=BLACK, lw=2.2):
    """사람 아이콘 (머리 원 + 어깨)"""
    head_r = size*0.18
    head_y = cy + size*0.25
    ax.add_patch(Circle((cx, head_y), head_r, fill=False, linewidth=lw, edgecolor=color))
    # 어깨 (반원)
    arc = Arc((cx, cy-size*0.05), size*0.9, size*0.7, angle=0,
              theta1=0, theta2=180, linewidth=lw, color=color)
    ax.add_patch(arc)

def icon_db(ax, cx, cy, size=5, color=BLACK, lw=2.2):
    """DB 아이콘 (원기둥 3단)"""
    w = size*0.9
    h_each = size*0.22
    total_h = size*0.9
    top_y = cy + total_h/2
    # 상단 타원
    ax.add_patch(Ellipse((cx, top_y), w, h_each, fill=False, linewidth=lw, edgecolor=color))
    # 하단 타원 (바닥)
    bot_y = cy - total_h/2
    ax.add_patch(Ellipse((cx, bot_y), w, h_each, fill=False, linewidth=lw, edgecolor=color))
    # 양쪽 측면
    ax.plot([cx-w/2, cx-w/2], [top_y, bot_y], color=color, lw=lw)
    ax.plot([cx+w/2, cx+w/2], [top_y, bot_y], color=color, lw=lw)
    # 중간 경계선 (타원 반쪽)
    for frac in [1/3, 2/3]:
        y = top_y - total_h*frac
        ax.add_patch(Arc((cx, y), w, h_each, angle=0,
                         theta1=180, theta2=360, linewidth=lw*0.7, color=color))

def icon_ai(ax, cx, cy, size=5, color=BLACK, lw=2.2):
    """AI/CPU 아이콘 (정사각형 + 핀 + 회로)"""
    side = size*0.7
    x, y = cx - side/2, cy - side/2
    ax.add_patch(Rectangle((x, y), side, side, fill=False, linewidth=lw, edgecolor=color))
    # 핀 4면
    pin_len = size*0.12
    for i in range(3):
        px = x + side*(0.25 + i*0.25)
        ax.plot([px, px], [y, y-pin_len], color=color, lw=lw*0.7)
        ax.plot([px, px], [y+side, y+side+pin_len], color=color, lw=lw*0.7)
        py = y + side*(0.25 + i*0.25)
        ax.plot([x, x-pin_len], [py, py], color=color, lw=lw*0.7)
        ax.plot([x+side, x+side+pin_len], [py, py], color=color, lw=lw*0.7)
    # 중앙 텍스트
    ax.text(cx, cy, "AI", ha='center', va='center',
            fontsize=size*1.9, fontweight='bold', color=color)

def icon_gear(ax, cx, cy, size=5, color=BLACK, lw=2.0):
    """톱니바퀴 (판정 엔진용)"""
    import numpy as np
    outer_r = size*0.42
    inner_r = size*0.32
    n_teeth = 8
    pts = []
    for i in range(n_teeth * 2):
        angle = 2*np.pi * i / (n_teeth*2)
        r = outer_r if i % 2 == 0 else inner_r
        pts.append((cx + r*np.cos(angle), cy + r*np.sin(angle)))
    ax.add_patch(Polygon(pts, fill=False, linewidth=lw, edgecolor=color, closed=True))
    # 가운데 구멍
    ax.add_patch(Circle((cx, cy), size*0.12, fill=False, linewidth=lw, edgecolor=color))

def icon_web(ax, cx, cy, size=5, color=BLACK, lw=2.2):
    """브라우저 창 아이콘"""
    w, h = size*1.1, size*0.78
    x, y = cx - w/2, cy - h/2
    ax.add_patch(Rectangle((x, y), w, h, fill=False, linewidth=lw, edgecolor=color))
    # 상단 바
    ax.plot([x, x+w], [y+h-size*0.15, y+h-size*0.15], color=color, lw=lw)
    # 버튼 3개
    for i in range(3):
        ax.add_patch(Circle((x + size*0.12 + i*size*0.12, y+h-size*0.075), size*0.035, fill=False, linewidth=lw*0.7, edgecolor=color))

# ===== 라벨 =====
def label(ax, cx, cy, text, size=10, bold=True, color=BLACK):
    ax.text(cx, cy, text, ha='center', va='center', fontsize=size,
            fontweight='bold' if bold else 'normal', color=color)

def sublabel(ax, cx, cy, text, size=8.5, color=GRAY):
    ax.text(cx, cy, text, ha='center', va='center', fontsize=size, color=color)

# ===== 화살표 =====
def arrow(ax, x1, y1, x2, y2, color=DARK, lw=1.8, text="", text_offset=(0, 1.2), dashed=False):
    style = "-|>"
    ls = '--' if dashed else '-'
    a = FancyArrowPatch((x1, y1), (x2, y2),
                        arrowstyle=style, mutation_scale=16,
                        color=color, linewidth=lw, linestyle=ls)
    ax.add_patch(a)
    if text:
        mx, my = (x1+x2)/2 + text_offset[0], (y1+y2)/2 + text_offset[1]
        ax.text(mx, my, text, ha='center', va='center', fontsize=8.5,
                color=color, fontweight='bold',
                bbox=dict(boxstyle='round,pad=0.25', fc=BG, ec=LIGHT, lw=0.6))

# ===== 섹션 박스 (아주 연한 회색) =====
def section(ax, x, y, w, h, label_text, color=DARK):
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle="round,pad=0.3,rounding_size=1.2",
                          linewidth=1.2, edgecolor=color, facecolor="#F7F7F7", alpha=1.0)
    ax.add_patch(rect)
    ax.text(x + w/2, y + h - 1.5, label_text, ha='center', va='center',
            fontsize=10.5, fontweight='bold', color=color)

# =========================================================
# 타이틀
# =========================================================
ax.text(80, 105, "주통기 취약점 진단 플랫폼 — 시스템 구조도",
        ha='center', fontsize=17, fontweight='bold', color=BLACK)
ax.text(80, 101.5, "수집 자동화 · LLM 판정 · 조치 자동화 · 가이드라인 자동 반영",
        ha='center', fontsize=10.5, color=GRAY, style='italic')

# =========================================================
# [1] 사용자 (최상단)
# =========================================================
icon_user(ax, 80, 92, size=5, color=BLACK, lw=2.4)
label(ax, 80, 86.5, "사용자 / 관리자", size=11)

# =========================================================
# [2] 웹 UI 레이어
# =========================================================
section(ax, 6, 72, 148, 11, "웹 UI  (FastAPI + Jinja2 · 포트 8081)")

# 4개 블록
web_items = [
    (20, "사용자 대시보드", "스캔·결과·리포트", icon_web),
    (58, "관리자 페이지",   "PDF·diff 승인",      icon_document),
    (96, "인증",             "bcrypt · 세션",       icon_user),
    (134, "REST API",        "scan/judge/patch",    icon_code),
]
for cx, t, st, ic in web_items:
    ic(ax, cx, 78, size=4, color=BLACK, lw=2)
    label(ax, cx, 74.5, t, size=9.5)
    sublabel(ax, cx, 72.8, st, size=8)

# =========================================================
# [3] 수집 엔진 레이어
# =========================================================
section(ax, 6, 54, 88, 14, "수집 엔진  (asyncio Semaphore · 5개 병렬)")

# Windows
icon_code(ax, 25, 60.5, size=5, color=BLACK, lw=2.2)
label(ax, 25, 56.5, "Windows 수집", size=10.5)
sublabel(ax, 25, 55, "W-01~64 · PC-01~18  (82개) · UAC 실행", size=8.2)

# Unix
icon_code(ax, 75, 60.5, size=5, color=BLACK, lw=2.2)
label(ax, 75, 56.5, "Unix / Linux 수집", size=10.5)
sublabel(ax, 75, 55, "U-01~67  (67개) · sudo 실행", size=8.2)

# =========================================================
# [4] 판정 파이프라인
# =========================================================
section(ax, 6, 34, 88, 16, "판정 파이프라인  (engine/pipeline.py)")

# 규칙 1차
icon_gear(ax, 18, 43, size=5, color=BLACK, lw=2)
label(ax, 18, 39, "규칙 1차 판정", size=10)
sublabel(ax, 18, 37.5, "양호 / 취약 / 규칙불가", size=8)

# LLM 2차
icon_ai(ax, 50, 43, size=5, color=BLACK, lw=2)
label(ax, 50, 39, "LLM 2차 판정", size=10)
sublabel(ax, 50, 37.5, "Gemini CLI + 가이드라인 DB 주입", size=8)

# 조치 생성
icon_code(ax, 82, 43, size=5, color=BLACK, lw=2.2)
label(ax, 82, 39, "조치 스크립트 생성", size=10)
sublabel(ax, 82, 37.5, "patch_script", size=8)

# 파이프라인 내부 화살표
arrow(ax, 22, 43, 45, 43, lw=1.4)
arrow(ax, 55, 43, 77, 43, lw=1.4)

# =========================================================
# [5] 관리자 영역 — 가이드라인 (왼쪽 하단)
# =========================================================
section(ax, 6, 6, 88, 24, "관리자 영역  —  주통기 가이드라인 자동 반영")

# 초기: PDF → JSON
icon_document(ax, 18, 22, size=5, color=BLACK, lw=2.2)
label(ax, 18, 18, "주통기 PDF", size=10)
sublabel(ax, 18, 16.5, "873p 가이드라인", size=8)

icon_document(ax, 42, 22, size=5, color=BLACK, lw=2.2)
label(ax, 42, 18, "JSON 저장", size=10)
sublabel(ax, 42, 16.5, "주통기 항목 149개", size=8)

# 신규 PDF → CLI 비교 → Gemini 자동 증감
icon_gear(ax, 66, 22, size=5, color=BLACK, lw=2)
label(ax, 66, 18, "CLI 비교 도구", size=10)
sublabel(ax, 66, 16.5, "add / mod / del", size=8)

icon_ai(ax, 86, 22, size=5, color=BLACK, lw=2)
label(ax, 86, 18, "Gemini 스크립트", size=10)
sublabel(ax, 86, 16.5, "자동 생성/재작성/삭제", size=8)

# 화살표
arrow(ax, 22, 22, 38, 22, text="PDF 파싱", text_offset=(0, 1.4))
arrow(ax, 46, 22, 62, 22, text="신규 PDF\n비교", text_offset=(0, 2.2))
arrow(ax, 70, 22, 82, 22, text="자동 반영", text_offset=(0, 1.4))

# 하단 설명
ax.text(50, 8.5,
        "초기 1회 : PDF → JSON · 스크립트 수동 작성        |        업데이트 : 신규 PDF → 비교 → Gemini로 스크립트 자동 생성·재작성·삭제",
        ha='center', fontsize=8.5, color=GRAY, style='italic')

# =========================================================
# [6] 저장소 (오른쪽)
# =========================================================
section(ax, 100, 6, 54, 62, "저장소")

# PostgreSQL
icon_db(ax, 127, 56, size=6, color=BLACK, lw=2.2)
label(ax, 127, 50, "PostgreSQL", size=11)
sublabel(ax, 127, 48.5, "vs_* 8개 테이블", size=8.5)
db_lines = [
    "vs_scan_results / vs_judgments",
    "vs_comparisons / vs_users",
    "vs_guideline_items / versions / diffs",
    "vs_script_registry",
]
for i, t in enumerate(db_lines):
    ax.text(127, 46 - i*1.7, "• " + t, ha='center', va='center', fontsize=8.3, color=DARK)

# Gemini CLI
icon_ai(ax, 127, 22, size=6, color=BLACK, lw=2.2)
label(ax, 127, 14, "Gemini CLI", size=11.5)
sublabel(ax, 127, 12, "gemini-2.5-flash (npx 로컬 호출)", size=8.5)
sublabel(ax, 127, 10, "API 키 불필요 · 비용 0", size=8.5)

# =========================================================
# 전체 흐름 화살표
# =========================================================
# 사용자 → 웹 UI
arrow(ax, 80, 89, 80, 83.5, text="HTTP")

# 웹 → 수집 (Windows / Unix)
arrow(ax, 25, 72, 25, 65, text="스캔 실행", text_offset=(0, 1))
arrow(ax, 75, 72, 75, 65, text="스캔 실행", text_offset=(0, 1))

# 수집 → 판정
arrow(ax, 25, 54, 25, 48)
arrow(ax, 75, 54, 75, 48)

# 판정 → DB 저장 (오른쪽으로)
arrow(ax, 87, 43, 100, 43, text="저장", text_offset=(0, 1))

# LLM 판정 ↔ Gemini (오른쪽 하단으로)
arrow(ax, 54, 40, 120, 13, color=GRAY, lw=1.2, dashed=True)

# 조치 생성 → patch 루프
arrow(ax, 82, 38, 82, 34, dashed=True)
ax.text(94, 36, "실패 시 재작성 루프", fontsize=8.5, color=GRAY,
        bbox=dict(boxstyle='round,pad=0.25', fc=BG, ec=LIGHT, lw=0.6))

# Gemini 스크립트 → 수집 스크립트 (자동 반영)
arrow(ax, 86, 26, 25, 54, color=GRAY, lw=1.2, dashed=True)
arrow(ax, 86, 26, 75, 54, color=GRAY, lw=1.2, dashed=True)

# DB → 관리자 페이지 (가이드라인 적용)
arrow(ax, 100, 22, 58, 72, color=GRAY, lw=1, dashed=True)

plt.tight_layout()
out_png = "d:/Task/4/취약점진단/시스템_구조도.png"
plt.savefig(out_png, dpi=180, bbox_inches='tight', facecolor=BG)
print(f"Saved: {out_png}")
