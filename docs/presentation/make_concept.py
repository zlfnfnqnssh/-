"""
3대 핵심 컨셉 다이어그램 — 슬라이드 6용
"""
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle, Rectangle

plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False

BLACK = "#111111"
DARK  = "#333333"
GRAY  = "#888888"
LIGHT = "#E8E8E8"
BG    = "#FFFFFF"
ACCENT = "#1F3864"
GREEN = "#548235"

fig, ax = plt.subplots(figsize=(15, 7.5))
ax.set_xlim(0, 150)
ax.set_ylim(0, 75)
ax.axis('off')
fig.patch.set_facecolor(BG)

# 타이틀
ax.text(75, 70, "제안 시스템 — 3대 핵심", ha='center', fontsize=20, fontweight='bold', color=BLACK)
ax.text(75, 66, "수집 스크립트 + 가이드라인 DB + LLM 판정을 결합한 3단 E2E 주통기 진단 플랫폼",
        ha='center', fontsize=11, color=GRAY, style='italic')

# ===== 3 Pillar =====
def pillar(ax, cx, title, icon_fn, num, body_lines):
    top_y = 58
    w = 42
    h = 50
    x = cx - w/2
    y = top_y - h

    # 외곽
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle="round,pad=0.3,rounding_size=1.5",
                                linewidth=1.8, edgecolor=DARK, facecolor="#FAFAFA"))

    # 번호 원
    ax.add_patch(Circle((cx, top_y-3.5), 2.8, facecolor=ACCENT, edgecolor=ACCENT))
    ax.text(cx, top_y-3.5, num, ha='center', va='center',
            fontsize=16, color='white', fontweight='bold')

    # 아이콘
    icon_fn(ax, cx, top_y-13, size=7)

    # 타이틀
    ax.text(cx, top_y-21, title, ha='center', va='center',
            fontsize=13, fontweight='bold', color=BLACK)

    # 본문
    for i, line in enumerate(body_lines):
        ax.text(x+2.5, top_y-28 - i*4.5, "· " + line,
                ha='left', va='center', fontsize=10, color=DARK)

# ===== 아이콘 =====
def icon_brain(ax, cx, cy, size=7):
    # 두뇌 (둥근 사각형 + 물결)
    w = size*1.4
    h = size*1.0
    ax.add_patch(FancyBboxPatch((cx-w/2, cy-h/2), w, h,
                                boxstyle="round,pad=0.1,rounding_size=1.2",
                                linewidth=2.2, edgecolor=BLACK, facecolor='none'))
    # 수직선 가운데
    ax.plot([cx, cx], [cy-h/2+0.5, cy+h/2-0.5], color=BLACK, lw=1.5)
    # 물결 선
    import numpy as np
    xs = np.linspace(cx-w/2+1, cx-0.5, 20)
    ys = cy + np.sin(xs*3)*0.6
    ax.plot(xs, ys, color=BLACK, lw=1.2)
    xs2 = np.linspace(cx+0.5, cx+w/2-1, 20)
    ys2 = cy + np.sin(xs2*3)*0.6
    ax.plot(xs2, ys2, color=BLACK, lw=1.2)

def icon_gear_play(ax, cx, cy, size=7):
    # 톱니바퀴 + 재생 화살표
    import numpy as np
    outer = size*0.55
    inner = size*0.42
    n = 8
    pts = []
    for i in range(n*2):
        ang = 2*np.pi*i/(n*2)
        r = outer if i%2==0 else inner
        pts.append((cx + r*np.cos(ang), cy + r*np.sin(ang)))
    from matplotlib.patches import Polygon
    ax.add_patch(Polygon(pts, fill=False, linewidth=2, edgecolor=BLACK, closed=True))
    # 가운데 재생 삼각형
    tri = [(cx-1.5, cy-1.8), (cx-1.5, cy+1.8), (cx+1.8, cy)]
    ax.add_patch(Polygon(tri, facecolor=BLACK, edgecolor=BLACK))

def icon_refresh(ax, cx, cy, size=7):
    # 리프레시 화살표 원형
    import numpy as np
    r = size*0.5
    # 3/4 원 호
    theta = np.linspace(np.deg2rad(30), np.deg2rad(330), 60)
    xs = cx + r*np.cos(theta)
    ys = cy + r*np.sin(theta)
    ax.plot(xs, ys, color=BLACK, lw=2.2)
    # 화살표 촉
    from matplotlib.patches import Polygon
    ax_tip = (cx + r*np.cos(np.deg2rad(30)), cy + r*np.sin(np.deg2rad(30)))
    tri = [
        (ax_tip[0]-1.3, ax_tip[1]+0.3),
        (ax_tip[0]+1.3, ax_tip[1]+1.3),
        (ax_tip[0]+0.3, ax_tip[1]-1.3),
    ]
    ax.add_patch(Polygon(tri, facecolor=BLACK, edgecolor=BLACK))
    # 가운데 문서
    ax.add_patch(FancyBboxPatch((cx-1.8, cy-2.2), 3.6, 4.4,
                                boxstyle="round,pad=0.05,rounding_size=0.4",
                                linewidth=1.5, edgecolor=BLACK, facecolor='none'))
    for i in range(3):
        ax.plot([cx-1.2, cx+1.2], [cy+1.0-i*1.0, cy+1.0-i*1.0], color=BLACK, lw=0.8)

# ===== 3 Pillar 배치 =====
pillar(ax, 28, "맥락 이해 판정", icon_brain, "1", [
    "규칙 1차 → LLM 2차 재판정",
    "가이드라인 DB 프롬프트 주입",
    "오탐·환각 동시 억제",
    "예: 주석 처리된 설정 구분",
])

pillar(ax, 75, "조치 자동화", icon_gear_play, "2", [
    "patch_script LLM 자동 생성",
    "UAC / sudo 자동 승격 실행",
    "실패 시 Gemini 재작성 루프",
    "패치 전·후 재수집으로 검증",
])

pillar(ax, 122, "자가 갱신", icon_refresh, "3", [
    "신규 PDF → 자동 파싱·diff",
    "Gemini로 스크립트 자동 생성",
    "변경·삭제 항목도 자동 반영",
    "매년 KISA 개정 사람 손 불필요",
])

# 화살표 (연결 흐름)
arrow_kw = dict(arrowstyle="-|>", mutation_scale=15, color=GRAY, linewidth=1.2)
ax.add_patch(FancyArrowPatch((49, 33), (54, 33), **arrow_kw))
ax.add_patch(FancyArrowPatch((96, 33), (101, 33), **arrow_kw))

# 하단 슬로건
ax.add_patch(FancyBboxPatch((15, 2), 120, 7,
                            boxstyle="round,pad=0.3,rounding_size=1.5",
                            linewidth=1.5, edgecolor=ACCENT, facecolor="#F0F4FA"))
ax.text(75, 5.5,
        "기존 도구는 \"규칙 매칭까지\"  |  우리는 \"맥락 이해 + 조치 자동화 + 가이드라인 자가 갱신\"까지",
        ha='center', va='center', fontsize=12.5, fontweight='bold', color=ACCENT)

plt.tight_layout()
out = "d:/Task/4/취약점진단/3대핵심_컨셉.png"
plt.savefig(out, dpi=180, bbox_inches='tight', facecolor=BG)
print(f"Saved: {out}")
