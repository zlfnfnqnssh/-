"""
기존 진단 도구 비교표 PNG 생성
"""
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch

plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False

BLACK = "#111111"
DARK  = "#333333"
GRAY  = "#888888"
LIGHT = "#E8E8E8"
ACCENT = "#C00000"
BG    = "#FFFFFF"
HEAD_BG = "#1F3864"

fig, ax = plt.subplots(figsize=(14, 8.5))
ax.set_xlim(0, 140)
ax.set_ylim(0, 85)
ax.axis('off')
fig.patch.set_facecolor(BG)

# ===== 타이틀 =====
ax.text(70, 81, "기존 OS 설정 점검 도구 비교",
        ha='center', fontsize=19, fontweight='bold', color=BLACK)
ax.text(70, 77, "※ 네트워크·CVE 스캐너(Nessus/Qualys) 제외 · OS 내부 설정 점검 도구로 한정",
        ha='center', fontsize=10, color=GRAY, style='italic')

# ===== 테이블 좌표 =====
# 컬럼: 구분 | 대표 도구 | 점검 대상 | 한계점
cols_x = [4, 30, 64, 88]   # 각 컬럼 시작 x
cols_w = [26, 34, 24, 48]  # 각 컬럼 너비
headers = ["구분", "대표 도구", "점검 대상", "한계점"]

# 헤더 행
header_y = 67
header_h = 6
for x, w, h in zip(cols_x, cols_w, headers):
    ax.add_patch(Rectangle((x, header_y), w, header_h, facecolor=HEAD_BG, edgecolor=DARK, lw=1.2))
    ax.text(x + w/2, header_y + header_h/2, h, ha='center', va='center',
            fontsize=12, color='white', fontweight='bold')

# 데이터 행
rows = [
    {
        "category":   ("Linux / Unix OSS", BLACK),
        "tools":      ("Lynis, OpenSCAP", BLACK),
        "target":     ("Linux 설정\nCIS 기준", DARK),
        "limit":      ("한국어 주통기 미대응\n보고서·조치 수동", DARK),
    },
    {
        "category":   ("Windows OSS", BLACK),
        "tools":      ("HardeningKitty\nMS Security Compliance Toolkit", BLACK),
        "target":     ("Windows 설정\nSTIG 기준", DARK),
        "limit":      ("한국어 주통기 미대응\n조치는 예시 문서만 제공", DARK),
    },
    {
        "category":   ("주통기 자체 스크립트", ACCENT),
        "tools":      ("기관·GitHub 공개 프로젝트\n(Win-KICS-Checker 등 10+)", BLACK),
        "target":     ("주통기 U / W / PC\n점검 항목", DARK),
        "limit":      ("판정까지만 자동\n조치·보고서·가이드 변경은 수동", DARK),
    },
]

row_y = 49
row_h = 8.5
for i, row in enumerate(rows):
    y = row_y - i * row_h
    # 행 배경 (교차)
    bg = "#FAFAFA" if i % 2 == 0 else BG
    for x, w in zip(cols_x, cols_w):
        ax.add_patch(Rectangle((x, y), w, row_h, facecolor=bg, edgecolor=LIGHT, lw=0.8))

    for j, (key, w, x) in enumerate(zip(["category", "tools", "target", "limit"], cols_w, cols_x)):
        text, color = row[key]
        weight = 'bold' if j == 0 else 'normal'
        size = 11 if j == 0 else 10
        ax.text(x + w/2, y + row_h/2, text,
                ha='center', va='center', fontsize=size,
                color=color, fontweight=weight, linespacing=1.3)

# ===== 공통 한계 섹션 =====
sec_y = 3
sec_h = 20
ax.add_patch(FancyBboxPatch((4, sec_y), 132, sec_h,
                            boxstyle="round,pad=0.3,rounding_size=1.2",
                            facecolor="#FFF4E6", edgecolor=ACCENT, lw=1.5))

ax.text(70, sec_y + sec_h - 2.5,
        "공통 한계 — \"고정 규칙 매칭\" 방식의 태생적 제약",
        ha='center', fontsize=13, fontweight='bold', color=ACCENT)

limits = [
    "① 맥락 이해 불가 — 주석 처리된 설정 · 조건부 설정 · 환경 특수성 반영 실패",
    "       예) PermitRootLogin no 가 # 으로 주석 처리된 경우에도 「양호」로 오탐",
    "② KISA 가이드라인도 명시: \"최종 판정은 평가 수행자가 결정\"  →  맥락 재해석 필수",
    "③ 가이드라인 개정 시 스크립트 수작업 재작성 (매년 KISA 개정)",
    "④ 조치 스크립트 자동 생성·실행 불가  |  실행 실패 시 자동 재작성 루프 없음",
]
for i, t in enumerate(limits):
    ax.text(9, sec_y + sec_h - 6.5 - i*2.5, t,
            ha='left', va='center', fontsize=10.5, color=BLACK)

plt.tight_layout()
out = "d:/Task/4/취약점진단/기존도구_비교표.png"
plt.savefig(out, dpi=180, bbox_inches='tight', facecolor=BG)
print(f"Saved: {out}")
