"""
web/app.py — 주통기 취약점 스캐너 데모 웹 서버
실행: cd vulnerability-scanner && python web/app.py
"""

import asyncio
import json
import os
import queue
import re
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (Flask, Response, flash, jsonify, redirect,
                   render_template, request, session, url_for, stream_with_context)

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE / "core"))

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "vuln-scanner-demo-2026")

RESULTS_DB   = str(BASE / "db" / "results.db")
GUIDELINE_DB = str(BASE / "db" / "guidelines.db")
SCRIPTS_BASE = BASE / "scripts"

USERS = {
    "admin": {"password": "admin123", "role": "admin", "name": "관리자"},
    "user":  {"password": "user123",  "role": "user",  "name": "일반사용자"},
}


# ══════════════════════════════════════════════════════════
# 인증
# ══════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════
# DB 헬퍼
# ══════════════════════════════════════════════════════════

def get_db(path=RESULTS_DB):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def get_guideline(item_code: str) -> dict:
    try:
        conn = sqlite3.connect(GUIDELINE_DB)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM guidelines WHERE item_code=?", (item_code,)).fetchone()
        conn.close()
        return dict(row) if row else {}
    except Exception:
        return {}


def get_latest_scan_id() -> str | None:
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT scan_id FROM final_records ORDER BY scan_date DESC LIMIT 1"
        ).fetchone()
        conn.close()
        return row["scan_id"] if row else None
    except Exception:
        return None


def get_scans():
    conn = get_db()
    rows = conn.execute("""
        SELECT scan_id, MAX(scan_date) as scan_date,
               MAX(os_name) as os_name,
               COUNT(*) as total,
               SUM(CASE WHEN result='취약' THEN 1 ELSE 0 END) as vuln,
               SUM(CASE WHEN result IN ('양호','개선','해당없음') THEN 1 ELSE 0 END) as ok,
               SUM(CASE WHEN result='개선' THEN 1 ELSE 0 END) as improved
        FROM final_records
        GROUP BY scan_id
        ORDER BY scan_date DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_items(scan_id: str, filter_result: str = None):
    conn = get_db()
    if filter_result:
        rows = conn.execute(
            "SELECT * FROM final_records WHERE scan_id=? AND result=? ORDER BY item_code",
            (scan_id, filter_result)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM final_records WHERE scan_id=? ORDER BY item_code",
            (scan_id,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_item_detail(scan_id: str, item_code: str):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM final_records WHERE scan_id=? AND item_code=?",
        (scan_id, item_code)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_scan_stats():
    conn = get_db()
    try:
        total_scans = conn.execute("SELECT COUNT(DISTINCT scan_id) FROM final_records").fetchone()[0]
        total_vuln  = conn.execute("SELECT COUNT(*) FROM final_records WHERE result='취약'").fetchone()[0]
        total_ok    = conn.execute("SELECT COUNT(*) FROM final_records WHERE result IN ('양호','개선')").fetchone()[0]
        total_items = conn.execute("SELECT COUNT(*) FROM final_records").fetchone()[0]
    except Exception:
        total_scans = total_vuln = total_ok = total_items = 0
    conn.close()
    return {"scans": total_scans, "vuln": total_vuln, "ok": total_ok, "total": total_items}


def get_patch_history(item_code: str):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM patch_results WHERE item_code=? ORDER BY patched_at DESC LIMIT 10",
            (item_code,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        conn.close()
        return []


# ══════════════════════════════════════════════════════════
# 점검 파이프라인 실행기 (웹 트리거)
# ══════════════════════════════════════════════════════════

_scan_runs: dict[str, dict] = {}   # run_id → state dict


def start_scan_async(run_id: str, sudo_password: str, item_codes=None):
    """백그라운드 스레드에서 전체 파이프라인 실행"""
    _scan_runs[run_id] = {
        "status": "running", "progress": 0,
        "message": "준비 중...", "scan_id": None, "error": None,
    }
    state = _scan_runs[run_id]

    def _update(pct: int, msg: str):
        state["progress"] = pct
        state["message"] = msg

    def _worker():
        try:
            from runner import ScriptRunner
            from collector import Collector
            from batch_judge import BatchJudge
            from db_writer import DBWriter

            api_key = os.getenv("GEMINI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
            judge_mode = os.getenv("JUDGE_MODE", "hybrid")

            # ── STEP 1: 스크립트 실행 (0~60%) ──
            _update(2, "OS 탐지 및 스크립트 준비 중...")

            scripts_list = sorted((BASE / "scripts" / "linux").glob("u*.py"))
            total_scripts = len(scripts_list)

            def on_script_progress(current, total, label):
                pct = int(current / total * 58) + 2 if total else 60
                _update(pct, f"[{current}/{total}] {label} 점검 중...")

            runner = ScriptRunner(
                scripts_base=str(BASE / "scripts"),
                sudo_password=sudo_password,
                output_dir="/tmp/scan_results",
                progress_callback=on_script_progress,
            )
            os.environ["COMPACT_OUTPUT"] = "1"
            scan_results = runner.run_items(item_codes) if item_codes else runner.run_all()

            if not scan_results:
                state["status"] = "error"
                state["error"] = "점검 스크립트 실행 결과 없음"
                return

            # ── STEP 2: 수집 ──
            _update(62, f"수집 중... ({len(scan_results)}개 항목)")
            payloads = Collector.prepare(scan_results)

            # ── STEP 3: LLM 판정 (62~88%) ──
            _update(65, f"LLM 판정 시작 ({len(payloads)}항목, mode={judge_mode})")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            judge_results = loop.run_until_complete(
                BatchJudge.run(payloads, api_key=api_key, mode=judge_mode)
            )
            loop.close()

            # ── STEP 4: DB 저장 ──
            _update(90, "DB 저장 중...")
            db = DBWriter(RESULTS_DB)
            db.init_schema()
            final_records = db.save_results(judge_results)

            vuln_n = sum(1 for r in final_records if r.result == "취약")
            ok_n   = sum(1 for r in final_records if r.result in ("양호", "개선", "해당없음"))
            # 최신 scan_id 추출 (all same)
            new_scan_id = final_records[0].scan_id if final_records else ""

            state["status"]  = "done"
            state["progress"] = 100
            state["message"] = f"완료: 전체 {len(final_records)}건 / 취약 {vuln_n}건 / 양호 {ok_n}건"
            state["scan_id"] = new_scan_id

        except Exception as e:
            import traceback
            state["status"] = "error"
            state["error"]  = str(e)
            state["message"] = f"오류 발생: {e}"
            print(f"[ScanRun] 오류:\n{traceback.format_exc()}")

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


# ══════════════════════════════════════════════════════════
# 패치 실행기
# ══════════════════════════════════════════════════════════

_patch_streams: dict[str, queue.Queue] = {}


def _run_script_stream(script_content: str, out_q: queue.Queue) -> tuple[int, list[str]]:
    lines = []
    try:
        proc = subprocess.Popen(
            ["bash", "-s"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        proc.stdin.write(script_content)
        proc.stdin.close()
        for line in iter(proc.stdout.readline, ""):
            stripped = line.rstrip()
            out_q.put(("line", stripped))
            lines.append(stripped)
        proc.wait()
        return proc.returncode, lines
    except Exception as e:
        msg = f"[실행 오류] {e}"
        out_q.put(("line", msg))
        lines.append(msg)
        return -1, lines


def _fix_script_with_gemini(script: str, error_output: str, item_code: str) -> str:
    try:
        from google import genai
        from google.genai import types
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            return ""
        client = genai.Client(api_key=api_key)
        prompt = f"""bash 패치 스크립트 오류 수정.
[항목] {item_code}
[오류 출력]
{error_output[:500]}
[원본 스크립트]
{script}
수정된 bash 스크립트만 출력하세요."""
        resp = client.models.generate_content(
            model="gemini-2.5-flash", contents=prompt,
            config=types.GenerateContentConfig(temperature=0.1, max_output_tokens=1000),
        )
        cleaned = re.sub(r"```(?:bash|sh)?\s*", "", resp.text).strip().rstrip("`").strip()
        return cleaned
    except Exception:
        return ""


def execute_patch_with_retry(patch_id, item_code, scan_id, script_content, max_retries=3):
    out_q = queue.Queue()
    _patch_streams[patch_id] = out_q

    def _worker():
        current_script = script_content
        all_output = []
        success = False

        for attempt in range(1, max_retries + 1):
            out_q.put(("status", f"attempt:{attempt}/{max_retries}"))
            out_q.put(("line", ""))
            out_q.put(("line", f"═══ 실행 시도 {attempt}/{max_retries} ═══"))

            rc, attempt_output = _run_script_stream(current_script, out_q)
            all_output.extend(attempt_output)

            if rc == 0:
                out_q.put(("status", "success"))
                out_q.put(("line", "✓ 패치 성공 (exit=0)"))
                success = True
                _save_patch_result(scan_id, item_code, current_script,
                                   "\n".join(all_output), "", rc, True, attempt)
                break
            else:
                err_text = "\n".join(attempt_output[-20:])
                out_q.put(("line", f"✗ 오류 발생 (exit={rc})"))
                if attempt < max_retries:
                    out_q.put(("status", f"fixing:{attempt}"))
                    out_q.put(("line", f"⏳ Gemini에게 수정 요청 중... ({attempt}/{max_retries-1})"))
                    fixed = _fix_script_with_gemini(current_script, err_text, item_code)
                    if fixed:
                        current_script = fixed
                        out_q.put(("line", "✎ 스크립트 수정 완료, 재시도합니다"))
                    else:
                        out_q.put(("line", "⚠ Gemini 수정 실패"))

        if not success:
            out_q.put(("status", "failed"))
            out_q.put(("line", f"✗ 최대 재시도({max_retries}회) 초과, 패치 실패"))
            _save_patch_result(scan_id, item_code, current_script,
                               "\n".join(all_output), "max_retries exceeded", -1, False, max_retries)
        out_q.put(("done", ""))

    threading.Thread(target=_worker, daemon=True).start()


def _save_patch_result(scan_id, item_code, script, stdout, stderr, rc, success, attempt):
    conn = get_db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS patch_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT, item_code TEXT, patch_script TEXT,
                patch_stdout TEXT, patch_stderr TEXT, patch_exit_code INTEGER,
                verify_result TEXT, attempt INTEGER, patched_at TEXT, patch_success INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO patch_results
                (scan_id,item_code,patch_script,patch_stdout,patch_stderr,
                 patch_exit_code,verify_result,attempt,patched_at,patch_success)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (scan_id, item_code, script, stdout, stderr, rc,
              "", attempt, datetime.now().isoformat(), int(success)))
        conn.commit()
    except Exception:
        pass
    conn.close()


def recheck_item(item_code: str) -> dict:
    code_num = item_code.replace("U-", "").replace("u-", "").lstrip("0") or "0"
    script_path = SCRIPTS_BASE / "linux" / f"u{int(code_num):02d}.py"
    if not script_path.exists():
        return {"error": f"스크립트 없음: {script_path}"}
    env = os.environ.copy()
    env["COMPACT_OUTPUT"] = "1"
    try:
        result = subprocess.run(
            ["python3", str(script_path)],
            capture_output=True, text=True, timeout=30, env=env
        )
        stdout = result.stdout
        s = stdout.find("{"); e = stdout.rfind("}") + 1
        if s != -1 and e > s:
            return json.loads(stdout[s:e])
    except Exception as e:
        return {"error": str(e)}
    return {"error": "결과 없음"}


def _get_or_generate_patch(scan_id, item_code, item, guide) -> str:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT script_content FROM patch_scripts WHERE scan_id=? AND item_code=?",
            (scan_id, item_code)
        ).fetchone()
        conn.close()
        if row and row["script_content"]:
            return row["script_content"]
    except Exception:
        conn.close()

    return _generate_patch_with_gemini(item_code, item, guide)


def _generate_patch_with_gemini(item_code: str, item: dict, guide: dict) -> str:
    try:
        from google import genai
        from google.genai import types
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            return "# GEMINI_API_KEY 미설정\n# 수동으로 조치가 필요합니다.\n"
        client = genai.Client(api_key=api_key)
        standard = guide.get("standard", "") if guide else ""
        reason = item.get("reason", "") if item else ""
        remediation = item.get("remediation", "") if item else ""
        prompt = f"""주통기 취약점 패치 bash 스크립트 작성.
항목: {item_code}
판정 근거: {reason[:200]}
조치방법: {remediation[:200]}
판단기준: {standard[:200]}
요구사항: set -e / 수정 전 백업(cp -p) / 설정 변경 후 검증 명령어 / 실패 시 롤백 / echo 진행상황
bash 코드만 출력."""
        resp = client.models.generate_content(
            model="gemini-2.5-flash", contents=prompt,
            config=types.GenerateContentConfig(temperature=0.1, max_output_tokens=1000),
        )
        cleaned = re.sub(r"```(?:bash|sh)?\s*", "", resp.text).strip().rstrip("`").strip()
        _save_patch_script(item_code, item.get("scan_id", "") if item else "", "", cleaned)
        return cleaned
    except Exception as e:
        return f"# 패치 스크립트 생성 실패: {e}\n# 수동으로 조치하세요.\n"


def _save_patch_script(item_code, scan_id, item_name, script):
    conn = get_db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS patch_scripts (
                patch_id TEXT, scan_id TEXT, item_code TEXT, item_name TEXT,
                script_content TEXT, description TEXT, status TEXT, generated_at TEXT
            )
        """)
        conn.execute("""
            INSERT OR REPLACE INTO patch_scripts
                (patch_id,scan_id,item_code,item_name,script_content,status,generated_at)
            VALUES (?,?,?,?,?,'ready',?)
        """, (f"{scan_id}_{item_code}", scan_id, item_code, item_name,
              script, datetime.now().isoformat()))
        conn.commit()
    except Exception:
        pass
    conn.close()


# ══════════════════════════════════════════════════════════
# 라우트
# ══════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = USERS.get(username)
        if user and user["password"] == password:
            session["username"] = username
            session["role"] = user["role"]
            session["name"] = user["name"]
            return redirect(url_for("dashboard"))
        flash("아이디 또는 비밀번호가 틀렸습니다.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    stats = get_scan_stats()
    latest_scan_id = get_latest_scan_id()
    latest_items = get_scan_items(latest_scan_id) if latest_scan_id else []
    scans = get_scans()[:5]
    return render_template("dashboard.html",
                           stats=stats, scans=scans,
                           latest_scan_id=latest_scan_id,
                           latest_items=latest_items)


@app.route("/scans")
@login_required
def scan_list():
    scans = get_scans()
    return render_template("scan_list.html", scans=scans)


@app.route("/scan/<scan_id>")
@login_required
def scan_detail(scan_id):
    tab = request.args.get("tab", "all")
    filter_map = {"vuln": "취약"}
    result_filter = filter_map.get(tab)

    items = get_scan_items(scan_id, result_filter)
    all_items = get_scan_items(scan_id)

    counts = {
        "total": len(all_items),
        "vuln": sum(1 for i in all_items if i["result"] == "취약"),
        "ok": sum(1 for i in all_items if i["result"] in ("양호", "개선", "해당없음")),
        "improved": sum(1 for i in all_items if i["result"] == "개선"),
    }
    os_name = all_items[0].get("os_name", "") if all_items else ""
    scan_date = all_items[0].get("scan_date", "") if all_items else ""
    return render_template("scan_detail.html",
                           scan_id=scan_id, items=items,
                           counts=counts, tab=tab,
                           os_name=os_name, scan_date=scan_date)


@app.route("/scan/<scan_id>/item/<item_code>")
@login_required
def item_detail(scan_id, item_code):
    item = get_item_detail(scan_id, item_code)
    if not item:
        flash("항목을 찾을 수 없습니다.", "warning")
        return redirect(url_for("scan_detail", scan_id=scan_id))
    guide = get_guideline(item_code)
    patch_history = get_patch_history(item_code)

    # 수집 데이터 파싱 (collected_json → list)
    collected_data = []
    try:
        raw_json = item.get("collected_json", "") or ""
        if raw_json:
            collected_data = json.loads(raw_json)
    except Exception:
        collected_data = []

    # 점검 스크립트 파일 내용
    script_content = ""
    try:
        code_num = item_code.replace("U-", "").replace("u-", "").lstrip("0") or "0"
        script_path = BASE / "scripts" / "linux" / f"u{int(code_num):02d}.py"
        if script_path.exists():
            script_content = script_path.read_text(encoding="utf-8")
    except Exception:
        script_content = ""

    return render_template("item_detail.html",
                           item=item, guide=guide,
                           patch_history=patch_history, scan_id=scan_id,
                           collected_data=collected_data,
                           script_content=script_content)


@app.route("/scan/<scan_id>/patch/<item_code>", methods=["GET"])
@login_required
def patch_view(scan_id, item_code):
    item = get_item_detail(scan_id, item_code)
    guide = get_guideline(item_code)
    patch_script = _get_or_generate_patch(scan_id, item_code, item, guide)
    before_result = {"result": item["result"], "reason": item["reason"]} if item else {}
    return render_template("patch_detail.html",
                           item=item, guide=guide,
                           patch_script=patch_script,
                           scan_id=scan_id, item_code=item_code,
                           before_result=before_result)


# ── 점검 실행 (SSE 진행) ──────────────────────────────────

@app.route("/scan/start", methods=["POST"])
@login_required
def scan_start():
    sudo_password = request.form.get("password", "")
    run_id = f"run_{int(time.time())}"
    start_scan_async(run_id, sudo_password)
    return jsonify({"run_id": run_id})


@app.route("/scan/progress/<run_id>")
@login_required
def scan_progress(run_id):
    def generate():
        timeout = 3600
        start = time.time()
        last_pct = -1
        while time.time() - start < timeout:
            state = _scan_runs.get(run_id)
            if not state:
                yield f"data: {json.dumps({'type':'error','msg':'run_id 없음'})}\n\n"
                break
            pct = state.get("progress", 0)
            msg = state.get("message", "")
            status = state.get("status", "running")
            if pct != last_pct or status != "running":
                last_pct = pct
                yield f"data: {json.dumps({'type':'progress','pct':pct,'msg':msg,'status':status,'scan_id':state.get('scan_id','')})}\n\n"
            if status in ("done", "error"):
                break
            time.sleep(0.8)
    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── 패치 실행 ────────────────────────────────────────────

@app.route("/patch/execute/<scan_id>/<item_code>", methods=["POST"])
@login_required
def patch_execute(scan_id, item_code):
    script = request.form.get("script", "")
    if not script.strip():
        return jsonify({"error": "스크립트 없음"}), 400
    patch_id = f"{scan_id}_{item_code}_{int(time.time())}"
    execute_patch_with_retry(patch_id, item_code, scan_id, script)
    return jsonify({"patch_id": patch_id})


@app.route("/patch/stream/<patch_id>")
@login_required
def patch_stream(patch_id):
    def generate():
        q = _patch_streams.get(patch_id)
        if not q:
            yield f"data: {json.dumps({'type':'error','msg':'스트림 없음'})}\n\n"
            return
        start = time.time()
        while time.time() - start < 120:
            try:
                kind, val = q.get(timeout=1)
                if kind == "line":
                    yield f"data: {json.dumps({'type':'line','msg':val})}\n\n"
                elif kind == "status":
                    yield f"data: {json.dumps({'type':'status','status':val})}\n\n"
                elif kind == "done":
                    yield f"data: {json.dumps({'type':'done'})}\n\n"
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type':'ping'})}\n\n"
    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/patch/recheck/<scan_id>/<item_code>")
@login_required
def patch_recheck(scan_id, item_code):
    after = recheck_item(item_code)
    before_item = get_item_detail(scan_id, item_code)
    before = {
        "result": before_item["result"] if before_item else "알 수 없음",
        "reason": before_item["reason"] if before_item else "",
    }
    after_result = "알 수 없음"
    after_reason = ""
    if "error" not in after:
        items = after.get("items", [])
        if items:
            cr = items[0].get("check_results", [{}])[0]
            cv = cr.get("collected_value", "").lower()
            after_reason = cv[:200]
            if any(kw in cv for kw in ["no", "false", "disable", "inactive", "not_running", "not found"]):
                after_result = "양호 (예상)"
            elif any(kw in cv for kw in ["yes", "true", "enable", "active", "running"]):
                after_result = "취약 (예상)"
            else:
                after_result = "확인 필요"
    return jsonify({
        "before": before,
        "after": {"result": after_result, "data": after_reason},
        "improved": after_result.startswith("양호") and before["result"] == "취약",
    })


# ── API ─────────────────────────────────────────────────

@app.route("/api/scans")
@login_required
def api_scans():
    return jsonify(get_scans())


@app.route("/api/scan/<scan_id>")
@login_required
def api_scan(scan_id):
    return jsonify(get_scan_items(scan_id))


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_scan_stats())


def _init_db():
    """앱 시작 시 DB 스키마 초기화 및 마이그레이션"""
    sys.path.insert(0, str(BASE / "core"))
    try:
        from db_writer import DBWriter
        DBWriter(RESULTS_DB).init_schema()
    except Exception as e:
        print(f"[DB init] {e}")


if __name__ == "__main__":
    _init_db()
    port = int(os.getenv("PORT", 5000))
    print(f"서버 시작: http://0.0.0.0:{port}")
    print("계정: admin/admin123 (관리자)  user/user123 (일반)")
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)
