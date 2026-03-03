#!/usr/bin/env python3
"""Page Dumper — Web GUI (Flask + SSE). Run: python3 web.py"""

import json
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import (Flask, Response, render_template_string, request,
                   redirect, url_for, jsonify)

app = Flask(__name__)
SCANS: dict[str, dict] = {}

TEMPLATE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Page Dumper{% if title %} — {{ title }}{% endif %}</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{background:#0d1117;color:#c9d1d9}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px}
  input,select,textarea{background:#0d1117!important;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:6px 10px}
  input:focus,textarea:focus{outline:none;border-color:#58a6ff}
  .btn{background:#238636;color:#fff;padding:8px 24px;border-radius:6px;font-weight:600;border:none;cursor:pointer}
  .btn:hover{background:#2ea043}
  .btn-red{background:#da3633}.btn-red:hover{background:#f85149}
  pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;overflow-x:auto;font-size:13px;max-height:70vh;overflow-y:auto}
  a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
  .badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600}
  .badge-green{background:#238636;color:#fff}
  .badge-yellow{background:#9e6a03;color:#fff}
  .badge-red{background:#da3633;color:#fff}
</style>
</head>
<body class="min-h-screen p-6">
<div class="max-w-4xl mx-auto">
<h1 class="text-2xl font-bold mb-1">Page Dumper</h1>
<p class="text-sm text-gray-500 mb-6">Web page source grabber & analyzer for recon / bug bounty</p>
{% block content %}{% endblock %}
</div>
</body></html>"""

FORM_PAGE = TEMPLATE.replace("{% block content %}{% endblock %}", """
{% block content %}
<form method="POST" action="/scan" class="card p-6 space-y-4">
  <div>
    <label class="block text-sm font-medium mb-1">Target URL *</label>
    <input type="text" name="url" placeholder="https://example.com or http://10.0.0.1:8080" class="w-full" required>
  </div>
  <div class="grid grid-cols-3 gap-4">
    <div>
      <label class="block text-sm font-medium mb-1">JS Depth</label>
      <input type="number" name="depth" value="1" min="0" max="5" class="w-full">
    </div>
    <div>
      <label class="block text-sm font-medium mb-1">Timeout (sec)</label>
      <input type="number" name="timeout" value="15" min="1" max="120" class="w-full">
    </div>
    <div>
      <label class="block text-sm font-medium mb-1">Delay (sec)</label>
      <input type="number" name="delay" value="0" min="0" max="10" step="0.1" class="w-full">
    </div>
  </div>
  <div class="grid grid-cols-2 gap-4">
    <div>
      <label class="block text-sm font-medium mb-1">Cookies</label>
      <input type="text" name="cookies" placeholder="session=abc; token=xyz" class="w-full">
    </div>
    <div>
      <label class="block text-sm font-medium mb-1">Custom Headers</label>
      <input type="text" name="headers" placeholder="Authorization: Bearer xxx" class="w-full">
    </div>
  </div>
  <div class="grid grid-cols-2 gap-4">
    <div>
      <label class="block text-sm font-medium mb-1">Proxy</label>
      <input type="text" name="proxy" placeholder="http://127.0.0.1:8080" class="w-full">
    </div>
    <div>
      <label class="block text-sm font-medium mb-1">Host Header</label>
      <input type="text" name="host_header" placeholder="target.local (for IP+vhost)" class="w-full">
    </div>
  </div>
  <div class="grid grid-cols-2 gap-4">
    <div>
      <label class="block text-sm font-medium mb-1">User-Agent</label>
      <input type="text" name="user_agent" placeholder="default: Chrome 131" class="w-full">
    </div>
    <div>
      <label class="block text-sm font-medium mb-1">Threads (bruteforce)</label>
      <input type="number" name="threads" value="10" min="1" max="50" class="w-full">
    </div>
  </div>
  <div class="flex flex-wrap gap-6 pt-2">
    <label class="flex items-center gap-2"><input type="checkbox" name="bruteforce"> Bruteforce directories</label>
    <label class="flex items-center gap-2"><input type="checkbox" name="onefile"> Single file output</label>
    <label class="flex items-center gap-2"><input type="checkbox" name="insecure"> Skip SSL verify</label>
    <label class="flex items-center gap-2"><input type="checkbox" name="json_report" checked> JSON report</label>
    <label class="flex items-center gap-2"><input type="checkbox" name="html_report" checked> HTML report</label>
    <label class="flex items-center gap-2"><input type="checkbox" name="no_extras"> Skip extras</label>
    <label class="flex items-center gap-2"><input type="checkbox" name="wayback"> Wayback Machine</label>
  </div>
  <div class="mt-4 p-3 rounded-lg" style="border:1px solid #9e6a03;background:#161b22">
    <div class="flex items-center gap-3 flex-wrap">
      <span class="font-bold" style="color:#d29922">Stealth Mode</span>
      <select name="stealth" id="stealthSel" class="text-sm" style="width:auto">
        <option value="0">Off</option>
        <option value="1">Light — 5 threads, 1s delay, 10 UAs</option>
        <option value="2">Medium — 3 threads, 1-3s random, 16 UAs</option>
        <option value="3">Heavy — 1 thread, 3-5s random, full rotation</option>
      </select>
    </div>
    <p class="text-xs text-gray-500 mt-1">UA rotation, browser fingerprint, no bruteforce, no WAF probe</p>
  </div>
  <script>
  document.getElementById('stealthSel').addEventListener('change',function(){
    const bf=document.querySelector('[name=bruteforce]');
    if(parseInt(this.value)>0){bf.checked=false;bf.disabled=true}else{bf.disabled=false}
  });
  </script>
  <button type="submit" class="btn mt-4">Start Scan</button>
</form>

{% if scans %}
<h2 class="text-lg font-bold mt-8 mb-3">Recent Scans</h2>
<div class="space-y-2">
{% for sid, s in scans %}
<div class="card p-3 flex justify-between items-center">
  <div>
    <a href="/scan/{{ sid }}"><strong>{{ s.url }}</strong></a>
    <span class="text-sm text-gray-500 ml-2">{{ s.started }}</span>
  </div>
  <div>
    {% if s.status == 'running' %}<span class="badge badge-yellow">Running</span>
    {% elif s.status == 'done' %}<span class="badge badge-green">Done</span>
    {% else %}<span class="badge badge-red">{{ s.status | title }}</span>{% endif %}
  </div>
</div>
{% endfor %}
</div>
{% endif %}
{% endblock %}
""")

RESULT_PAGE = TEMPLATE.replace("{% block content %}{% endblock %}", """
{% block content %}
<div class="flex items-center gap-3 mb-4">
  <a href="/">&larr; Back</a>
  <h2 class="text-lg font-bold">{{ scan.url }}</h2>
  {% if scan.status == 'running' %}<span class="badge badge-yellow">Running...</span>
  {% elif scan.status == 'done' %}<span class="badge badge-green">Done</span>
  {% else %}<span class="badge badge-red">{{ scan.status | title }}</span>{% endif %}
</div>

{% if scan.status == 'running' %}
<div class="card p-4 mb-4">
  <div class="flex justify-between items-center mb-2">
    <h3 class="font-bold">Live Output</h3>
    <form method="POST" action="/scan/{{ scan_id }}/stop">
      <button type="submit" class="btn btn-red text-sm py-1 px-4">Stop Scan</button>
    </form>
  </div>
  <pre id="output"></pre>
</div>
<script>
(function(){
  const pre=document.getElementById('output');
  const es=new EventSource('/scan/{{ scan_id }}/stream');
  es.onmessage=function(e){
    pre.textContent+=JSON.parse(e.data)+'\\n';
    pre.scrollTop=pre.scrollHeight;
  };
  es.addEventListener('done',function(){
    es.close();
    setTimeout(()=>location.reload(),500);
  });
  es.onerror=function(){es.close();setTimeout(()=>location.reload(),2000);};
})();
</script>
{% else %}
<div class="card p-4 mb-4">
  <h3 class="font-bold mb-2">Console Output</h3>
  <pre>{{ output }}</pre>
</div>
{% if scan.stealth %}
<div class="card p-4 mb-4" style="border-color:#9e6a03">
  <p class="text-sm mb-3" style="color:#d29922">Stealth scan complete. Run bruteforce on the same target?</p>
  <form method="POST" action="/scan" class="flex gap-2">
    {% for k, v in scan.form.items() %}
    <input type="hidden" name="{{ k }}" value="{{ v }}">
    {% endfor %}
    <input type="hidden" name="bruteforce" value="on">
    <input type="hidden" name="json_report" value="on">
    <input type="hidden" name="html_report" value="on">
    <button type="submit" class="btn text-sm" style="background:#9e6a03">Run Bruteforce &rarr;</button>
  </form>
</div>
{% endif %}
{% if html_report_url %}
<div class="card p-4 mb-4">
  <a href="{{ html_report_url }}" target="_blank" class="btn">Open HTML Report</a>
</div>
{% endif %}
{% if report %}
<div class="card p-4 mb-4">
  <h3 class="font-bold mb-2">Report</h3>
  <pre>{{ report }}</pre>
</div>
{% endif %}
{% if json_report %}
<div class="card p-4">
  <h3 class="font-bold mb-2">JSON Report</h3>
  <pre>{{ json_report }}</pre>
</div>
{% endif %}
{% endif %}
{% endblock %}
""")


def _build_cmd(form) -> list[str]:
    cmd = [sys.executable, str(Path(__file__).parent / "dumper.py")]
    cmd.append(form["url"])
    cmd.extend(["-d", form.get("depth", "1")])
    cmd.extend(["--timeout", form.get("timeout", "15")])
    cmd.extend(["-t", form.get("threads", "10")])
    delay = form.get("delay", "0")
    if delay and float(delay) > 0:
        cmd.extend(["--delay", delay])
    if form.get("bruteforce"):
        cmd.append("-b")
    if form.get("onefile"):
        cmd.append("-o")
    if form.get("insecure"):
        cmd.append("-k")
    if form.get("json_report"):
        cmd.append("--json-report")
    if form.get("html_report"):
        cmd.append("--html-report")
    if form.get("no_extras"):
        cmd.append("--no-extras")
    if form.get("wayback"):
        cmd.append("--wayback")
    stealth = form.get("stealth", "0")
    if stealth and int(stealth) > 0:
        cmd.extend(["--stealth", stealth])
    if form.get("cookies"):
        cmd.extend(["--cookie", form["cookies"]])
    if form.get("headers"):
        cmd.extend(["-H", form["headers"]])
    if form.get("proxy"):
        cmd.extend(["--proxy", form["proxy"]])
    if form.get("host_header"):
        cmd.extend(["--host-header", form["host_header"]])
    if form.get("user_agent"):
        cmd.extend(["-A", form["user_agent"]])
    return cmd


def _run_scan(scan_id: str, cmd: list[str]):
    scan = SCANS[scan_id]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        scan["proc"] = proc
        for line in proc.stdout:
            scan["lines"].append(line.rstrip("\n"))
        proc.wait()
        scan["stderr"] = proc.stderr.read()
        scan["status"] = "done" if proc.returncode == 0 else "error"
    except Exception as e:
        scan["stderr"] = str(e)
        scan["status"] = "error"
    finally:
        scan["proc"] = None


@app.route("/")
def index():
    scans = sorted(SCANS.items(), key=lambda x: x[1]["started"], reverse=True)[:20]
    return render_template_string(FORM_PAGE, title="", scans=scans)


@app.route("/scan", methods=["POST"])
def start_scan():
    scan_id = uuid.uuid4().hex[:12]
    cmd = _build_cmd(request.form)
    SCANS[scan_id] = {
        "url": request.form["url"],
        "cmd": cmd,
        "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "running",
        "lines": [],
        "stderr": "",
        "proc": None,
        "stealth": int(request.form.get("stealth", 0)) > 0,
        "form": {k: v for k, v in request.form.items() if k != "stealth"},
    }
    threading.Thread(target=_run_scan, args=(scan_id, cmd), daemon=True).start()
    return redirect(url_for("scan_result", scan_id=scan_id))


@app.route("/scan/<scan_id>")
def scan_result(scan_id):
    scan = SCANS.get(scan_id)
    if not scan:
        return "Scan not found", 404
    report = json_report = html_report_url = None
    output = "\n".join(scan["lines"])
    if scan["stderr"]:
        output += "\n\n--- STDERR ---\n" + scan["stderr"]
    if scan["status"] != "running":
        for line in scan["lines"]:
            if "Done! Output" in line:
                dirname = line.split("\u2192")[-1].strip().rstrip("/")
                rpath = Path(dirname) / "report.txt"
                jpath = Path(dirname) / "report.json"
                hpath = Path(dirname) / "report.html"
                if rpath.exists():
                    report = rpath.read_text(encoding="utf-8")
                if jpath.exists():
                    json_report = jpath.read_text(encoding="utf-8")
                if hpath.exists():
                    html_report_url = f"/report/{scan_id}"
                    SCANS[scan_id]["report_html"] = str(hpath)
                break
    return render_template_string(RESULT_PAGE, title=scan["url"], scan=scan,
                                  scan_id=scan_id, output=output,
                                  report=report, json_report=json_report,
                                  html_report_url=html_report_url)


@app.route("/scan/<scan_id>/stream")
def scan_stream(scan_id):
    scan = SCANS.get(scan_id)
    if not scan:
        return "Not found", 404

    def generate():
        idx = 0
        while scan["status"] == "running":
            lines = scan["lines"]
            while idx < len(lines):
                yield f"data: {json.dumps(lines[idx])}\n\n"
                idx += 1
            time.sleep(0.3)
        lines = scan["lines"]
        while idx < len(lines):
            yield f"data: {json.dumps(lines[idx])}\n\n"
            idx += 1
        yield "event: done\ndata: {}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/scan/<scan_id>/stop", methods=["POST"])
def stop_scan(scan_id):
    scan = SCANS.get(scan_id)
    if scan and scan.get("proc"):
        try:
            scan["proc"].send_signal(signal.SIGINT)
        except OSError:
            pass
    return redirect(url_for("scan_result", scan_id=scan_id))


@app.route("/report/<scan_id>")
def report_html(scan_id):
    scan = SCANS.get(scan_id)
    path = scan.get("report_html") if scan else None
    if not path or not Path(path).exists():
        return "Report not found", 404
    return Response(Path(path).read_text(encoding="utf-8"),
                    mimetype="text/html")


@app.route("/api/scans")
def api_scans():
    return jsonify({
        k: {"url": v["url"], "status": v["status"], "started": v["started"],
            "cmd": " ".join(v["cmd"]), "lines_count": len(v["lines"])}
        for k, v in SCANS.items()
    })


if __name__ == "__main__":
    print("\n  Page Dumper Web GUI")
    print("  http://127.0.0.1:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
