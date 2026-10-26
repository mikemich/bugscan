"""Self-contained HTML report: health score, trend, stage results and every finding."""
import datetime
import html
import json
import os

from . import __version__, detect, findings, paths

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--text:#1d1d1f;--muted:#6e6e73;--line:#e5e5ea;--accent:#0a84ff;
--critical:#bf2c8a;--high:#d70015;--medium:#b25000;--low:#007aff;--ok:#248a3d}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#111113;--card:#1c1c1e;--text:#f2f2f7;--muted:#98989d;
--line:#2c2c2e;--critical:#ff6ac1;--high:#ff6961;--medium:#ffb340;--low:#64a8ff;--ok:#5bd17a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0}h2{font-size:17px;margin:32px 0 12px}
.muted{color:var(--muted)}.row{display:flex;gap:16px;flex-wrap:wrap}.card{background:var(--card);border:1px solid var(--line);
border-radius:14px;padding:18px}.score{font-size:56px;font-weight:700;line-height:1}.grade{font-size:20px;font-weight:600}
.chip{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--muted)}
.ok{color:var(--ok)}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:14px;
overflow:hidden}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}tr:last-child td{border-bottom:0}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.state-new,.state-came{font-weight:700;color:var(--high)}
.wrap{overflow-x:auto}svg{display:block}
"""


def _spark(scores, w=220, h=48):
    if len(scores) < 2:
        return ""
    step = w / (len(scores) - 1)
    pts = " ".join(f"{i * step:.1f},{h - 4 - s / 100 * (h - 8):.1f}" for i, s in enumerate(scores))
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" aria-label="health trend">'
            f'<polyline points="{pts}" fill="none" stroke="var(--accent)" stroke-width="2.5" stroke-linejoin="round"/></svg>')


def write(project):
    """Write report.html into the project's workspace and return its path."""
    target, info = project.target, project.info
    titles = project.titles
    db = findings.DB(target)
    runs = db.runs()
    latest = runs[-1] if runs else None
    score, grade = db.score()
    items = db.findings(include_closed=True)
    open_items = [f for f in items if f["status"] == "open"]
    counts = {s: sum(f["severity"] == s for f in open_items) for s in findings.SEVERITIES}
    e = html.escape
    stage_rows = ""
    if latest:
        results = db.latest_stage_results()
        for k in [s.key for s in project.stages if s.key in results]:
            st = results[k]
            cls = {"clean": "ok", "new": "high", "issues": "medium", "error": "high"}.get(st["status"], "muted")
            stage_rows += (f"<tr><td>{e(titles.get(k, k))}</td><td class='{cls}'>{e(st['status'])}</td>"
                           f"<td>{st['found']}</td><td>{st['new']}</td><td>{st['secs']}s</td></tr>")
    rows = ""
    for f in items:
        loc = f"{f['file']}:{f['line']}" if f["file"] and f["line"] else (f["file"] or "")
        url = f["extra"].get("url")
        msg = e(f["message"]) + (f' <a href="{e(url)}">details</a>' if url else "")
        rows += (f"<tr><td class='state-{f['state'].split()[0]}'>{e(f['state'])}</td><td><span class='chip {f['severity']}'>{f['severity']}</span></td>"
                 f"<td>{e(titles.get(f['stage'], f['stage']))}</td><td><code>{e(loc)}</code></td><td>{msg}</td></tr>")
    when = datetime.datetime.fromtimestamp(latest["finished"]).strftime("%Y-%m-%d %H:%M") if latest else "never"
    chips = " ".join(f"<span class='chip {s}'>{counts[s]} {s}</span>" for s in findings.SEVERITIES if counts[s])
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bug Scan Report</title><style>{CSS}</style></head><body><main>
<h1>{e(os.path.basename(target))}</h1><div class="muted">{e(detect.describe(info))} · last scan {when}</div>
<div class="row" style="margin-top:20px">
 <div class="card"><div class="muted">Health</div><div class="score">{score}</div><div class="grade">Grade {grade}</div></div>
 <div class="card" style="flex:1;min-width:260px"><div class="muted">Open findings</div><div style="font-size:30px;font-weight:700">{len(open_items)}</div>
  <div style="margin-top:6px">{chips or "<span class='ok'>Nothing open</span>"}</div></div>
 <div class="card"><div class="muted">Trend ({len(runs)} scans)</div>{_spark([r['score'] for r in runs if r['score'] is not None]) or "<div class='muted'>needs 2+ scans</div>"}</div>
</div>
<h2>Checks (latest result of each)</h2><div class="wrap"><table><tr><th>Stage</th><th>Result</th><th>Found</th><th>New</th><th>Time</th></tr>{stage_rows or "<tr><td colspan=5 class=muted>No scans yet</td></tr>"}</table></div>
<h2>Findings</h2><div class="wrap"><table><tr><th>State</th><th>Severity</th><th>Stage</th><th>Location</th><th>Issue</th></tr>{rows or "<tr><td colspan=5 class=muted>No findings</td></tr>"}</table></div>
<p class="muted" style="margin-top:28px">Generated by bugscan {__version__}</p>
</main></body></html>"""
    path = os.path.join(paths.workspace(target), "report.html")
    with open(path, "w") as fh:
        fh.write(page)
    db.close()
    return path
