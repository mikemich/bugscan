"""One format for every tool's findings, and a database that remembers them between scans.

Each finding has a stable fingerprint (fp) that survives line shifts, so across scans it is:
  new        first seen in the latest scan          came back  was fixed, now seen again
  open       seen before and still there            fixed      gone in a full run of its check
  ignored    marked as not a problem by the user
"""
import hashlib
import json
import math
import os
import re
import sqlite3
import time

from . import __version__, paths

SEVERITIES = ["critical", "high", "medium", "low", "info"]
WEIGHT = {"critical": 25, "high": 10, "medium": 3, "low": 1, "info": 0}


def fingerprint(*parts):
    return hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()[:16]


def norm(text):
    return re.sub(r"\s+", " ", text or "").strip()


def make(stage, tool, rule, severity, file, line, message, snippet="", key=None, **extra):
    """Build a finding. `key` is what identifies it across scans (default: snippet, else message)."""
    if severity not in SEVERITIES:
        severity = "medium"
    return {"fp": fingerprint(stage, rule, file, key if key is not None else norm(snippet) or norm(message)),
            "stage": stage, "tool": tool, "rule": str(rule), "severity": severity, "file": file,
            "line": int(line) if line else None, "message": (message or "").strip(), "snippet": snippet or "",
            "extra": {k: v for k, v in extra.items() if v is not None}}


class Source:
    """Makes paths project-relative and reads source lines for snippets."""

    def __init__(self, target):
        self.target, self.files = os.path.realpath(target), {}

    def rel(self, path):
        if not path:
            return path
        if path.startswith("file://"):
            path = path[7:]
        if os.path.isabs(path):
            real = os.path.realpath(path)
            return os.path.relpath(real, self.target) if real.startswith(self.target + os.sep) else path
        return os.path.normpath(path)

    def line(self, rel, n):
        if not rel or not n or os.path.isabs(rel):
            return ""
        if rel not in self.files:
            try:
                with open(os.path.join(self.target, rel), errors="replace") as fh:
                    self.files[rel] = fh.read().splitlines()
            except OSError:
                self.files[rel] = []
        lines = self.files[rel]
        return lines[n - 1].strip()[:300] if 0 < n <= len(lines) else ""


# ── generic readers for custom checks ──────────────────────────────────────────────────────────────

SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def from_sarif(path, stage, src, default_severity="medium"):
    """Findings from a SARIF 2.1 file (what most analyzers can emit)."""
    with open(path) as fh:
        doc = json.load(fh)
    out = []
    for run in doc.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", stage)
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            file = src.rel(loc.get("artifactLocation", {}).get("uri"))
            line = loc.get("region", {}).get("startLine")
            rule = r.get("ruleId") or "result"
            props = r.get("properties", {})
            sev = props.get("severity") if props.get("severity") in SEVERITIES else SARIF_LEVEL.get(
                r.get("level") or rules.get(rule, {}).get("defaultConfiguration", {}).get("level", ""), default_severity)
            msg = r.get("message", {}).get("text") or rules.get(rule, {}).get("shortDescription", {}).get("text", rule)
            out.append(make(stage, tool, rule, sev, file, line, msg, src.line(file, line),
                            url=rules.get(rule, {}).get("helpUri")))
    return out


def from_matchers(text, matchers, stage, tool, src):
    """Findings from regex matches over a tool's output (named groups: message, file, line, severity, rule)."""
    out, seen = [], set()
    for m in matchers:
        for hit in m["regex"].finditer(text):
            g = hit.groupdict()
            file = src.rel(g.get("file"))
            line = g.get("line")
            sev = g.get("severity", "").lower() if g.get("severity", "").lower() in SEVERITIES else m["severity"]
            msg = (g.get("message") or hit.group(0)).strip()
            f = make(stage, tool, g.get("rule") or m["rule"], sev, file, line, msg, src.line(file, int(line) if line else None),
                     key=f"{file}|{re.sub(r'[0-9]+', 'N', msg)}")
            if f["fp"] not in seen:
                seen.add(f["fp"])
                out.append(f)
    return out


# ── database ───────────────────────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, started REAL, finished REAL, profile TEXT, stages TEXT,
  score INTEGER, counts TEXT);
CREATE TABLE IF NOT EXISTS stage_runs(run_id INTEGER, stage TEXT, status TEXT, secs INTEGER, found INTEGER, new INTEGER);
CREATE TABLE IF NOT EXISTS findings(fp TEXT PRIMARY KEY, stage TEXT, tool TEXT, rule TEXT, severity TEXT, file TEXT,
  line INTEGER, message TEXT, snippet TEXT, extra TEXT, status TEXT, first_run INTEGER, last_run INTEGER,
  fixed_run INTEGER, reopened_run INTEGER, explanation TEXT);
"""


def score_of(counts):
    penalty = sum(WEIGHT.get(s, 0) * n for s, n in counts.items())
    return round(100 * math.exp(-penalty / 60))


def grade(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


STATE_ORDER = {"new": 0, "came back": 1, "open": 2, "fixed": 3, "ignored": 4}


class DB:
    def __init__(self, target):
        self.target = os.path.realpath(target)
        self.path = os.path.join(paths.workspace(target), "findings.db")
        self.con = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)

    def close(self):
        self.con.close()

    def __del__(self):
        try:
            self.con.close()
        except Exception:
            pass

    def begin_run(self, profile, stages):
        cur = self.con.execute("INSERT INTO runs(started, profile, stages) VALUES (?,?,?)", (time.time(), profile, ",".join(stages)))
        self.con.commit()
        return cur.lastrowid

    def ingest(self, run, stage, items, complete):
        """Store one check's findings. `complete`: the check looked at everything, so missing findings are fixed."""
        c, seen = self.con, set()
        new = came_back = 0
        for f in items:
            if f["fp"] in seen:
                continue
            seen.add(f["fp"])
            row = c.execute("SELECT status FROM findings WHERE fp=?", (f["fp"],)).fetchone()
            vals = (f["stage"], f["tool"], f["rule"], f["severity"], f["file"], f["line"], f["message"], f["snippet"],
                    json.dumps(f["extra"]))
            if row is None:
                c.execute("INSERT INTO findings(stage, tool, rule, severity, file, line, message, snippet, extra, fp, status,"
                          " first_run, last_run) VALUES (?,?,?,?,?,?,?,?,?,?, 'open', ?, ?)", vals + (f["fp"], run, run))
                new += 1
            else:
                came_back += row["status"] == "fixed"
                c.execute("UPDATE findings SET stage=?, tool=?, rule=?, severity=?, file=?, line=?, message=?, snippet=?, extra=?,"
                          " last_run=?, reopened_run=CASE WHEN status='fixed' THEN ? ELSE reopened_run END,"
                          " status=CASE WHEN status='fixed' THEN 'open' ELSE status END WHERE fp=?",
                          vals + (run, run, f["fp"]))
        fixed = 0
        if complete:
            fixed = c.execute("UPDATE findings SET status='fixed', fixed_run=? WHERE stage=? AND status='open' AND last_run<?",
                              (run, stage, run)).rowcount
        c.commit()
        return {"found": len(seen), "new": new, "came_back": came_back, "fixed": fixed}

    def record_stage(self, run, stage, status, secs, found=0, new=0):
        self.con.execute("INSERT INTO stage_runs VALUES (?,?,?,?,?,?)", (run, stage, status, secs, found, new))
        self.con.commit()

    def open_counts(self):
        rows = self.con.execute("SELECT severity, COUNT(*) n FROM findings WHERE status='open' GROUP BY severity").fetchall()
        return {r["severity"]: r["n"] for r in rows}

    def end_run(self, run):
        counts = self.open_counts()
        score = score_of(counts)
        self.con.execute("UPDATE runs SET finished=?, score=?, counts=? WHERE id=?", (time.time(), score, json.dumps(counts), run))
        self.con.commit()
        return score

    def latest_run(self):
        r = self.con.execute("SELECT * FROM runs WHERE finished IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        return dict(r) if r else None

    def runs(self, limit=50):
        rows = self.con.execute("SELECT * FROM runs WHERE finished IS NOT NULL ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows][::-1]

    def latest_stage_results(self):
        """Most recent result of each check, whichever scan it ran in."""
        rows = self.con.execute("SELECT * FROM stage_runs WHERE rowid IN (SELECT MAX(rowid) FROM stage_runs GROUP BY stage)")
        return {r["stage"]: dict(r) for r in rows}

    def findings(self, include_closed=False):
        latest = self.con.execute("SELECT MAX(id) FROM runs").fetchone()[0]  # includes a scan in progress
        where = "" if include_closed else "WHERE status='open'"
        out = []
        for r in self.con.execute(f"SELECT * FROM findings {where}").fetchall():
            d = dict(r)
            d["extra"] = json.loads(d["extra"] or "{}")
            d["id"] = d["fp"][:8]
            d["state"] = (d["status"] if d["status"] != "open" else
                          "came back" if d["reopened_run"] and d["reopened_run"] == d["last_run"] == latest else
                          "new" if d["first_run"] == latest else "open")
            out.append(d)
        order = {s: i for i, s in enumerate(SEVERITIES)}
        out.sort(key=lambda d: (STATE_ORDER[d["state"]] >= 3, order.get(d["severity"], 9), STATE_ORDER[d["state"]],
                                d["file"] or "", d["line"] or 0))
        return out

    def get(self, ident):
        """A finding by full fingerprint or its short id (first characters)."""
        rows = self.con.execute("SELECT fp FROM findings WHERE fp LIKE ?", (ident + "%",)).fetchall()
        if len(rows) != 1:
            return None
        return next((f for f in self.findings(include_closed=True) if f["fp"] == rows[0]["fp"]), None)

    def set_status(self, fp, status):
        self.con.execute("UPDATE findings SET status=? WHERE fp=?", (status, fp))
        self.con.commit()

    def set_explanation(self, fp, text):
        self.con.execute("UPDATE findings SET explanation=? WHERE fp=?", (text, fp))
        self.con.commit()

    def score(self):
        s = score_of(self.open_counts())
        return s, grade(s)


# ── exports ────────────────────────────────────────────────────────────────────────────────────────

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(items):
    rules, results = {}, []
    for f in items:
        rid = f"{f['stage']}/{f['rule']}"
        rules.setdefault(rid, {"id": rid, "shortDescription": {"text": f["rule"]},
                               **({"helpUri": f["extra"]["url"]} if f["extra"].get("url") else {})})
        res = {"ruleId": rid, "level": LEVEL[f["severity"]], "message": {"text": f["message"]},
               "partialFingerprints": {"bugscan/v1": f["fp"]},
               "properties": {"severity": f["severity"], "state": f["state"], "check": f["stage"]}}
        if f["file"] and not os.path.isabs(f["file"]):
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                      **({"region": {"startLine": f["line"]}} if f["line"] else {})}}]
        results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bugscan", "version": __version__, "rules": list(rules.values())}},
                      "results": results}]}


def to_json(items):
    keys = ("id", "fp", "state", "severity", "stage", "tool", "rule", "file", "line", "message", "extra")
    return [{k: f[k] for k in keys} for f in items]
