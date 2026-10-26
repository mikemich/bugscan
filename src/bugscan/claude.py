"""Claude helpers, run through the local Claude Code CLI (`claude -p`), so they use your existing login.
Nothing is sent unless you trigger an action. Fixes need git so they can be reviewed and undone.
BUGSCAN_CLAUDE points at a different executable (the test suite uses a fake one)."""
import json
import os
import re
import shutil
import subprocess
import tempfile

from . import paths

READ_ONLY = ["Read", "Grep", "Glob"]


def available():
    return shutil.which(os.environ.get("BUGSCAN_CLAUDE", "claude")) is not None


def run(prompt, cwd, tools, mode=None, timeout=900, on_line=None, proc_holder=None):
    cmd = [os.environ.get("BUGSCAN_CLAUDE", "claude"), "-p", prompt, "--output-format", "text", "--allowedTools", ",".join(tools)]
    if mode:
        cmd += ["--permission-mode", mode]
    try:
        # The claude CLI, as an argument list (no shell).
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,  # nosemgrep
                             stdin=subprocess.DEVNULL, text=True, errors="replace", start_new_session=True)
    except FileNotFoundError:
        return 127, "Claude Code isn't installed (see bugscan doctor)."
    if proc_holder is not None:
        proc_holder.append(p)
    lines = []
    for line in p.stdout:
        lines.append(line.rstrip("\n"))
        if on_line:
            on_line(line.rstrip("\n"))
    p.stdout.close()
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
    return p.returncode, "\n".join(lines).strip()


def context(f, target, radius=12):
    if not f.get("file") or not f.get("line"):
        return ""
    try:
        with open(os.path.join(target, f["file"]), errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ""
    lo, hi = max(1, f["line"] - radius), min(len(lines), f["line"] + radius)
    return "\n".join(f"{'>' if n == f['line'] else ' '}{n:5} | {lines[n - 1]}" for n in range(lo, hi + 1))


def describe(f, target):
    loc = f"{f['file']}:{f['line']}" if f.get("file") and f.get("line") else f.get("file") or "(no file)"
    extra = {k: v for k, v in (f.get("extra") or {}).items() if k in ("package", "version", "fixed", "kev", "url", "repro", "signature")}
    code = context(f, target)
    repro = ""
    if extra.get("repro") and os.path.exists(extra["repro"]) and extra["repro"].endswith(".json"):
        with open(extra["repro"]) as fh:
            repro = "\nCrashing input (fuzzer reproducer):\n" + fh.read()[:3000]
    return (f"Tool: {f['tool']} (stage: {f['stage']})\nRule: {f['rule']}\nSeverity: {f['severity']}\nLocation: {loc}\n"
            f"Message: {f['message']}\n" + (f"Details: {json.dumps(extra)}\n" if extra else "") +
            (f"\nCode around the location (> marks the line):\n{code}\n" if code else "") + repro)


def explain(f, target, on_line=None, proc_holder=None):
    prompt = f"""An automated bug scanner reported this finding in the project in the current directory.

{describe(f, target)}
Look at the relevant code (read other files if that helps; do not edit anything) and explain it to the developer
in plain language, under 180 words, using exactly these headings:
Verdict: one of "Real issue", "Likely false positive" or "Needs a human look", plus one sentence why.
What's wrong:
Why it matters:
How to fix:"""
    return run(prompt, target, READ_ONLY, on_line=on_line, proc_holder=proc_holder)


# ── fixing, with a git snapshot so the change can be reviewed and undone

def _git(target, *args):
    return subprocess.run(["git", "-C", target, *args], capture_output=True, text=True)


def is_git(target):
    return _git(target, "rev-parse", "HEAD").returncode == 0


def snapshot(target):
    """Commit object holding the current working tree (without touching it), plus untracked files."""
    snap = _git(target, "stash", "create").stdout.strip() or _git(target, "rev-parse", "HEAD").stdout.strip()
    untracked = set(_git(target, "ls-files", "--others", "--exclude-standard").stdout.splitlines())
    return {"commit": snap, "untracked": untracked}


def changes_since(target, snap):
    tracked = [l for l in _git(target, "diff", "--name-only", snap["commit"]).stdout.splitlines() if l]
    now_untracked = set(_git(target, "ls-files", "--others", "--exclude-standard").stdout.splitlines())
    new_files = sorted(now_untracked - snap["untracked"])
    diff = _git(target, "diff", snap["commit"]).stdout
    for nf in new_files:
        diff += _git(target, "diff", "--no-index", "/dev/null", nf).stdout
    return tracked, new_files, diff


def revert(target, snap, tracked, new_files):
    for path in tracked:
        if _git(target, "cat-file", "-e", f"{snap['commit']}:{path}").returncode == 0:
            _git(target, "checkout", snap["commit"], "--", path)
        else:
            try:
                os.remove(os.path.join(target, path))
            except OSError:
                pass
    for path in new_files:
        try:
            os.remove(os.path.join(target, path))
        except OSError:
            pass


def fix(f, target, on_line=None, proc_holder=None):
    if not is_git(target):
        return {"error": "Fixing needs a git repository (so every change can be reviewed and undone)."}
    snap = snapshot(target)
    dep_hint = ""
    if f["stage"] == "deps":
        dep_hint = ("This is a vulnerable dependency: raise the version constraint in the manifest (package.json, "
                    "requirements.txt, Podfile, Package.swift, …) to the fixed version. If only a lockfile exists, "
                    "update the version there consistently. Say if the lockfile must be regenerated with the package manager.\n")
    prompt = f"""An automated bug scanner reported this finding in the project in the current directory.

{describe(f, target)}
Fix it with the smallest correct change. Edit the files directly.
- Change only what the fix needs; no unrelated refactors, renames or formatting changes.
- Don't add comments that mention the scanner or this task.
- If the finding is a false positive, change nothing and say why.
{dep_hint}Finish with one short paragraph describing what you changed."""
    rc, text = run(prompt, target, ["Read", "Edit", "Write", "Grep", "Glob"], mode="acceptEdits", on_line=on_line, proc_holder=proc_holder)
    tracked, new_files, diff = changes_since(target, snap)
    return {"snapshot": snap, "tracked": tracked, "new_files": new_files, "diff": diff, "summary": text, "rc": rc}


# ── rules from fixed bugs

LANG = {".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
        ".tsx": "typescript", ".py": "python", ".swift": "swift", ".go": "go", ".java": "java", ".rb": "ruby",
        ".php": "php", ".rs": "rust", ".kt": "kotlin", ".c": "c", ".cpp": "cpp", ".cs": "csharp"}


def _strip_fences(text):
    m = re.search(r"```(?:ya?ml)?\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip()


def _indent(rule):
    return "\n".join("  " + l for l in rule.splitlines()) + "\n"


def write_rule(f, target, diff, on_line=None, proc_holder=None):
    """Ask Claude for a Semgrep rule matching the bug pattern, validate it, and append it to .bugscan/rules.yml."""
    lang = LANG.get(os.path.splitext(f.get("file") or "")[1].lower())
    if not lang:
        return {"error": "Rules can only be written for findings in source files of a language Semgrep supports."}
    if not shutil.which("semgrep"):
        return {"error": "semgrep is not installed."}
    rules_path = os.path.join(paths.project_dir(target), "rules.yml")
    existing = ""
    if os.path.exists(rules_path):
        with open(rules_path) as fh:
            existing = fh.read()
    base = f"""A bug was found and fixed in this project (current directory).

{describe(f, target)}
The fix (git diff):
{diff[:6000] or "(no diff available; base the rule on the code and message above)"}

Write ONE Semgrep rule (language: {lang}) that would catch this same bug pattern anywhere else in the codebase,
without matching the fixed code. Prefer `patterns` with `pattern-not` over regex. Keep it general enough to find
other instances, but not so general it fires on normal code.
Reply with ONLY the YAML for the single rule: start with "- id: project.<short-kebab-name>" and include
languages, severity (ERROR for crashes/security, WARNING otherwise), message (say what to do instead) and the patterns.
Don't include a top-level "rules:" key and don't edit any files."""
    prompt, error = base, None
    for attempt in range(2):
        rc, text = run(prompt, target, READ_ONLY, on_line=on_line, proc_holder=proc_holder)
        rule = _strip_fences(text)
        if not rule.startswith("- id:"):
            error = "the reply was not a rule"
        else:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = os.path.join(tmp, "rule.yml")
                with open(cfg, "w") as fh:
                    fh.write("rules:\n" + _indent(rule))
                v = subprocess.run(["semgrep", "--validate", "--config", cfg, "--metrics=off", "--quiet"], capture_output=True, text=True)
                if v.returncode != 0:
                    error = (v.stderr or v.stdout).strip()[-800:]
                else:
                    # does it run, and how many places does it match right now?
                    r = subprocess.run(["semgrep", "scan", "--config", cfg, "--json", "--metrics=off", "--quiet", "--exclude", ".bugscan", target],
                                       capture_output=True, text=True)
                    hits = len(json.loads(r.stdout or "{}").get("results", [])) if r.stdout else 0
                    os.makedirs(os.path.dirname(rules_path), exist_ok=True)
                    body = existing if existing.strip() else "rules:\n"
                    with open(rules_path, "w") as fh:
                        fh.write(body.rstrip("\n") + "\n" + _indent(rule))
                    return {"path": rules_path, "rule": rule, "matches": hits}
        prompt = base + f"\n\nYour previous attempt was rejected ({error}). Previous attempt:\n{rule}\nReply with a corrected rule only."
    return {"error": f"Couldn't produce a valid rule: {error}"}


# ── fuzz harnesses for any project

def write_harness(target, info, on_line=None, proc_holder=None):
    langs = info["languages"]
    js = next((l for l in langs if l in ("JavaScript", "TypeScript")), None)
    py = "Python" in langs
    if not js and not py:
        return {"error": "Automatic fuzz harnesses support JavaScript/TypeScript and Python projects."}
    kind = "mjs" if js and (not py or langs.index(js) < langs.index("Python")) else "py"
    driver = paths.data(f"driver.{kind}")
    harness = os.path.join(paths.project_dir(target), "fuzz", f"harness.{kind}")
    with open(driver) as fh:
        src = fh.read()
    contract = src.split("import", 1)[0] if kind == "mjs" else src.split('"""')[1]
    runner = f"node {driver}" if kind == "mjs" else f"python3 {driver}"
    base = f"""Write a fuzz harness for the project in the current directory, at {os.path.relpath(harness, target)}.

The harness contract (the fuzzer that runs it):
{contract}
Steps:
1. Find 1-4 functions in this project that take external or untrusted input and are likely to break on odd data:
   parsers, decoders, validators, request/response handlers, data transformers, formatters. Prefer pure functions.
2. Write the harness so each target calls the real project function. Inputs should be the shape the function
   really receives (objects, arrays, strings). Provide 3-10 realistic seeds.
3. Targets must not touch the network, write files, spawn processes or sleep, and must run in well under 10 ms.
   Stub anything like that. Let real bugs throw; use `expected` only for errors the code deliberately raises
   for invalid input.
4. Check it works: run `{runner} {harness} 5 {tempfile.mkdtemp(prefix="bugscan-check-")}` and fix the harness until it loads
   and runs (finding crashes is fine and expected; HARNESS ERROR is not).
Don't change any project files other than the harness. Finish with a short list of the functions you chose and why."""
    tools = ["Read", "Grep", "Glob", "Write", "Edit", "Bash(node:*)", "Bash(python3:*)"]
    rc, text = run(base, target, tools, mode="acceptEdits", on_line=on_line, proc_holder=proc_holder)
    if not os.path.exists(harness):
        return {"error": "Claude didn't create the harness.", "summary": text}
    check = subprocess.run((["node"] if kind == "mjs" else ["python3"]) + [driver, harness, "3", tempfile.mkdtemp()],
                           capture_output=True, text=True, timeout=120)
    if "HARNESS ERROR" in check.stdout:
        return {"error": "The harness doesn't load:\n" + check.stdout[-1500:], "path": harness, "summary": text}
    return {"path": harness, "summary": text, "check": check.stdout.strip().splitlines()[0] if check.stdout.strip() else ""}


# ── summary of a whole scan

def summarize(target, db, on_line=None, proc_holder=None):
    items = db.findings()
    score, grade = db.score()
    top = [{k: f[k] for k in ("state", "severity", "stage", "file", "line", "message")} for f in items[:60]]
    prompt = f"""Here are the results of an automated bug scan of the project in the current directory.
Health score: {score}/100 (grade {grade}). Open findings: {len(items)} (showing up to 60):
{json.dumps(top, indent=1)}

Write a short report in Markdown for the developer (under 300 words):
## Summary  (2-3 sentences: overall state, the biggest risk)
## Fix first  (up to 5 items, most important first, each with file and why)
## Quick wins  (cheap fixes that remove many findings, e.g. one dependency upgrade)
## Probably noise  (findings that look like false positives, if any)
You may read files to check details; don't edit anything."""
    rc, text = run(prompt, target, READ_ONLY, on_line=on_line, proc_holder=proc_holder)
    path = os.path.join(paths.workspace(target), "summary.md")
    with open(path, "w") as fh:
        fh.write(text)
    return {"path": path, "text": text}
