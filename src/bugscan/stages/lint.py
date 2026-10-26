"""Syntax-check every JS, shell, Python, JSON and plist file (only changed ones in quick mode)."""
import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .. import detect, findings
from .base import Result, Stage

KINDS = {".js": "js", ".mjs": "js", ".cjs": "js", ".sh": "shell", ".bash": "shell", ".py": "python", ".json": "json",
         ".webmanifest": "json", ".plist": "plist", ".entitlements": "plist"}


def check_js(path):
    r = subprocess.run(["node", "--check", path], capture_output=True, text=True)
    if r.returncode == 0:
        return None
    lines = [l for l in r.stderr.splitlines() if l.strip()]
    m = re.search(r":(\d+)$", lines[0]) if lines else None
    msg = next((l for l in lines if re.match(r"\w*Error:", l)), lines[-1] if lines else "syntax error")
    return int(m.group(1)) if m else 1, msg


def check_shell(path):
    r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
    if r.returncode == 0:
        return None
    m = re.search(r"line (\d+): (.*)", r.stderr)
    return (int(m.group(1)), m.group(2)) if m else (1, r.stderr.strip()[:200])


def check_python(path):
    try:
        with open(path, "rb") as fh:
            compile(fh.read(), path, "exec")
    except SyntaxError as e:
        return e.lineno or 1, f"SyntaxError: {e.msg}"
    except ValueError as e:
        return 1, str(e)
    return None


def check_json(path):
    name = os.path.basename(path)
    if name.startswith(("tsconfig", "jsconfig")) or "/.vscode/" in path or name.endswith(".jsonc"):
        return None  # these allow comments
    try:
        with open(path, encoding="utf-8-sig") as fh:
            text = fh.read()
        if text.strip():
            json.loads(text)
    except json.JSONDecodeError as e:
        return e.lineno, f"invalid JSON: {e.msg}"
    except UnicodeDecodeError:
        return 1, "not UTF-8"
    return None


def check_plist(path):
    r = subprocess.run(["plutil", "-lint", "-s", path], capture_output=True, text=True)
    return None if r.returncode == 0 else (1, (r.stdout + r.stderr).strip().split(": ", 1)[-1][:200])


CHECKS = {"js": (check_js, "node"), "shell": (check_shell, "bash"), "python": (check_python, None),
          "json": (check_json, None), "plist": (check_plist, "plutil")}


class Lint(Stage):
    key, title, description = "lint", "Syntax lint", "JS / Python / shell / JSON / plist"
    levels = ("quick", "standard", "deep")

    def run(self, ctx):
        if ctx.quick:
            files = [f for f in ctx.changed if not detect.skipped(f, ctx.exclude)]
        else:
            files = list(detect.walk(ctx.target, exclude=ctx.exclude))
        jobs = []
        for rel in files:
            kind = KINDS.get(os.path.splitext(rel)[1].lower())
            path = os.path.join(ctx.target, rel)
            if kind and os.path.isfile(path) and (CHECKS[kind][1] is None or shutil.which(CHECKS[kind][1])):
                jobs.append((kind, rel, path))
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda j: (j, CHECKS[j[0]][0](j[2])), jobs))
        items, counts = [], {}
        for (kind, rel, _), res in results:
            counts[kind] = counts.get(kind, 0) + 1
            if res:
                line, msg = res
                ctx.log(f"{rel}:{line}: {msg}")
                items.append(findings.make("lint", kind, f"{kind}-syntax", "high", rel, line, msg, ctx.src.line(rel, line), key=msg))
        ctx.log("checked " + ", ".join(f"{n} {k}" for k, n in counts.items()) if counts else "no files to check")
        return Result("ok", items, complete=not ctx.quick)
