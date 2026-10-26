import json
import os

from .. import findings
from .base import Result, Stage, error, skip


class Secrets(Stage):
    key, title, description = "secrets", "Secrets", "leaked keys & tokens (gitleaks)"
    levels = ("quick", "standard", "deep")
    tools = ("gitleaks",)

    def run(self, ctx):
        if self.missing_tool():
            return skip("gitleaks is not installed (see bugscan doctor)")
        report = ctx.out("gitleaks.json")
        if os.path.exists(report):
            os.remove(report)
        git = ctx.info["git"]
        cmd = ["gitleaks", "git" if git else "dir", "--no-banner", "--redact", "--report-format", "json", "--report-path", report]
        complete = True
        if git and ctx.quick:  # only uncommitted (or staged) changes
            cmd.append("--pre-commit")
            if ctx.staged:
                cmd.append("--staged")
            complete = False
        rc, _ = ctx.run(cmd + [ctx.target])
        if not os.path.exists(report):
            return error(f"gitleaks failed (exit {rc})")
        return Result("ok", parse(report, ctx.src, ctx.exclude), complete=complete)


def parse(report, src, exclude=()):
    from ..detect import skipped
    out = []
    with open(report) as fh:
        data = json.load(fh) or []
    for d in data:
        file = src.rel(d.get("File"))
        if file and skipped(file, exclude):
            continue
        desc = (d.get("Description") or "Possible secret").rstrip(".")
        where = f" Found in commit {d['Commit'][:8]}." if d.get("Commit") else ""
        out.append(findings.make("secrets", "gitleaks", d.get("RuleID", "secret"), "critical", file, d.get("StartLine"),
                                 f"{desc}.{where} Rotate the secret, then remove it from the code (and git history).",
                                 key=d.get("Fingerprint") or f"{file}:{d.get('StartLine')}:{d.get('RuleID')}",
                                 commit=d.get("Commit")))
    return out
