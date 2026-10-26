import json
import os
import re

from .. import detect, findings, paths
from .base import Result, Stage, error, skip

SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


class Sast(Stage):
    key, title, description = "sast", "Static analysis", "Semgrep bug & security rules"
    levels = ("quick", "standard", "deep")
    tools = ("semgrep",)

    def run(self, ctx):
        if self.missing_tool():
            return skip("semgrep is not installed (see bugscan doctor)")
        configs = rule_configs(ctx, log=ctx.log)
        report = ctx.out("semgrep.json")
        if os.path.exists(report):
            os.remove(report)
        cmd = ["semgrep", "scan", "--metrics=off", "--quiet", "--json-output", report, "--text", "--exclude", ".bugscan"]
        for c in configs:
            cmd += ["--config", c]
        for e in ctx.exclude:
            cmd += ["--exclude", e]
        targets, complete = ["."], True
        if ctx.quick:  # only the changed files (new findings in them show as new, known ones stay open)
            changed = [f for f in ctx.changed if not detect.skipped(f, ctx.exclude) and os.path.isfile(os.path.join(ctx.target, f))]
            if not changed:
                ctx.log("no changed files to check")
                return Result("ok", [], complete=False)
            if len(changed) <= 1000:
                targets, complete = changed, False
        rc, _ = ctx.run(cmd + ["--"] + targets)
        if not os.path.exists(report):
            return error(f"semgrep failed (exit {rc})")
        return Result("ok", parse(report, ctx.src, local_rule_ids(configs)), complete=complete)


def rule_configs(ctx, log=print):
    """Cached registry packs for the detected languages + built-in rules + the project's own rules."""
    from .. import sync
    packs = detect.packs_for(ctx.info, deep=ctx.profile == "deep")
    cached = sync.rules(packs, log=log)
    configs = [cached[p] for p in packs if p in cached]
    if len(configs) < len(packs) and not cached:
        configs = [p for p in packs if p not in sync.missing_packs()]  # offline and nothing cached: let semgrep fetch
    configs.append(paths.data("rules.yml"))
    local = os.path.join(paths.project_dir(ctx.target), "rules.yml")
    if os.path.exists(local):
        configs.append(local)
    return configs


def local_rule_ids(configs):
    """Ids declared in local rule files (built-in and project rules)."""
    ids = set()
    for c in configs:
        if os.path.isfile(c) and not c.startswith(paths.cache_root()):
            with open(c) as fh:
                ids |= set(re.findall(r"^\s*-\s*id:\s*['\"]?([\w.-]+)", fh.read(), re.M))
    return ids


def parse(report, src, local_ids=()):
    with open(report) as fh:
        data = json.load(fh)
    out = []
    for r in data.get("results", []):
        file, line = src.rel(r["path"]), r["start"]["line"]
        ex = r.get("extra", {})
        rule = r["check_id"]
        # semgrep prefixes ids from local rule files with the file's path: map back to the declared id
        rule = next((i for i in sorted(local_ids, key=len, reverse=True) if rule == i or rule.endswith("." + i)), rule)
        refs = ex.get("metadata", {}).get("references") or []
        out.append(findings.make("sast", "semgrep", rule, SEVERITY.get(ex.get("severity"), "medium"), file, line,
                                 ex.get("message", ""), src.line(file, line), url=refs[0] if refs else None))
    return out
