"""Checks a project declares in .bugscan/config.toml: run any command, read its findings from SARIF,
from regex matchers over its output, or (if neither) report a failure when it exits non-zero.
Exit code 77 means "can't run here" and skips the check (its last output line is shown as the reason)."""
import os
import shutil

from .. import findings, paths
from .base import Result, Stage, error, skip


class Custom(Stage):
    def __init__(self, check):
        self.check = check
        self.key, self.title, self.description = check["name"], check["title"], check["description"]
        self.levels = tuple(check["levels"])

    def run(self, ctx):
        c = self.check
        missing = next((t for t in c["requires"] if not shutil.which(t)), None)
        if missing:
            return skip(f"needs {missing}")
        work = os.path.join(ctx.ws, "custom", c["name"])
        os.makedirs(work, exist_ok=True)
        sarif = os.path.join(work, "results.sarif")
        if os.path.exists(sarif):
            os.remove(sarif)
        env = {"BUGSCAN_TARGET": ctx.target, "BUGSCAN_OUT": work, "BUGSCAN_SARIF": sarif, "BUGSCAN_LEVEL": ctx.profile,
               "BUGSCAN_FUZZ_SECONDS": str(max(1, ctx.fuzz_seconds)),
               "BUGSCAN_SEEDS": os.path.join(paths.workspace(ctx.target), "seeds")}
        if ctx.changed is not None:
            listing = os.path.join(work, "changed.txt")
            with open(listing, "w") as fh:
                fh.write("".join(f + "\n" for f in ctx.changed))
            env["BUGSCAN_CHANGED"] = listing
        rc, out = ctx.run(c["run"], env=env, timeout=c["timeout"], shell=True)
        if ctx.should_stop():
            return error("cancelled")
        if rc == 77:  # convention: "can't run here" (e.g. a missing service), like automake's skip code
            last = out.strip().splitlines()[-1] if out.strip() else "the check skipped itself"
            return skip(last[:200])
        items = []
        if c["sarif"] and os.path.exists(sarif):
            try:
                items = findings.from_sarif(sarif, c["name"], ctx.src, c["severity"])
            except (ValueError, KeyError) as e:
                return error(f"couldn't read {sarif}: {e}")
        items += findings.from_matchers(out, c["matchers"], c["name"], c["name"], ctx.src)
        if rc != 0 and not items:
            tail = "\n".join(l for l in out.strip().splitlines()[-8:])
            if rc == 127 and "not found" in out:
                return error(f"command not found: {c['run']}")
            items.append(findings.make(c["name"], c["name"], "check-failed", c["severity"], None, None,
                                       f"`{c['run']}` failed (exit {rc}).\n{tail}", key=f"exit|{c['run']}"))
        return Result("ok", items)
