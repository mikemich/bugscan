import glob
import json
import os
import shutil

from .. import findings, paths
from .base import Result, Stage, error, skip


def seed_dirs(target):
    """Extra fuzz seeds: committed ones in .bugscan/fuzz/seeds, plus real inputs recorded by `bugscan sync`."""
    dirs = [os.path.join(paths.project_dir(target), "fuzz", "seeds"), os.path.join(paths.workspace(target), "seeds")]
    return [d for d in dirs if os.path.isdir(d)]


def known(path):
    try:
        with open(path) as fh:
            return {l.strip() for l in fh if l.strip() and not l.startswith("#")}
    except OSError:
        return set()


class Fuzz(Stage):
    key, title, description = "fuzz", "Fuzzing", "runs your .bugscan/fuzz harness"

    def applies(self, info, config):
        return (True, "") if info["harness"] else (False, "no fuzz harness yet · press g")

    def run(self, ctx):
        harness = ctx.info["harness"]
        node = harness.endswith(".mjs")
        runner = "node" if node else "python3"
        if not shutil.which(runner):
            return skip(f"{runner} is not installed")
        work = ctx.out("fuzz")
        shutil.rmtree(work, ignore_errors=True)  # crash files are per run; history lives in .bugscan/fuzz/regressions
        os.makedirs(work)
        driver = paths.data("driver.mjs" if node else "driver.py")
        env = {"BUGSCAN_SEEDS": os.pathsep.join(seed_dirs(ctx.target))}
        rc, out = ctx.run([runner, driver, harness, str(max(1, ctx.fuzz_seconds)), work], env=env)
        if "HARNESS ERROR" in out:
            return error("the fuzz harness doesn't load (see the log)")
        accepted = known(os.path.join(os.path.dirname(harness), "known-crashes.txt"))
        items = []
        for path in sorted(glob.glob(os.path.join(work, "crash-*.json"))):
            with open(path) as fh:
                c = json.load(fh)
            if c.get("signature") in accepted:
                continue
            items.append(findings.make("fuzz", "fuzzer", "fuzz-crash", "high", c.get("file"), c.get("line"),
                                       f"Crash when fuzzing `{c.get('target')}`: {c.get('message', '')}", key=c.get("signature"),
                                       snippet=ctx.src.line(c.get("file"), c.get("line")), repro=path, signature=c.get("signature")))
        if rc not in (0, 1) and not items:
            return error(f"the fuzzer exited with {rc}")
        return Result("ok", items)  # saved crash inputs are replayed every run, so this is complete
