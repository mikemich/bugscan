"""Runs scans: picks checks for a scan level, runs them, stores findings, scores the result.
Used by the interactive UI and the command line."""
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import config as config_mod
from . import detect, findings, paths
from .stages import all_stages
from .stages.base import Ctx, error

PROFILES = {
    "quick": {"title": "Quick", "desc": "changed files only · no fuzzing", "fuzz": 0},
    "standard": {"title": "Standard", "desc": "everything · 1 min fuzzing", "fuzz": 60},
    "deep": {"title": "Deep", "desc": "everything · 30 min fuzzing", "fuzz": 1800},
}
PROFILE_ORDER = ["quick", "standard", "deep"]
PARALLEL = {"secrets", "sast", "lint", "deps"}  # quick, independent tools: run at the same time


class Project:
    """A folder plus what we know about it: detection, config, available checks."""

    def __init__(self, target):
        self.target = os.path.realpath(target)
        self.config = config_mod.load(self.target)
        self.info = detect.detect(self.target, self.config["scan"]["exclude"])
        self.stages = all_stages(self.config)
        self._avail = {}

    def stage(self, key):
        return next((s for s in self.stages if s.key == key), None)

    def availability(self, key):
        """(applies, reason). Cached: the UI asks on every redraw, and some checks look through the files."""
        if key not in self._avail:
            s = self.stage(key)
            self._avail[key] = ((False, "turned off in .bugscan/config.toml") if key in self.config["scan"]["skip"] else
                                s.applies(self.info, self.config) if s else (False, "unknown check"))
        return self._avail[key]

    def default_stages(self, profile):
        return [s.key for s in self.stages if profile in s.levels and self.availability(s.key)[0]]

    @property
    def titles(self):
        return {s.key: s.title for s in self.stages}


def changed_files(target, staged=False):
    """Paths changed since the last commit (plus untracked files), or None without git history."""
    def git(*args):
        r = subprocess.run(["git", "-C", target, *args], capture_output=True, text=True)
        return r.stdout.splitlines() if r.returncode == 0 else None
    if not os.path.isdir(os.path.join(target, ".git")) or git("rev-parse", "HEAD") is None:
        return None
    files = git("diff", "--name-only", "--cached" if staged else "HEAD") or []
    if not staged:
        files += git("ls-files", "--others", "--exclude-standard") or []
    return sorted(set(files))


class Scan:
    """One scan. Callbacks: on_line(text) for tool output, on_stage(key, state) for progress."""

    def __init__(self, project, profile=None, stages=None, fuzz=None, staged=False, on_line=None, on_stage=None):
        self.project = project if isinstance(project, Project) else Project(project)
        p = self.project
        self.target = p.target
        self.profile = profile or p.config["scan"]["level"]
        wanted = stages or p.default_stages(self.profile)
        unknown = [k for k in wanted if not p.stage(k)]
        if unknown:
            raise ValueError(f"unknown check(s): {', '.join(unknown)}. Available: {', '.join(s.key for s in p.stages)}")
        self.stages = [k for k in wanted if p.availability(k)[0]]
        cfg_fuzz = p.config["scan"]["fuzz_seconds"]
        self.fuzz = fuzz if fuzz is not None else cfg_fuzz if cfg_fuzz is not None else PROFILES[self.profile]["fuzz"] or 60
        self.staged = staged
        self.on_line = on_line or (lambda s: None)
        self.on_stage = on_stage or (lambda k, st: None)
        self.ws = paths.workspace(self.target)
        self.db = findings.DB(self.target)
        self.cancelled = False
        self.ctxs = []
        self.lock = threading.Lock()
        self.state = {k: {"status": "queued"} for k in self.stages}

    def run(self):
        """Run the checks: the quick independent ones in parallel, then the heavy ones one by one."""
        run_id = self.db.begin_run(self.profile, self.stages)
        changed = changed_files(self.target, self.staged) if self.profile == "quick" else None
        together = [k for k in self.stages if k in PARALLEL]
        alone = [k for k in self.stages if k not in PARALLEL]
        if len(together) > 1:
            with ThreadPoolExecutor(len(together)) as pool:
                list(pool.map(lambda k: self._run_stage(k, run_id, changed, label=True), together))
        else:
            alone = together + alone
        for key in alone:
            self._run_stage(key, run_id, changed)
        score = self.db.end_run(run_id)
        return {"run": run_id, "score": score, "grade": findings.grade(score), "stages": self.state}

    def _run_stage(self, key, run_id, changed, label=False):
        p = self.project
        stage = p.stage(key)
        if self.cancelled:
            self._set(key, {"status": "cancelled"})
            return
        started = time.time()
        self._set(key, {"status": "running", "started": started})
        log = (lambda s: self.on_line(f"[{stage.title}] {s}")) if label else self.on_line
        if not label:
            self.on_line(f"━━ {stage.title} ━━")
        ctx = Ctx(self.target, p.info, p.config, self.ws, self.profile, self.fuzz, changed=changed,
                  staged=self.staged, log=log, should_stop=lambda: self.cancelled)
        with self.lock:
            self.ctxs.append(ctx)
        with open(os.path.join(self.ws, f"{key}.log"), "w") as logfile:
            ctx.logfile = logfile
            try:
                res = stage.run(ctx)
            except Exception as e:  # a broken check must not kill the scan
                res = error(f"{type(e).__name__}: {e}")
                ctx.log(res.note)
        st = {"status": res.status, "secs": int(time.time() - started), "note": res.note}
        if self.cancelled:
            st["status"] = "cancelled"
        elif res.status == "ok":
            with self.lock:
                st.update(self.db.ingest(run_id, key, res.items, res.complete))
            st["status"] = "new" if st["new"] or st["came_back"] else "issues" if st["found"] else "clean"
        elif res.status == "skip":
            st["status"] = "skipped"
            log(f"skipped: {res.note}")
        else:
            log(f"error: {res.note}")
        with self.lock:
            self.db.record_stage(run_id, key, st["status"], st["secs"], st.get("found", 0), st.get("new", 0))
        self._set(key, st)

    def _set(self, key, st):
        self.state[key] = st
        self.on_stage(key, st)

    def cancel(self):
        self.cancelled = True
        with self.lock:
            for ctx in self.ctxs:
                ctx.stop()
