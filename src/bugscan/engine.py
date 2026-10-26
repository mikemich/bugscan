"""Runs scans: picks checks for a scan level, runs them, stores findings, scores the result.
Used by the interactive UI and the command line."""
import os
import subprocess
import time

from . import config as config_mod
from . import detect, findings, paths
from .stages import all_stages
from .stages.base import Ctx

PROFILES = {
    "quick": {"title": "Quick", "desc": "changed files only · no fuzzing", "fuzz": 0},
    "standard": {"title": "Standard", "desc": "everything · 1 min fuzzing", "fuzz": 60},
    "deep": {"title": "Deep", "desc": "everything · 30 min fuzzing", "fuzz": 1800},
}
PROFILE_ORDER = ["quick", "standard", "deep"]


class Project:
    """A folder plus what we know about it: detection, config, available checks."""

    def __init__(self, target):
        self.target = os.path.realpath(target)
        self.config = config_mod.load(self.target)
        self.info = detect.detect(self.target, self.config["scan"]["exclude"])
        self.stages = all_stages(self.config)

    def stage(self, key):
        return next((s for s in self.stages if s.key == key), None)

    def availability(self, key):
        s = self.stage(key)
        return s.applies(self.info, self.config) if s else (False, "unknown check")

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
        self.ctx = None
        self.state = {k: {"status": "queued"} for k in self.stages}

    def run(self):
        p = self.project
        run_id = self.db.begin_run(self.profile, self.stages)
        changed = changed_files(self.target, self.staged) if self.profile == "quick" else None
        for key in self.stages:
            if self.cancelled:
                self.state[key] = {"status": "cancelled"}
                self.on_stage(key, self.state[key])
                continue
            stage = p.stage(key)
            started = time.time()
            self.state[key] = {"status": "running", "started": started}
            self.on_stage(key, self.state[key])
            self.on_line(f"━━ {stage.title} ━━")
            ctx = Ctx(self.target, p.info, p.config, self.ws, self.profile, self.fuzz,
                      changed=changed,
                      staged=self.staged, log=self.on_line, should_stop=lambda: self.cancelled)
            self.ctx = ctx
            with open(os.path.join(self.ws, f"{key}.log"), "w") as logfile:
                ctx.logfile = logfile
                try:
                    res = stage.run(ctx)
                except Exception as e:  # a broken check must not kill the scan
                    from .stages.base import error
                    res = error(f"{type(e).__name__}: {e}")
                    ctx.log(res.note)
            st = {"status": res.status, "secs": int(time.time() - started), "note": res.note}
            if self.cancelled:
                st["status"] = "cancelled"
            elif res.status == "ok":
                st.update(self.db.ingest(run_id, key, res.items, res.complete))
                st["status"] = "new" if st["new"] or st["came_back"] else "issues" if st["found"] else "clean"
            elif res.status == "skip":
                st["status"] = "skipped"
                self.on_line(f"skipped: {res.note}")
            else:
                self.on_line(f"error: {res.note}")
            self.state[key] = st
            self.db.record_stage(run_id, key, st["status"], st["secs"], st.get("found", 0), st.get("new", 0))
            self.on_stage(key, st)
        score = self.db.end_run(run_id)
        return {"run": run_id, "score": score, "grade": findings.grade(score), "stages": self.state}

    def cancel(self):
        self.cancelled = True
        if self.ctx:
            self.ctx.stop()
