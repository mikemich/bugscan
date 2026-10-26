"""What every check (stage) gets and returns."""
import os
import re
import shutil
import signal
import subprocess
import threading

from .. import findings

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class Result:
    """status: ok (ran, findings may be empty) | skip (not applicable / tool missing) | error (couldn't run).
    complete: the check looked at the whole project, so findings it no longer reports are fixed."""

    def __init__(self, status, items=None, note="", complete=True):
        self.status, self.items, self.note, self.complete = status, items or [], note, complete


def skip(note):
    return Result("skip", note=note)


def error(note):
    return Result("error", note=note)


class Stage:
    key = title = description = ""
    levels = ("standard", "deep")
    tools = ()  # executables needed; a missing one skips the check

    def applies(self, ctx_info, config):
        """(True, "") or (False, reason shown in the UI)."""
        return True, ""

    def missing_tool(self):
        return next((t for t in self.tools if not shutil.which(t)), None)

    def run(self, ctx):
        raise NotImplementedError


class Ctx:
    """Everything a check needs: the project, settings, a place for files, and a way to run commands."""

    def __init__(self, target, info, config, ws, profile, fuzz_seconds, changed=None, staged=False,
                 log=None, should_stop=None):
        self.target, self.info, self.config, self.ws = target, info, config, ws
        self.profile, self.fuzz_seconds, self.changed, self.staged = profile, fuzz_seconds, changed, staged
        self._log = log or (lambda s: None)
        self.should_stop = should_stop or (lambda: False)
        self.logfile = None
        self.proc = None
        self.src = findings.Source(target)

    @property
    def exclude(self):
        return self.config["scan"]["exclude"]

    @property
    def quick(self):
        """True when only changed files should be looked at."""
        return self.changed is not None

    def out(self, *parts):
        p = os.path.join(self.ws, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def log(self, line):
        line = ANSI.sub("", str(line)).rstrip("\n").split("\r")[-1]
        if self.logfile:
            self.logfile.write(line + "\n")
            self.logfile.flush()
        self._log(line.replace(self.target + "/", ""))

    def run(self, cmd, cwd=None, env=None, timeout=None, quiet=False, shell=False):
        """Run a command, streaming its output to the log. Returns (exit code, output)."""
        full_env = dict(os.environ, **(env or {}))
        try:
            self.proc = subprocess.Popen(cmd, cwd=cwd or self.target, env=full_env, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, errors="replace",
                                         start_new_session=True, shell=shell)
        except FileNotFoundError:
            return 127, f"{cmd[0] if isinstance(cmd, list) else cmd}: not found"
        out, size = [], 0
        timer = threading.Timer(timeout, self.stop) if timeout else None
        if timer:
            timer.start()
        try:
            for line in self.proc.stdout:
                if size < 4_000_000:
                    out.append(line)
                    size += len(line)
                if not quiet:
                    self.log(line)
            self.proc.wait()
        finally:
            if timer:
                timer.cancel()
            self.proc.stdout.close()
        rc = self.proc.returncode
        self.proc = None
        return rc, "".join(out)

    def stop(self):
        p = self.proc
        if p and p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
