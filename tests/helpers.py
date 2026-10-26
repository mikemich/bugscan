"""Shared test helpers: temp projects, tool checks, an isolated cache, a fake `claude`, and a pty driver."""
import codecs
import fcntl
import json
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, SRC)

# One cache for the whole test run (keeps downloaded rule packs between runs), separate from yours.
os.environ.setdefault("BUGSCAN_CACHE", os.path.join(os.path.expanduser("~/.cache"), "bugscan-test"))
os.environ["NO_COLOR"] = "1"

OFFLINE = os.environ.get("BUGSCAN_TEST_OFFLINE") == "1"   # skip tests that need the network
FAST = os.environ.get("BUGSCAN_TEST_FAST") == "1"         # skip slow toolchain tests (Swift/Go builds)


def needs(*tools):
    missing = [t for t in tools if not shutil.which(t)]
    return unittest.skipIf(missing, f"needs {', '.join(missing)}")


def needs_network(fn):
    return unittest.skipIf(OFFLINE, "needs the network (BUGSCAN_TEST_OFFLINE=1)")(fn)


def slow(fn):
    return unittest.skipIf(FAST, "slow (BUGSCAN_TEST_FAST=1)")(fn)


class TempProject:
    """A throwaway project folder built from {relative path: content}."""

    def __init__(self, files=None, git=False):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="bugscan-test-"))
        self.write(files or {})
        if git:
            self.git("init", "-q", "-b", "main")
            self.commit("initial")

    def write(self, files):
        for rel, content in files.items():
            p = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(p, mode) as fh:
                fh.write(content)
        return self

    def read(self, rel):
        with open(os.path.join(self.root, rel)) as fh:
            return fh.read()

    def git(self, *args):
        return subprocess.run(["git", "-C", self.root, "-c", "user.name=test", "-c", "user.email=test@example.com",
                               "-c", "commit.gpgsign=false", *args], capture_output=True, text=True)

    def commit(self, msg="change"):
        self.git("add", "-A")
        return self.git("commit", "-q", "--allow-empty", "-m", msg)

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def copy_fixture(name, git=False):
    p = TempProject()
    shutil.rmtree(p.root)
    shutil.copytree(os.path.join(FIXTURES, "projects", name), p.root, ignore=shutil.ignore_patterns(".build"))
    if git:
        p.git("init", "-q", "-b", "main")
        p.commit("initial")
    return p


def fake_token():
    """A realistic-looking GitHub token generated at test time (never committed)."""
    import random
    import string
    r = random.Random(1234)
    return "ghp_" + "".join(r.choice(string.ascii_letters + string.digits) for _ in range(36))


def bugscan_cmd(*args):
    return [sys.executable, "-m", "bugscan", *args]


def run_cli(*args, cwd=None, env=None, timeout=900):
    e = dict(os.environ, PYTHONPATH=SRC, **(env or {}))
    return subprocess.run(bugscan_cmd(*args), capture_output=True, text=True, cwd=cwd, env=e, timeout=timeout,
                          stdin=subprocess.DEVNULL)


class FakeClaude:
    """Points BUGSCAN_CLAUDE at tests/fake_claude.py with a scripted behaviour; records every call."""

    def __init__(self, **behaviour):
        self.dir = tempfile.mkdtemp(prefix="fake-claude-")
        self.log = os.path.join(self.dir, "calls.jsonl")
        self.script = os.path.join(self.dir, "claude")
        with open(self.script, "w") as fh:
            fh.write(f"#!{sys.executable}\nimport runpy, sys\nsys.argv[0] = 'claude'\nrunpy.run_path({os.path.join(HERE, 'fake_claude.py')!r}, run_name='__main__')\n")
        os.chmod(self.script, 0o755)
        self.behaviour = behaviour

    def __enter__(self):
        self.old = {k: os.environ.get(k) for k in ("BUGSCAN_CLAUDE", "FAKE_CLAUDE")}
        os.environ["BUGSCAN_CLAUDE"] = self.script
        os.environ["FAKE_CLAUDE"] = json.dumps(dict(self.behaviour, log=self.log))
        return self

    def __exit__(self, *exc):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.dir, ignore_errors=True)

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as fh:
            return [json.loads(l) for l in fh]


# ── driving the TUI in a pseudo-terminal ───────────────────────────────────────────────────────────

class Tui:
    def __init__(self, args, rows=34, cols=120, env=None):
        from tests import vt
        self.rows, self.cols = rows, cols
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ.update(env or {})
            os.environ.update({"TERM": "xterm-256color", "PYTHONPATH": SRC})
            os.execv(sys.executable, bugscan_cmd(*args))
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.screen = vt.Screen(rows, cols)
        self.dec = codecs.getincrementaldecoder("utf-8")("replace")

    def pump(self, t):
        end = time.monotonic() + t
        while time.monotonic() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    self.screen.feed(self.dec.decode(os.read(self.fd, 65536)))
                except OSError:
                    return

    def text(self):
        return self.screen.text()

    def flat(self):
        return re.sub(r"\s+", " ", self.text())

    def send(self, keys):
        os.write(self.fd, keys.encode() if isinstance(keys, str) else keys)

    def wait_for(self, *texts, timeout=10):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.pump(0.2)
            if all(t in self.flat() for t in texts):
                return True
        return False

    def close(self):
        try:
            self.send("qqqq")
            self.pump(1)
            os.kill(self.pid, 9)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass
