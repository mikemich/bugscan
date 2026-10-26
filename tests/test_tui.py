"""Drives the real curses UI in a pseudo-terminal and checks what's on screen."""
import json
import os
import time
import unittest

from tests.helpers import FakeClaude, TempProject, Tui, needs

CONFIG = '[[check]]\nname = "probe"\ntitle = "Probe"\ndescription = "custom check from config"\nrun = "true"\nlevels = ["quick", "standard"]\n'


class TuiTests(unittest.TestCase):
    def setUp(self):
        self.p = TempProject({"app.py": "x = 1\n", "broken.py": "def (:\n", ".bugscan/config.toml": CONFIG}, git=True)
        self.ui = None

    def tearDown(self):
        if self.ui:
            self.ui.close()
        self.p.cleanup()

    def start(self, *args, env=None, rows=34, cols=120):
        self.ui = Tui([*(args or [self.p.root])], rows=rows, cols=cols, env=env)
        return self.ui

    def expect(self, *texts, timeout=10):
        ok = self.ui.wait_for(*texts, timeout=timeout)
        self.assertTrue(ok, f"expected {texts} on screen:\n{self.ui.text()}")

    def test_scan_findings_explain_fix_undo_and_keep(self):
        fix = {"file": "broken.py", "old": "def (:", "new": "x = 2"}
        with FakeClaude(explain="Verdict: Real issue - broken syntax.\nHow to fix: write valid Python.", fix=fix):
            env = {k: os.environ[k] for k in ("BUGSCAN_CLAUDE", "FAKE_CLAUDE")}
            self.start(env=env)
            self.expect("BUG SCANNER", "Probe", "custom check from config", "Syntax lint", "no lockfiles found")
            self.ui.send("\r")
            self.expect("Scan done", timeout=60)
            self.expect("✗ 1 new")
            self.ui.send("f")
            self.expect("New 1", "broken.py:1")
            self.ui.send("\r")
            self.expect("Code", "def (:")
            self.ui.send("e")
            self.expect("Verdict: Real issue", timeout=20)
            self.ui.send("x")
            self.expect("Proposed fix", "+x = 2", timeout=20)
            self.ui.send("n")
            self.expect("Change undone")
            self.assertEqual(self.p.read("broken.py"), "def (:\n")
            self.ui.send("x")
            self.expect("Proposed fix", timeout=20)
            self.ui.send("y")
            self.expect("Verified", timeout=60)
            self.assertEqual(self.p.read("broken.py"), "x = 2\n")

    def test_help_tools_levels_log_and_picker(self):
        other = TempProject({"pkg/main.go": "package main\n", "go.mod": "module x\n"})
        try:
            self.start()
            self.expect("Standard")
            self.ui.send("?")
            self.expect("MAIN SCREEN", "STATES")
            self.ui.send("q")
            self.ui.send("d")
            self.expect("semgrep", "osv-scanner")
            self.ui.send("q")
            self.ui.send("1")
            self.expect("changed files only")
            self.ui.send("l")
            self.expect("No log yet")
            self.ui.send("t")
            self.expect("Choose a folder")
            self.ui.send("/")
            self.expect("Path:")
            self.ui.send("\x15" + other.root + "\r")
            self.expect("pkg/")
            self.ui.send("s")
            self.expect("Go", "Memory & races")
        finally:
            other.cleanup()

    def test_watch_and_hook(self):
        self.start()
        self.expect("BUG SCANNER")
        self.ui.send("w")
        self.expect("watching")
        time.sleep(3)
        self.p.write({"new.py": "def (:\n"})
        self.expect("Quick scan", timeout=15)
        self.expect("Scan done", timeout=60)
        self.ui.send("h")
        self.expect("hook on")
        self.ui.send("h")
        self.expect("Removed")

    def test_small_terminal(self):
        self.start(rows=12, cols=50)
        self.expect("Make the terminal bigger")
