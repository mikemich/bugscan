"""Claude features against a fake `claude` executable (no tokens spent)."""
import os
import unittest

from tests.helpers import FakeClaude, TempProject, needs
from bugscan import claude, detect, engine, findings

BUGGY = "def average(xs):\n    return sum(xs) / len(xs)\n"


def a_finding(p):
    run = engine.Scan(p.root, stages=["lint"]).db
    f = findings.make("fuzz", "fuzzer", "fuzz-crash", "high", "calc.py", 2, "ZeroDivisionError: division by zero", "return sum(xs) / len(xs)")
    r = run.begin_run("standard", ["fuzz"])
    run.ingest(r, "fuzz", [f], True)
    run.end_run(r)
    return run.findings()[0], run


class ClaudeTests(unittest.TestCase):
    def setUp(self):
        self.p = TempProject({"calc.py": BUGGY, "notes.txt": "keep me\n"}, git=True)
        self.f, self.db = a_finding(self.p)

    def tearDown(self):
        self.db.close()
        self.p.cleanup()

    def test_explain_is_read_only(self):
        with FakeClaude(explain="Verdict: Real issue - empty list.") as fc:
            rc, text = claude.explain(self.f, self.p.root)
            self.assertEqual((rc, text), (0, "Verdict: Real issue - empty list."))
            call = fc.calls()[0]
            self.assertEqual((call["tools"], call["mode"]), ("Read,Grep,Glob", None))
            self.assertIn("calc.py:2", call["prompt"])
            self.assertIn("return sum(xs) / len(xs)", call["prompt"])  # code context is included

    def test_stderr_is_captured_not_leaked(self):
        with FakeClaude(explain="ok", stderr="warning: rate limited"):
            rc, text = claude.explain(self.f, self.p.root)
        self.assertIn("warning: rate limited", text)

    def test_fix_review_and_undo(self):
        self.p.write({"notes.txt": "uncommitted edit\n"})  # the user's own uncommitted work must survive an undo
        fix = {"file": "calc.py", "old": "return sum(xs) / len(xs)", "new": "return sum(xs) / len(xs) if xs else 0.0"}
        with FakeClaude(fix=fix) as fc:
            r = claude.fix(self.f, self.p.root)
            self.assertEqual(fc.calls()[0]["mode"], "acceptEdits")
        self.assertEqual(r["tracked"], ["calc.py"])
        self.assertIn("+    return sum(xs) / len(xs) if xs else 0.0", r["diff"])
        self.assertNotIn("notes.txt", r["diff"])
        claude.revert(self.p.root, r["snapshot"], r["tracked"], r["new_files"])
        self.assertEqual(self.p.read("calc.py"), BUGGY)
        self.assertEqual(self.p.read("notes.txt"), "uncommitted edit\n")

    def test_fix_that_changes_nothing(self):
        with FakeClaude():
            r = claude.fix(self.f, self.p.root)
        self.assertEqual(r["diff"], "")
        self.assertIn("false positive", r["summary"])

    def test_fix_needs_git(self):
        plain = TempProject({"calc.py": BUGGY})
        try:
            with FakeClaude():
                self.assertIn("git", claude.fix(self.f, plain.root)["error"])
        finally:
            plain.cleanup()

    def test_new_files_are_removed_on_undo(self):
        snap = claude.snapshot(self.p.root)
        self.p.write({"extra.py": "x = 1\n", "calc.py": "changed\n"})
        tracked, new, diff = claude.changes_since(self.p.root, snap)
        self.assertEqual((tracked, new), (["calc.py"], ["extra.py"]))
        claude.revert(self.p.root, snap, tracked, new)
        self.assertFalse(os.path.exists(os.path.join(self.p.root, "extra.py")))
        self.assertEqual(self.p.read("calc.py"), BUGGY)

    @needs("semgrep")
    def test_rule_is_validated_then_saved(self):
        self.p.write({"other.py": "def mean(v):\n    return sum(v) / len(v)\n"})
        rule = ("- id: project.unguarded-mean\n  languages: [python]\n  severity: ERROR\n  message: guard empty input\n"
                "  pattern: sum($X) / len($X)")
        with FakeClaude(rule=rule):
            r = claude.write_rule(self.f, self.p.root, "diff")
        self.assertEqual(r["matches"], 2)
        with open(os.path.join(self.p.root, ".bugscan", "rules.yml")) as fh:
            saved = fh.read()
        self.assertTrue(saved.startswith("rules:\n  - id: project.unguarded-mean"))
        # the saved rule is then part of every scan
        res = engine.Scan(self.p.root, stages=["sast"]).run()
        ids = {f["rule"] for f in engine.Scan(self.p.root, stages=["lint"]).db.findings()}
        self.assertIn("project.unguarded-mean", ids)

    @needs("semgrep")
    def test_invalid_rule_is_retried_then_rejected(self):
        with FakeClaude(rule="- id: project.bad\n  languages: [python]\n  pattern: ((") as fc:
            r = claude.write_rule(self.f, self.p.root, "")
            self.assertEqual(len(fc.calls()), 2)  # one retry with the error
        self.assertIn("valid rule", r["error"])
        self.assertFalse(os.path.exists(os.path.join(self.p.root, ".bugscan", "rules.yml")))

    def test_harness_written_and_checked(self):
        harness = {"path": ".bugscan/fuzz/harness.py",
                   "content": "from calc import average\nSEEDS = [[1, 2]]\nTARGETS = {'average': lambda x: average(x) if isinstance(x, list) and all(type(i) is int for i in x) else None}\n"}
        with FakeClaude(harness=harness) as fc:
            r = claude.write_harness(self.p.root, detect.detect(self.p.root))
            call = fc.calls()[0]
        self.assertNotIn("error", r)
        self.assertIn("Bash(python3:*)", call["tools"])
        self.assertIn("fuzz (average)", r["check"])
        self.assertTrue(engine.Project(self.p.root).availability("fuzz")[0])

    def test_broken_harness_is_reported(self):
        with FakeClaude(harness={"path": ".bugscan/fuzz/harness.py", "content": "import nothing_here\n"}):
            r = claude.write_harness(self.p.root, detect.detect(self.p.root))
        self.assertIn("doesn't load", r["error"])

    def test_harness_needs_supported_language(self):
        go = TempProject({"main.go": "package main"})
        try:
            self.assertIn("support", claude.write_harness(go.root, detect.detect(go.root))["error"])
        finally:
            go.cleanup()

    def test_summary(self):
        with FakeClaude(summary="## Summary\nAll good.") as fc:
            r = claude.summarize(self.p.root, self.db)
            self.assertIn("calc.py", fc.calls()[0]["prompt"])
        self.assertEqual(r["text"], "## Summary\nAll good.")
        self.assertTrue(os.path.exists(r["path"]))

    def test_missing_claude(self):
        old = os.environ.get("BUGSCAN_CLAUDE")
        os.environ["BUGSCAN_CLAUDE"] = "/nonexistent/claude"
        try:
            self.assertFalse(claude.available())
            rc, text = claude.explain(self.f, self.p.root)
            self.assertEqual(rc, 127)
            self.assertIn("isn't installed", text)
        finally:
            if old is None:
                os.environ.pop("BUGSCAN_CLAUDE")
            else:
                os.environ["BUGSCAN_CLAUDE"] = old
