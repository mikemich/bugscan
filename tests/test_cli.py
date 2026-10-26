import json
import os
import unittest

from tests.helpers import FakeClaude, TempProject, fake_token, needs, run_cli
from bugscan import engine, findings, report

CHECK = '[[check]]\nname = "probe"\nrun = "test -f bad && echo \'app.py:1: problem here\' && exit 1 || exit 0"\nlevels = ["quick", "standard"]\n' \
        'severity = "{sev}"\nmatchers = [{{ regex = \'^(?P<file>\\S+):(?P<line>\\d+): (?P<message>.*)$\' }}]\n'


class CliScanTests(unittest.TestCase):
    def setUp(self):
        self.p = TempProject({"app.py": "x = 1\n", ".bugscan/config.toml": CHECK.format(sev="medium")}, git=True)

    def tearDown(self):
        self.p.cleanup()

    def scan(self, *args):
        return run_cli("scan", "-t", self.p.root, "--stages", "probe,lint", *args)

    def test_exit_codes_follow_new_findings(self):
        self.assertEqual(self.scan().returncode, 0)
        self.p.write({"bad": ""})
        r = self.scan()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("problem here", r.stdout)
        self.assertEqual(self.scan().returncode, 0)                  # not new any more
        self.assertEqual(self.scan("--fail-on", "any").returncode, 1)
        self.assertEqual(self.scan("--fail-on", "any", "--min-severity", "high").returncode, 0)

    def test_exports_and_out_folder(self):
        self.p.write({"bad": ""})
        out = os.path.join(self.p.root, "results")
        r = self.scan("--out", out, "--sarif", os.path.join(out, "x.sarif"), "--json", os.path.join(out, "x.json"), "--fail-on", "none")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(out, "findings.db")))
        with open(os.path.join(out, "x.sarif")) as fh:
            sarif = json.load(fh)
        self.assertEqual(sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.py")
        with open(os.path.join(out, "x.json")) as fh:
            data = json.load(fh)
        self.assertEqual(data["findings"][0]["state"], "new")

    def test_findings_show_ignore(self):
        self.p.write({"bad": ""})
        self.scan()
        items = json.loads(run_cli("findings", "-t", self.p.root, "--json").stdout)
        fid = items[0]["id"]
        self.assertIn("problem here", run_cli("show", "-t", self.p.root, fid).stdout)
        self.assertIn("Ignored", run_cli("ignore", "-t", self.p.root, fid).stdout)
        self.assertEqual(json.loads(run_cli("findings", "-t", self.p.root, "--json").stdout), [])
        self.assertEqual(run_cli("show", "-t", self.p.root, "zzzz").returncode, 2)

    def test_explain_and_fix_through_cli(self):
        self.p.write({"bad": ""})
        self.scan()
        fid = json.loads(run_cli("findings", "-t", self.p.root, "--json").stdout)[0]["id"]
        with FakeClaude(explain="Verdict: Real issue - because.", fix={"file": "app.py", "old": "x = 1", "new": "x = 2"}):
            env = {k: os.environ[k] for k in ("BUGSCAN_CLAUDE", "FAKE_CLAUDE")}
            r = run_cli("explain", "-t", self.p.root, fid, env=env)
            self.assertIn("Real issue", r.stdout)
            self.assertIn("Real issue", run_cli("show", "-t", self.p.root, fid).stdout)  # stored
            r = run_cli("fix", "-t", self.p.root, fid, env=env, timeout=120)  # no tty: answers "no"
        self.assertIn("Undone", r.stdout)
        self.assertEqual(self.p.read("app.py"), "x = 1\n")


class CliMiscTests(unittest.TestCase):
    def test_version_help_and_errors(self):
        self.assertIn("bugscan 0.", run_cli("--version").stdout)
        self.assertEqual(run_cli().returncode, 2)  # no tty: the UI refuses politely
        self.assertEqual(run_cli("scan", "-t", "/no/such/dir").returncode, 2)
        p = TempProject({".bugscan/config.toml": '[scan]\nlevel = "turbo"\n'})
        try:
            r = run_cli("scan", "-t", p.root)
            self.assertEqual(r.returncode, 2)
            self.assertIn("Config error", r.stderr)
            r = run_cli("scan", "-t", p.root, "--stages", "nope")
        finally:
            p.cleanup()

    def test_init(self):
        p = TempProject()
        try:
            self.assertEqual(run_cli("init", "-t", p.root).returncode, 0)
            self.assertTrue(os.path.exists(os.path.join(p.root, ".bugscan", "config.toml")))
            self.assertEqual(run_cli("init", "-t", p.root).returncode, 1)
            self.assertEqual(run_cli("scan", "-t", p.root, "--stages", "lint").returncode, 0)
        finally:
            p.cleanup()

    def test_doctor(self):
        r = run_cli("doctor")
        self.assertIn("semgrep", r.stdout)
        self.assertIn(r.returncode, (0, 1))


class HookTests(unittest.TestCase):
    @needs("git")
    def test_hook_blocks_new_issues_and_chains_existing_hook(self):
        p = TempProject({"app.py": "x = 1\n"}, git=True)
        try:
            hook = os.path.join(p.root, ".git", "hooks", "pre-commit")
            os.makedirs(os.path.dirname(hook), exist_ok=True)
            with open(hook, "w") as fh:
                fh.write("#!/bin/sh\necho existing-hook-ran\n")
            os.chmod(hook, 0o755)
            self.assertIn("existing hook still runs", run_cli("hook", "install", "-t", p.root).stdout)
            env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))
            p.write({"broken.py": "def (:\n"})
            p.git("add", "broken.py")
            import subprocess
            r = subprocess.run(["git", "-C", p.root, "-c", "user.name=t", "-c", "user.email=t@e", "commit", "-m", "x"],
                               capture_output=True, text=True, env=env)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("existing-hook-ran", r.stdout + r.stderr)
            self.assertIn("bugscan found new issues", r.stdout + r.stderr)
            p.write({"broken.py": "x = 2\n"})
            p.git("add", "broken.py")
            r = subprocess.run(["git", "-C", p.root, "-c", "user.name=t", "-c", "user.email=t@e", "commit", "-m", "ok"],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("original pre-commit hook is restored", run_cli("hook", "uninstall", "-t", p.root).stdout)
            with open(hook) as fh:
                self.assertIn("existing-hook-ran", fh.read())
        finally:
            p.cleanup()

    def test_not_a_repo(self):
        p = TempProject()
        try:
            self.assertIn("Not a git repository", run_cli("hook", "install", "-t", p.root).stdout)
        finally:
            p.cleanup()


class ReportTests(unittest.TestCase):
    def test_report_escapes_and_shows_score(self):
        p = TempProject({"a.py": "x = 1\n"})
        try:
            proj = engine.Project(p.root)
            db = findings.DB(p.root)
            r = db.begin_run("standard", ["lint"])
            db.ingest(r, "lint", [findings.make("lint", "t", "r", "high", "a.py", 1, "<script>alert(1)</script>")], True)
            db.record_stage(r, "lint", "new", 1, 1, 1)
            db.end_run(r)
            path = report.write(proj)
            with open(path) as fh:
                html = fh.read()
            self.assertNotIn("<script>alert", html)
            self.assertIn("&lt;script&gt;", html)
            self.assertIn("Grade B", html)
            self.assertIn("Syntax lint", html)
        finally:
            p.cleanup()
