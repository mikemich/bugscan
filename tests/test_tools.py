"""Checks that drive real tools (gitleaks, semgrep, osv-scanner, go, swift). Skipped when a tool is missing."""
import json
import sys
import unittest

from tests.helpers import TempProject, copy_fixture, fake_token, needs, needs_network, slow
from bugscan import engine

LOCK = json.dumps({"name": "demo", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
    "": {"name": "demo", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
    "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}}})


def run(p, *stages, **kw):
    s = engine.Scan(p.root, stages=list(stages), **kw)
    res = s.run()
    return res, s.db.findings()


def diag(p, res, stage):
    """Status, note and log tail of a check, for assertion messages (CI failures explain themselves)."""
    import os
    from bugscan import paths
    st = res["stages"].get(stage, {})
    log = os.path.join(paths.workspace(p.root), f"{stage}.log")
    tail = "(no log)"
    if os.path.exists(log):
        with open(log) as fh:
            tail = fh.read()[-3000:]
    return f"\n{stage}: {st.get('status')} {st.get('note', '')}\n--- log tail ---\n{tail}"


class SecretsTests(unittest.TestCase):
    @needs("gitleaks", "git")
    def test_git_history_and_quick_staged(self):
        p = TempProject({"README.md": "hi\n"}, git=True)
        try:
            p.write({"config.py": f'TOKEN = "{fake_token()}"\n'})
            res, items = run(p, "secrets", profile="quick", staged=True)
            self.assertEqual(res["stages"]["secrets"]["found"], 0)  # not staged yet
            p.git("add", "config.py")
            res, items = run(p, "secrets", profile="quick", staged=True)
            self.assertEqual(res["stages"]["secrets"]["found"], 1)
            p.commit("leak")
            res, items = run(p, "secrets")
            leak = [f for f in items if f["stage"] == "secrets"]
            self.assertEqual((leak[0]["file"], leak[0]["severity"]), ("config.py", "critical"))
            self.assertIn("Found in commit", leak[0]["message"])
        finally:
            p.cleanup()

    @needs("gitleaks")
    def test_plain_folder(self):
        p = TempProject({"a/key.txt": f"token={fake_token()}\n"})
        try:
            res, _ = run(p, "secrets")
            self.assertEqual(res["stages"]["secrets"]["found"], 1)
        finally:
            p.cleanup()


class SastTests(unittest.TestCase):
    @needs("semgrep")
    @needs_network
    def test_builtin_and_project_rules(self):
        p = TempProject({
            "web/app.js": "const el = document.getElementById('o');\nel.innerHTML = `<b>${location.hash}</b>`;\n",
            "svc.py": "def f():\n    try:\n        g()\n    except:\n        pass\n",
            ".bugscan/rules.yml": "rules:\n  - id: project.no-print\n    languages: [python]\n    severity: INFO\n    message: no print\n    pattern: print(...)\n",
            "tool.py": "print('x')\n",
        })
        try:
            res, items = run(p, "sast")
            rules = {f["rule"] for f in items}
            self.assertIn("bugscan.js-innerhtml-template", rules)
            self.assertIn("bugscan.python-bare-except-pass", rules)
            self.assertIn("project.no-print", rules)
            self.assertEqual(res["stages"]["sast"]["status"], "new")
        finally:
            p.cleanup()

    @needs("semgrep", "git")
    @needs_network
    def test_quick_reports_only_new_code(self):
        p = TempProject({"a.py": "try:\n    x()\nexcept:\n    pass\n"}, git=True)
        try:
            p.write({"b.py": "try:\n    y()\nexcept:\n    pass\n"})
            res, items = run(p, "sast", profile="quick")
            self.assertEqual({f["file"] for f in items}, {"b.py"})
        finally:
            p.cleanup()


class DepsTests(unittest.TestCase):
    @needs("osv-scanner")
    @needs_network
    def test_vulnerable_lockfile(self):
        p = TempProject({"package-lock.json": LOCK, "requirements.txt": "django==2.0\n"})
        try:
            res, items = run(p, "deps")
            deps = {f["extra"]["package"]: f for f in items if f["stage"] == "deps"}
            self.assertTrue({"lodash", "django"} <= set(deps), f"{deps.keys()}" + diag(p, res, "deps"))  # one finding per package
            lodash = deps["lodash"]
            self.assertEqual(lodash["file"], "package-lock.json")
            self.assertGreater(len(lodash["extra"]["advisories"]), 3)
            self.assertGreaterEqual(tuple(int(x) for x in lodash["extra"]["fixed"].split(".")), (4, 17, 21))
            # upgrading fixes them
            p.write({"package-lock.json": LOCK.replace("4.17.15", "4.17.21"), "requirements.txt": "django==5.2.8\n"})
            p.write({"package-lock.json": LOCK.replace("4.17.15", lodash["extra"]["fixed"])})
            res, items = run(p, "deps")
            self.assertGreaterEqual(res["stages"]["deps"]["fixed"], 1)
            self.assertNotIn("lodash", {f["extra"]["package"] for f in items if f["stage"] == "deps" and f["status"] == "open"})
        finally:
            p.cleanup()

    def test_not_applicable_without_lockfiles(self):
        p = TempProject({"a.py": ""})
        try:
            self.assertEqual(engine.Project(p.root).availability("deps"), (False, "no lockfiles found"))
        finally:
            p.cleanup()


class MemoryTests(unittest.TestCase):
    @needs("go")
    @slow
    def test_go(self):
        p = copy_fixture("go-race")
        try:
            res, items = run(p, "memory")
            rules = {(f["rule"], f["file"]) for f in items}
            self.assertIn(("data-race", "counter.go"), rules, diag(p, res, "memory"))
            self.assertIn(("go-vet", "counter.go"), rules)
            self.assertIn(("test-failure", "counter_test.go"), rules)
        finally:
            p.cleanup()

    @needs("swift")
    @slow
    def test_swift(self):
        p = copy_fixture("swift-race")
        try:
            res, items = run(p, "memory")
            rules = {f["rule"] for f in items}
            # ThreadSanitizer is reliable on macOS; on Linux it depends on the environment (it can hang or stay silent)
            expected = {"swift-concurrency", "test-failure"} | ({"data-race"} if sys.platform == "darwin" else set())
            self.assertTrue(expected <= rules, f"{rules}" + diag(p, res, "memory"))
            self.assertTrue(all(f["file"] and not f["file"].startswith("/") for f in items))
        finally:
            p.cleanup()

    def test_not_applicable_elsewhere(self):
        p = TempProject({"a.py": ""})
        try:
            self.assertFalse(engine.Project(p.root).availability("memory")[0])
        finally:
            p.cleanup()
