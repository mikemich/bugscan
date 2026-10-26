"""0.2.0 features: .gitignore + nested repos, test suites, type checks/linters, upgrades, triage."""
import json
import os
import sqlite3
import unittest

from tests.helpers import FakeClaude, TempProject, needs, needs_network, slow
from bugscan import detect, engine, findings, paths, upgrade
from bugscan.stages import tests as tests_stage
from bugscan.stages import types as types_stage
from bugscan.stages.suites import suites

SRC = findings.Source("/P")


class FileListingTests(unittest.TestCase):
    def test_gitignore_and_nested_repos(self):
        p = TempProject({".gitignore": "data/\n*.log\n", "a.py": "", "data/x.json": "{", "run.log": "", "sub/b.py": ""}, git=True)
        nested = TempProject({"lib.rs": ""}, git=True)
        try:
            os.rename(nested.root, os.path.join(p.root, "inner"))
            files = set(detect.walk(p.root))
            self.assertIn("a.py", files)
            self.assertIn("sub/b.py", files)
            self.assertIn("inner/lib.rs", files)          # nested repository included
            self.assertNotIn("data/x.json", files)        # .gitignore respected
            self.assertNotIn("run.log", files)
        finally:
            p.cleanup()

    def test_plain_folder_still_walks(self):
        p = TempProject({"a.py": "", "node_modules/x.js": ""})
        try:
            self.assertEqual(list(detect.walk(p.root)), ["a.py"])
        finally:
            p.cleanup()


class SuiteDetectionTests(unittest.TestCase):
    def test_finds_suites_and_explains_skips(self):
        p = TempProject({
            "web/package.json": json.dumps({"scripts": {"test": "vitest run"}}),
            "app/package.json": json.dumps({"scripts": {"test": 'echo "Error: no test specified" && exit 1'}}),
            "core/Cargo.toml": "[package]\nname='c'\nversion='0.1.0'\n",
            "py/pyproject.toml": "", "py/tests/test_x.py": "def test_a(): pass\n",
        })
        try:
            got = {(k, d): why for k, d, cmd, why in suites(p.root)}
            self.assertIn(("npm", "web"), got)
            self.assertNotIn(("npm", "app"), got)                        # the npm placeholder isn't a suite
            self.assertIn("npm install", got[("npm", "web")])            # no node_modules: skipped with a reason
            self.assertIn(("cargo", "core"), got)
            self.assertTrue(("pytest", "py") in got or ("unittest", "py") in got, got)  # unittest when pytest is missing
        finally:
            p.cleanup()

    def test_no_suites_means_not_applicable(self):
        p = TempProject({"a.py": "x = 1\n"})
        try:
            self.assertEqual(engine.Project(p.root).availability("tests"), (False, "no test suite found"))
        finally:
            p.cleanup()


class UnittestFallbackTests(unittest.TestCase):
    def test_unittest_failures_are_found(self):
        p = TempProject({"pkg/__init__.py": "", "pkg/calc.py": "def avg(xs):\n    return sum(xs) / len(xs)\n",
                         "tests/__init__.py": "", "tests/test_calc.py":
                         "import unittest\nfrom pkg.calc import avg\n\nclass T(unittest.TestCase):\n    def test_empty(self):\n"
                         "        self.assertEqual(avg([]), 0)\n\n    def test_ok(self):\n        self.assertEqual(avg([2]), 2)\n"})
        try:
            from bugscan.stages import suites as suites_mod
            old = suites_mod.pytest_available
            suites_mod.pytest_available = lambda: False
            try:
                res = engine.Scan(p.root, stages=["tests"]).run()
            finally:
                suites_mod.pytest_available = old
            items = engine.Scan(p.root, stages=["lint"]).db.findings()
            t = [f for f in items if f["stage"] == "tests"]
            self.assertEqual(len(t), 1)
            self.assertEqual((t[0]["file"], t[0]["line"]), ("pkg/calc.py", 2))
            self.assertIn("ZeroDivisionError", t[0]["message"])
        finally:
            p.cleanup()

    def test_module_named_setup_is_not_a_project(self):
        p = TempProject({"src/tool/setup.py": "def check(): pass\n", "src/tool/__init__.py": "", "tests/test_a.py": ""})
        try:
            self.assertEqual([d for k, d, c, w in suites(p.root) if k in ("pytest", "unittest")], [""])
        finally:
            p.cleanup()


class OutputParserTests(unittest.TestCase):
    def test_pytest(self):
        out = ("tests/test_calc.py:7: AssertionError\n=== short test summary info ===\n"
               "FAILED tests/test_calc.py::test_avg - ZeroDivisionError: division by zero\nERROR tests/test_db.py::test_conn\n")
        items = tests_stage.parse_pytest(out, "backend", SRC)
        self.assertEqual([(f["file"], f["line"]) for f in items], [("backend/tests/test_calc.py", 7), ("backend/tests/test_db.py", None)])
        self.assertIn("ZeroDivisionError", items[0]["message"])

    def test_cargo(self):
        out = ("test tests::adds ... FAILED\ntest tests::other ... FAILED\n\n"
               "thread 'tests::adds' (4242) panicked at src/lib.rs:10:5:\nassertion `left == right` failed\n"
               "failures:\n    tests::adds\n    tests::other\n    tests::quiet_only\n")
        items = tests_stage.parse_cargo(out, "core", SRC)
        self.assertEqual([(f["file"], f["line"]) for f in items], [("core/src/lib.rs", 10), ("core", None), ("core", None)])

    def test_npm_runners(self):
        out = (" FAIL  src/sum.test.ts > sum > adds\n   × adds 3ms\n"   # vitest
               " FAIL src/a.spec.js\n  ✕ handles empty (2 ms)\n"      # jest
               "not ok 1 - parses dates\n")                             # node:test
        items = tests_stage.parse_npm(out, "web", SRC)
        names = {f["message"] for f in items}
        self.assertTrue({"Test fails: sum > adds", "Test fails: handles empty (2 ms)", "Test fails: parses dates"} <= names
                        or {"Test fails: sum > adds", "Test fails: parses dates"} <= names, names)

    def test_tsc(self):
        out = "src/app.ts(12,7): error TS2322: Type 'string' is not assignable to type 'number'.\nnoise\n"
        f = types_stage.parse_tsc(out, "frontend", SRC)[0]
        self.assertEqual((f["file"], f["line"], f["rule"]), ("frontend/src/app.ts", 12, "TS2322"))

    def test_ruff(self):
        out = json.dumps([{"code": "F821", "message": "Undefined name `x`", "filename": "/P/a.py", "location": {"row": 3}},
                          {"code": "B007", "message": "Loop variable unused", "filename": "/P/b.py", "location": {"row": 1}},
                          {"code": "F401", "message": "unused import", "filename": "/P/c.py", "location": {"row": 1}}])
        sev = {f["rule"]: f["severity"] for f in types_stage.parse_ruff(out, SRC)}
        self.assertEqual(sev, {"F821": "high", "B007": "medium", "F401": "low"})

    def test_clippy(self):
        msg = {"reason": "compiler-message", "message": {"level": "error", "message": "equal expressions", "code": {"code": "clippy::eq_op"},
               "spans": [{"is_primary": True, "file_name": "src/main.rs", "line_start": 4}]}}
        f = types_stage.parse_clippy(json.dumps(msg) + "\n{}\n", "core", SRC)[0]
        self.assertEqual((f["file"], f["line"], f["severity"], f["rule"]), ("core/src/main.rs", 4, "high", "clippy::eq_op"))


CRATE = {"Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
         "src/lib.rs": "pub fn add(a: i32, b: i32) -> i32 { a - b }\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn adds() { assert_eq!(super::add(2, 2), 4); }\n}\n",
         "src/main.rs": "fn main() {\n    let x = 3;\n    if x == x { println!(\"same\"); }\n}\n"}


class RustTests(unittest.TestCase):
    @needs("cargo")
    @slow
    def test_cargo_test_and_clippy(self):
        p = TempProject(CRATE, git=True)
        try:
            res = engine.Scan(p.root, stages=["tests", "types"]).run()
            items = engine.Scan(p.root, stages=["lint"]).db.findings()
            tests = [f for f in items if f["stage"] == "tests"]
            self.assertEqual([(f["file"], f["line"]) for f in tests], [("src/lib.rs", 6)])
            self.assertIn("adds", tests[0]["message"])
            clippy = [f for f in items if f["stage"] == "types"]
            self.assertTrue(any(f["rule"] == "clippy::eq_op" and f["severity"] == "high" for f in clippy), clippy)
        finally:
            p.cleanup()


class UpgradeTests(unittest.TestCase):
    def finding(self, file, eco, pkg, version, fixed):
        return findings.make("deps", "osv-scanner", "vulnerable-dependency", "high", file, None, "m",
                             package=pkg, version=version, ecosystem=eco, fixed=fixed)

    def test_pip_pin_upgrade_with_family_warning_and_undo(self):
        from bugscan import claude
        p = TempProject({"backend/requirements.txt": "torch==2.5.1  # ml\ntorchaudio==2.5.1\nrequests==2.32.3\n"}, git=True)
        try:
            plan = upgrade.plan(self.finding("backend/requirements.txt", "PyPI", "torch", "2.5.1", "2.13.0"), p.root)
            self.assertIn("torchaudio", plan["describe"])
            r = upgrade.apply(plan, p.root)
            self.assertEqual(p.read("backend/requirements.txt"), "torch==2.13.0  # ml\ntorchaudio==2.5.1\nrequests==2.32.3\n")
            self.assertIn("+torch==2.13.0", r["diff"])
            claude.revert(p.root, r["snapshot"], r["tracked"], r["new_files"])
            self.assertIn("torch==2.5.1", p.read("backend/requirements.txt"))
            # transitive (not pinned in the file) needs Claude
            self.assertIsNone(upgrade.plan(self.finding("backend/requirements.txt", "PyPI", "certifi", "2026.7.22", "2026.10.19"), p.root))
        finally:
            p.cleanup()

    @needs("npm")
    def test_npm_plans(self):
        p = TempProject({"web/package.json": json.dumps({"dependencies": {"lodash": "4.17.15"}, "devDependencies": {"vite": "5.4.0"}}),
                         "web/package-lock.json": "{}"})
        try:
            direct = upgrade.plan(self.finding("web/package-lock.json", "npm", "lodash", "4.17.15", "4.17.21"), p.root)
            self.assertEqual(direct["cmd"][-1], "lodash@^4.17.21")
            dev = upgrade.plan(self.finding("web/package-lock.json", "npm", "vite", "5.4.0", "6.4.4"), p.root)
            self.assertIn("--save-dev", dev["cmd"])
            trans = upgrade.plan(self.finding("web/package-lock.json", "npm", "esbuild", "0.21.5", "0.25.0"), p.root)
            self.assertEqual(trans["cmd"][-2:], ["update", "esbuild"])
        finally:
            p.cleanup()

    @needs("npm")
    @needs_network
    def test_npm_upgrade_end_to_end(self):
        p = TempProject({"package.json": json.dumps({"name": "d", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}})})
        try:
            import subprocess
            subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=p.root, capture_output=True)
            p.git("init", "-q")
            p.commit()
            r = upgrade.apply(upgrade.plan(self.finding("package-lock.json", "npm", "lodash", "4.17.15", "4.17.21"), p.root), p.root)
            self.assertNotIn("error", r)
            self.assertNotEqual(upgrade.lock_version(os.path.join(p.root, "package-lock.json"), "lodash"), "4.17.15")
        finally:
            p.cleanup()


class TriageTests(unittest.TestCase):
    def test_triage_stores_verdicts(self):
        from bugscan import claude
        p = TempProject({"a.py": "x = 1\n"}, git=True)
        try:
            db = findings.DB(p.root)
            r = db.begin_run("standard", ["sast"])
            db.ingest(r, "sast", [findings.make("sast", "semgrep", "sha1", "medium", "a.py", 1, "SHA1"),
                                  findings.make("sast", "semgrep", "sqli", "high", "a.py", 1, "SQL injection")], True)
            db.end_run(r)
            ids = {f["message"]: f["id"] for f in db.findings()}
            verdicts = json.dumps([{"id": ids["SHA1"], "verdict": "false-positive", "reason": "ids only"},
                                   {"id": ids["SQL injection"], "verdict": "real", "reason": "user input"},
                                   {"id": "nonsense", "verdict": "real"}])
            with FakeClaude(triage="Here you go:\n```json\n" + verdicts + "\n```") as fc:
                res = claude.triage(p.root, db)
                self.assertEqual(fc.calls()[0]["tools"], "Read,Grep,Glob")
            self.assertEqual(res["count"], 2)
            got = {f["message"]: (f["triage"], f["triage_reason"]) for f in db.findings()}
            self.assertEqual(got, {"SHA1": ("false-positive", "ids only"), "SQL injection": ("real", "user input")})
            with FakeClaude(triage="sorry, no idea"):
                self.assertIn("error", claude.triage(p.root, db))
            db.close()
        finally:
            p.cleanup()

    def test_old_databases_are_upgraded(self):
        p = TempProject()
        try:
            path = os.path.join(paths.workspace(p.root), "findings.db")
            con = sqlite3.connect(path)
            con.executescript("CREATE TABLE findings(fp TEXT PRIMARY KEY, stage TEXT, tool TEXT, rule TEXT, severity TEXT, file TEXT,"
                              " line INTEGER, message TEXT, snippet TEXT, extra TEXT, status TEXT, first_run INTEGER, last_run INTEGER,"
                              " fixed_run INTEGER, reopened_run INTEGER, explanation TEXT);")
            con.close()
            db = findings.DB(p.root)
            cols = {r["name"] for r in db.con.execute("PRAGMA table_info(findings)")}
            self.assertTrue({"triage", "triage_reason"} <= cols)
            db.close()
        finally:
            p.cleanup()
