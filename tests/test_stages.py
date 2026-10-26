import json
import os
import threading
import time
import unittest

from tests.helpers import TempProject, needs
from bugscan import config, detect, engine, paths
from bugscan.stages.base import Ctx
from bugscan.stages.custom import Custom
from bugscan.stages.fuzz import Fuzz
from bugscan.stages.lint import Lint


def ctx_for(p, changed=None, fuzz=3, cfg=None, profile="standard"):
    cfg = cfg or config.load(p.root)
    lines = []
    c = Ctx(p.root, detect.detect(p.root, cfg["scan"]["exclude"]), cfg, paths.workspace(p.root), profile, fuzz,
            changed=changed, log=lines.append)
    c.lines = lines
    return c


class LintTests(unittest.TestCase):
    def setUp(self):
        self.p = TempProject({
            "ok.js": "export const a = 1;\n", "bad.js": "function f( {\n", "bad.py": "def f(:\n  pass\n",
            "bad.json": '{"a": 1,}', "tsconfig.json": "{ // comments allowed\n}", "empty.json": "",
            "bad.sh": "if then fi\n", "node_modules/x/bad.js": "(((", "ok.py": "x = 1\n",
        })

    def tearDown(self):
        self.p.cleanup()

    @needs("node")
    def test_full_lint(self):
        res = Lint().run(ctx_for(self.p))
        got = {(f["file"], f["tool"]) for f in res.items}
        self.assertEqual(got, {("bad.js", "js"), ("bad.py", "python"), ("bad.json", "json"), ("bad.sh", "shell")})
        self.assertTrue(res.complete)
        line = {f["file"]: f["line"] for f in res.items}
        self.assertEqual((line["bad.py"], line["bad.json"]), (1, 1))

    def test_quick_lint_only_changed_files(self):
        res = Lint().run(ctx_for(self.p, changed=["bad.py", "node_modules/x/bad.js", "gone.py"]))
        self.assertEqual([f["file"] for f in res.items], ["bad.py"])
        self.assertFalse(res.complete)


def custom(**kw):
    check = {"name": "chk", "run": "true", "levels": ["standard"]}
    check.update(kw)
    return config.validate({"check": [check]})["checks"][0]


class CustomCheckTests(unittest.TestCase):
    def setUp(self):
        self.p = TempProject({"src/a.js": "line1\nline2\n"})

    def tearDown(self):
        self.p.cleanup()

    def run_check(self, **kw):
        return Custom(custom(**kw)).run(ctx_for(self.p))

    def test_passing_command_is_clean(self):
        res = self.run_check(run="echo all good")
        self.assertEqual((res.status, res.items), ("ok", []))

    def test_failing_command_without_matchers(self):
        res = self.run_check(run="echo something broke; exit 3", severity="medium")
        self.assertEqual(len(res.items), 1)
        f = res.items[0]
        self.assertEqual((f["rule"], f["severity"]), ("check-failed", "medium"))
        self.assertIn("exit 3", f["message"])
        self.assertIn("something broke", f["message"])

    def test_matchers(self):
        res = self.run_check(run="echo 'src/a.js:2: warning: careful'; echo 'src/a.js:1: error: broken'; exit 1",
                             matchers=[{"regex": r"^(?P<file>\S+):(?P<line>\d+): (?P<severity>error|warning): (?P<message>.*)$", "severity": "low"}])
        got = sorted((f["line"], f["severity"], f["snippet"]) for f in res.items)
        self.assertEqual(got, [(1, "low", "line1"), (2, "low", "line2")])  # error/warning aren't bugscan severities

    def test_sarif_and_environment(self):
        script = ("import json,os;"
                  "assert os.environ['BUGSCAN_LEVEL']=='standard' and os.environ['BUGSCAN_TARGET'];"
                  "json.dump({'runs':[{'tool':{'driver':{'name':'t'}},'results':[{'ruleId':'r','level':'error','message':{'text':'m'},"
                  "'locations':[{'physicalLocation':{'artifactLocation':{'uri':'src/a.js'},'region':{'startLine':2}}}]}]}]},"
                  "open(os.environ['BUGSCAN_SARIF'],'w'))")
        res = self.run_check(run=f'python3 -c "{script}"')
        self.assertEqual([(f["file"], f["line"], f["severity"]) for f in res.items], [("src/a.js", 2, "high")])

    def test_exit_77_skips_with_reason(self):
        res = self.run_check(run="echo 'docker is not running'; exit 77")
        self.assertEqual((res.status, res.note), ("skip", "docker is not running"))

    def test_missing_tool_skips(self):
        self.assertEqual(self.run_check(requires=["definitely-not-a-tool"]).status, "skip")

    def test_timeout(self):
        t = time.time()
        res = self.run_check(run="sleep 30", timeout=1)
        self.assertLess(time.time() - t, 10)
        self.assertEqual(len(res.items), 1)


JS_HARNESS = """
import {initials} from '../../lib/names.mjs';
export const seeds = ['Ada Lovelace'];
export const targets = { initials: s => { if (typeof s === 'string' && s.trim()) initials(s); } };
export const prepareSeed = (v, name) => name.startsWith('skip') ? undefined : v;
"""
PY_HARNESS = """
from calc import average
SEEDS = [[1, 2, 3]]
TARGETS = {"average": lambda xs: average(xs) if isinstance(xs, list) and all(type(x) in (int, float) for x in xs) else None}
def expected(e):
    return isinstance(e, OverflowError)
"""


class FuzzStageTests(unittest.TestCase):
    def tearDown(self):
        self.p.cleanup()

    @needs("node")
    def test_js_harness_finds_crash_and_saves_regression(self):
        self.p = TempProject({"lib/names.mjs": "export const initials = n => n.trim().split(' ').map(p => p[0].toUpperCase()).join('');\n",
                              ".bugscan/fuzz/harness.mjs": JS_HARNESS,
                              ".bugscan/fuzz/seeds/real.txt": "Grace  Hopper", ".bugscan/fuzz/seeds/skip-me.txt": "x"})
        res = Fuzz().run(ctx_for(self.p, fuzz=2))
        self.assertEqual(res.status, "ok")
        self.assertEqual([(f["file"], f["line"]) for f in res.items], [("lib/names.mjs", 1)])
        regs = os.listdir(os.path.join(self.p.root, ".bugscan/fuzz/regressions"))
        self.assertTrue(regs)
        c = ctx_for(self.p, fuzz=1)
        Fuzz().run(c)
        self.assertTrue(any("seeds" in l for l in c.lines))
        # accepting the crash removes the finding
        sig = res.items[0]["extra"]["signature"]
        self.p.write({".bugscan/fuzz/known-crashes.txt": sig + "\n"})
        self.assertEqual(Fuzz().run(ctx_for(self.p, fuzz=1)).items, [])
        # fixing the bug: the saved input replays clean
        self.p.write({".bugscan/fuzz/known-crashes.txt": "", "lib/names.mjs": "export const initials = n => n.trim().split(/\\s+/).map(p => p[0].toUpperCase()).join('');\n"})
        self.assertEqual(Fuzz().run(ctx_for(self.p, fuzz=1)).items, [])

    @needs("python3")
    def test_python_harness_with_expected_errors(self):
        self.p = TempProject({"calc.py": "def average(xs):\n    return sum(xs) / len(xs)\n", ".bugscan/fuzz/harness.py": PY_HARNESS})
        res = Fuzz().run(ctx_for(self.p, fuzz=2))
        self.assertEqual([(f["file"], f["line"]) for f in res.items], [("calc.py", 2)])
        self.assertIn("ZeroDivisionError", res.items[0]["message"])

    @needs("node")
    def test_broken_harness_is_an_error(self):
        self.p = TempProject({".bugscan/fuzz/harness.mjs": "export const seeds = [];\n"})
        self.assertEqual(Fuzz().run(ctx_for(self.p)).status, "error")


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.p = TempProject({"a.py": "x = 1\n", ".bugscan/config.toml":
                              '[[check]]\nname = "flaky"\nrun = "test -f broken && exit 1 || exit 0"\nlevels = ["quick", "standard"]\n'},
                             git=True)

    def tearDown(self):
        self.p.cleanup()

    def scan(self, **kw):
        res = engine.Scan(self.p.root, stages=["lint", "flaky"], **kw).run()
        for k, st in res["stages"].items():
            self.assertNotEqual(st["status"], "error", f"{k}: {st.get('note')}")
        return res

    def test_lifecycle_through_engine(self):
        self.assertEqual(self.scan()["stages"]["lint"]["status"], "clean")
        self.p.write({"a.py": "def (:\n", "broken": ""})
        res = self.scan()
        self.assertEqual((res["stages"]["lint"]["status"], res["stages"]["flaky"]["status"]), ("new", "new"))
        self.assertLess(res["score"], 100)
        self.p.write({"a.py": "x = 2\n"})
        os.remove(os.path.join(self.p.root, "broken"))
        res = self.scan()
        self.assertEqual((res["stages"]["lint"]["fixed"], res["stages"]["flaky"]["fixed"]), (1, 1))
        self.assertEqual(res["score"], 100)

    def test_quick_level_uses_changed_files(self):
        self.p.write({"b.py": "def (:\n"})
        self.p.commit()
        res = engine.Scan(self.p.root, profile="quick", stages=["lint"]).run()
        self.assertEqual(res["stages"]["lint"]["found"], 0)  # committed already: not a change
        self.p.write({"c.py": "def (:\n"})
        res = engine.Scan(self.p.root, profile="quick", stages=["lint"]).run()
        self.assertEqual(res["stages"]["lint"]["found"], 1)

    def test_unknown_check(self):
        with self.assertRaisesRegex(ValueError, "unknown check"):
            engine.Scan(self.p.root, stages=["nope"])

    def test_default_stages_follow_levels_and_availability(self):
        proj = engine.Project(self.p.root)
        self.assertEqual(proj.default_stages("quick"), ["secrets", "sast", "lint", "flaky"])
        self.assertNotIn("deps", proj.default_stages("standard"))  # no lockfiles
        self.assertEqual(proj.availability("fuzz"), (False, "no fuzz harness yet · press g"))

    def test_cancel(self):
        self.p.write({".bugscan/config.toml": '[[check]]\nname = "slow"\nrun = "sleep 60"\n'})
        s = engine.Scan(self.p.root, stages=["slow", "lint"])
        out = {}
        t = threading.Thread(target=lambda: out.update(s.run()))
        t.start()
        time.sleep(1.5)
        s.cancel()
        t.join(15)
        self.assertFalse(t.is_alive())
        self.assertEqual({k: v["status"] for k, v in out["stages"].items()}, {"slow": "cancelled", "lint": "cancelled"})

    def test_broken_check_does_not_kill_scan(self):
        proj = engine.Project(self.p.root)
        proj.stage("lint").run = lambda ctx: 1 / 0
        res = engine.Scan(proj, stages=["lint", "flaky"]).run()
        self.assertEqual(res["stages"]["lint"]["status"], "error")
        self.assertEqual(res["stages"]["flaky"]["status"], "clean")
