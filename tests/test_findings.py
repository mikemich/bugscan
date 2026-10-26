import json
import unittest

from tests.helpers import TempProject
from bugscan import findings


def f(msg, line=1, sev="high", stage="lint", snippet=None):
    return findings.make(stage, "tool", "rule", sev, "a.py", line, msg, snippet if snippet is not None else msg)


class FingerprintTests(unittest.TestCase):
    def test_survives_line_shifts_and_whitespace(self):
        self.assertEqual(f("x  =  1", line=3)["fp"], f("x = 1", line=40)["fp"])
        self.assertNotEqual(f("x = 1")["fp"], f("x = 2")["fp"])

    def test_bad_severity_becomes_medium(self):
        self.assertEqual(findings.make("s", "t", "r", "spicy", None, None, "m")["severity"], "medium")


class DBTests(unittest.TestCase):
    def setUp(self):
        self.p = TempProject()
        self.db = findings.DB(self.p.root)

    def tearDown(self):
        self.db.close()
        self.p.cleanup()

    def scan(self, items, complete=True, stage="lint"):
        run = self.db.begin_run("standard", [stage])
        st = self.db.ingest(run, stage, items, complete)
        self.db.end_run(run)
        return st

    def states(self, **kw):
        return {x["message"]: x["state"] for x in self.db.findings(**kw)}

    def test_lifecycle_new_open_fixed_came_back(self):
        self.assertEqual(self.scan([f("A"), f("B")])["new"], 2)
        self.assertEqual(self.states(), {"A": "new", "B": "new"})
        st = self.scan([f("A"), f("B")])
        self.assertEqual((st["new"], st["fixed"]), (0, 0))
        self.assertEqual(self.states(), {"A": "open", "B": "open"})
        self.assertEqual(self.scan([f("A")])["fixed"], 1)
        self.assertEqual(self.states(include_closed=True), {"A": "open", "B": "fixed"})
        st = self.scan([f("A"), f("B")])
        self.assertEqual(st["came_back"], 1)
        self.assertEqual(self.states(), {"A": "open", "B": "came back"})

    def test_partial_scan_does_not_mark_fixed(self):
        self.scan([f("A")])
        self.assertEqual(self.scan([], complete=False)["fixed"], 0)
        self.assertEqual(self.states(), {"A": "open"})

    def test_other_stages_untouched(self):
        self.scan([f("A")], stage="lint")
        self.scan([f("S", stage="sast")], stage="sast")
        self.assertEqual(set(self.states()), {"A", "S"})

    def test_ignored_stays_ignored_and_does_not_score(self):
        self.scan([f("A", sev="critical")])
        self.assertLess(self.db.score()[0], 100)
        fp = self.db.findings()[0]["fp"]
        self.db.set_status(fp, "ignored")
        self.scan([f("A", sev="critical")])
        self.assertEqual(self.states(include_closed=True), {"A": "ignored"})
        self.assertEqual(self.db.score(), (100, "A"))

    def test_get_by_short_id_and_ambiguity(self):
        self.scan([f("A"), f("B")])
        a = self.db.findings()[0]
        self.assertEqual(self.db.get(a["id"])["fp"], a["fp"])
        self.assertIsNone(self.db.get(""))  # matches both
        self.assertIsNone(self.db.get("zzzz"))

    def test_scores_and_grades(self):
        self.assertEqual(findings.score_of({}), 100)
        self.assertEqual(findings.grade(findings.score_of({"high": 1})), "B")
        self.assertEqual(findings.grade(findings.score_of({"critical": 4})), "F")
        self.assertGreater(findings.score_of({"low": 5}), findings.score_of({"high": 1}))

    def test_history_and_latest_stage_results(self):
        r1 = self.db.begin_run("quick", ["lint"])
        self.db.record_stage(r1, "lint", "clean", 1)
        self.db.end_run(r1)
        r2 = self.db.begin_run("quick", ["sast"])
        self.db.record_stage(r2, "sast", "issues", 2, 3, 0)
        self.db.end_run(r2)
        self.assertEqual(set(self.db.latest_stage_results()), {"lint", "sast"})
        self.assertEqual([r["id"] for r in self.db.runs()], [r1, r2])

    def test_exports(self):
        self.scan([f("A", sev="critical"), findings.make("deps", "osv", "CVE-1", "low", None, None, "pkg", url="https://x")], stage="lint")
        items = self.db.findings()
        sarif = findings.to_sarif(items)
        json.dumps(sarif)
        res = sarif["runs"][0]["results"]
        self.assertEqual({r["level"] for r in res}, {"error", "note"})
        located = [r for r in res if "locations" in r]
        self.assertEqual(located[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
        self.assertEqual(len(findings.to_json(items)), 2)
