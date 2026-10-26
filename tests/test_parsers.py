import json
import os
import re
import unittest

from tests.helpers import FIXTURES, TempProject
from bugscan import findings, paths
from bugscan.stages import deps, sanitize, sast, secrets

OUT = os.path.join(FIXTURES, "outputs")
SRC = findings.Source("/PROJECT")


def fx(name):
    return os.path.join(OUT, name)


def read(name):
    with open(fx(name)) as fh:
        return fh.read()


class ToolParserTests(unittest.TestCase):
    def test_semgrep_rule_ids_from_cached_packs_are_clean(self):
        cfg = "/Users/me/.cache/bugscan/rules/p_python.yml"
        self.assertEqual(sast.clean_rule_id("Users.me..cache.bugscan.rules.python.lang.x", [cfg]), "python.lang.x")
        self.assertEqual(sast.clean_rule_id("python.lang.x", [cfg]), "python.lang.x")

    def test_semgrep(self):
        items = sast.parse(fx("semgrep.json"), SRC, {"bugscan.js-innerhtml-template"})
        self.assertEqual([i["severity"] for i in items], ["medium", "high", "low"])
        self.assertEqual(items[0]["rule"], "bugscan.js-innerhtml-template")  # path prefix stripped
        self.assertEqual(items[0]["file"], "web/app.js")
        self.assertEqual(items[1]["extra"]["url"], "https://owasp.org/x")

    def test_gitleaks_skips_dependency_and_excluded_folders(self):
        items = secrets.parse(fx("gitleaks.json"), SRC, exclude=["vendor"])
        self.assertEqual(len(items), 1)
        f = items[0]
        self.assertEqual((f["file"], f["line"], f["severity"]), ("config.py", 2, "critical"))
        self.assertIn("Found in commit 01234567", f["message"])

    def with_kev(self, ids, fn):
        kev = paths.cache("kev.json")
        backup = open(kev).read() if os.path.exists(kev) else None
        with open(kev, "w") as fh:
            json.dump({"vulnerabilities": [{"cveID": i} for i in ids]}, fh)
        try:
            return fn()
        finally:
            if backup is None:
                os.remove(kev)
            else:
                with open(kev, "w") as fh:
                    fh.write(backup)

    def test_osv_one_finding_per_package(self):
        items = self.with_kev([], lambda: deps.parse(fx("osv.json"), SRC))
        self.assertEqual(len(items), 1)
        f = items[0]
        self.assertEqual((f["severity"], f["file"], f["extra"]["fixed"]), ("high", "package-lock.json", "4.17.21"))
        self.assertIn("2 known vulnerabilities (1 high, 1 medium). Upgrade to 4.17.21 to fix them.", f["message"])
        advisories = {a["id"]: a for a in f["extra"]["advisories"]}
        self.assertEqual(advisories["CVE-2020-8203"]["fixed"], "4.17.19")  # nearest fix above 4.17.15, not 3.0.1
        self.assertIn("Prototype pollution in zipObjectDeep", advisories["CVE-2020-8203"]["summary"])  # details when no summary

    def test_osv_without_groups(self):
        with open(fx("osv.json")) as fh:
            doc = json.load(fh)
        for r in doc["results"]:
            for pk in r["packages"]:
                pk.pop("groups")
        p = TempProject({"osv.json": json.dumps(doc)})
        try:
            f = self.with_kev([], lambda: deps.parse(os.path.join(p.root, "osv.json"), SRC))[0]
            self.assertEqual((len(f["extra"]["advisories"]), f["extra"]["fixed"]), (2, "4.17.21"))
        finally:
            p.cleanup()

    def test_osv_kev_makes_it_critical(self):
        f = self.with_kev(["CVE-2020-8203"], lambda: deps.parse(fx("osv.json"), SRC))[0]
        self.assertEqual(f["severity"], "critical")
        self.assertIn("Actively exploited", f["message"])

    def test_dev_only_packages_rank_lower(self):
        p = TempProject({"package-lock.json": json.dumps({"packages": {"": {}, "node_modules/lodash": {"version": "4.17.15", "dev": True}}})})
        try:
            with open(fx("osv.json")) as fh:
                doc = json.load(fh)
            doc["results"][0]["source"]["path"] = os.path.join(p.root, "package-lock.json")
            p.write({"osv.json": json.dumps(doc)})
            f = self.with_kev([], lambda: deps.parse(os.path.join(p.root, "osv.json"), findings.Source(p.root)))[0]
            self.assertEqual((f["severity"], f["extra"]["dev"]), ("medium", True))
            self.assertIn("Dev dependency", f["message"])
            # …but never when actively exploited
            f = self.with_kev(["CVE-2021-23337"], lambda: deps.parse(os.path.join(p.root, "osv.json"), findings.Source(p.root)))[0]
            self.assertEqual(f["severity"], "critical")
        finally:
            p.cleanup()

    def test_exclude_flag_matches_installed_osv_scanner(self):
        import subprocess
        from unittest import mock
        deps.exclude_flag.cache_clear()
        old = subprocess.CompletedProcess([], 0, "   --experimental-exclude string   exclude paths", "")
        with mock.patch.object(deps.subprocess, "run", return_value=old):
            self.assertEqual(deps.exclude_flag(), "--experimental-exclude")   # osv-scanner 2.5
        deps.exclude_flag.cache_clear()
        new = subprocess.CompletedProcess([], 0, "   --x-exclude string   exclude paths", "")
        with mock.patch.object(deps.subprocess, "run", return_value=new):
            self.assertEqual(deps.exclude_flag(), "--x-exclude")               # 2.6+
        deps.exclude_flag.cache_clear()

    def test_version_ordering(self):
        self.assertLess(deps._ver("1.11.28"), deps._ver("2.2.10"))
        self.assertLess(deps._ver("4.17.9"), deps._ver("4.17.15"))


class GenericParserTests(unittest.TestCase):
    def test_sarif(self):
        items = findings.from_sarif(fx("sample.sarif"), "eslint", SRC, "medium")
        self.assertEqual([(i["file"], i["line"], i["severity"]) for i in items],
                         [("src/a.js", 7, "medium"), ("src/b.js", 2, "critical"), (None, None, "low")])
        self.assertEqual(items[0]["extra"]["url"], "https://eslint.org/no-unused-vars")

    def test_matchers_dedupe_and_numbers(self):
        m = [{"regex": re.compile(r"^(?P<file>\S+):(?P<line>\d+): (?P<message>.*)$", re.M), "severity": "low", "rule": "t"}]
        text = "a.py:3: took 12ms\na.py:3: took 15ms\nb.py:1: other\nnoise\n"
        items = findings.from_matchers(text, m, "chk", "chk", SRC)
        self.assertEqual([(i["file"], i["line"]) for i in items], [("a.py", 3), ("b.py", 1)])


class SanitizerParserTests(unittest.TestCase):
    def test_go_race_and_failures(self):
        text = read("go-race.txt")
        src = findings.Source("/PROJECT/go-race")
        races = sanitize.go_races(text, src)
        self.assertGreaterEqual(len(races), 1)
        self.assertEqual({(r["file"], r["line"]) for r in races}, {("counter.go", 10)})
        self.assertIn("(*Counter).Inc()", races[0]["message"])
        self.assertEqual(len({r["fp"] for r in races}), 1)  # repeated reports of one race = one finding
        fails = sanitize.go_failures(text, src)
        self.assertEqual({f["file"] for f in fails}, {"counter_test.go"})

    def test_swift_build_diagnostics(self):
        items = sanitize.swift_diagnostics(read("swift-build.txt"), findings.Source("/PROJECT/swift-race"))
        rules = {i["rule"] for i in items}
        self.assertEqual(rules, {"swift-concurrency"})
        self.assertTrue(any("sharedTotal" in i["message"] for i in items))
        self.assertTrue(all("[#" not in i["message"] for i in items))

    def test_swift_tsan_and_xctest(self):
        text = read("swift-tsan.txt")
        index = {"Counter.swift": ["Sources/Counter/Counter.swift"], "CounterTests.swift": ["Tests/CounterTests/CounterTests.swift"]}
        races = sanitize.sanitizer_reports(text, findings.Source("/PROJECT/swift-race"), index)
        self.assertTrue(races)
        self.assertTrue(all(r["file"] == "Sources/Counter/Counter.swift" for r in races))
        self.assertTrue(any("increment" in r["message"] for r in races))
        fails = sanitize.xctest_failures(read("swift-tsan.txt") + "\n/PROJECT/Tests/T.swift:9: error: -[Mod.T testX] : XCTAssertTrue failed\n"
                                         "/PROJECT/Tests/L.swift:4: error: CounterTests.testLinux : XCTAssertEqual failed\n", SRC)
        got = {(f["file"], f["line"]): f["message"] for f in fails}
        self.assertIn("testX", got[("Tests/T.swift", 9)])          # macOS format
        self.assertIn("testLinux", got[("Tests/L.swift", 4)])      # Linux format


if __name__ == "__main__":
    unittest.main()
