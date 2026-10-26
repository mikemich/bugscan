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

    def test_osv_versions_kev_and_summaries(self):
        kev = paths.cache("kev.json")
        backup = open(kev).read() if os.path.exists(kev) else None
        with open(kev, "w") as fh:
            json.dump({"vulnerabilities": [{"cveID": "CVE-2020-8203"}]}, fh)
        try:
            items = {i["rule"]: i for i in deps.parse(fx("osv.json"), SRC)}
        finally:
            if backup is None:
                os.remove(kev)
            else:
                with open(kev, "w") as fh:
                    fh.write(backup)
        cmd = items["CVE-2021-23337"]
        self.assertEqual((cmd["severity"], cmd["extra"]["fixed"], cmd["file"]), ("high", "4.17.21", "package-lock.json"))
        proto = items["CVE-2020-8203"]
        self.assertEqual(proto["severity"], "critical")  # on the KEV list
        self.assertIn("actively exploited", proto["message"])
        self.assertIn("Prototype pollution in zipObjectDeep", proto["message"])  # details used when summary empty
        self.assertEqual(proto["extra"]["fixed"], "4.17.19")  # nearest fix above 4.17.15, not 3.0.1

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
        fails = sanitize.xctest_failures(read("swift-tsan.txt") + "\n/PROJECT/Tests/T.swift:9: error: -[Mod.T testX] : XCTAssertTrue failed\n", SRC)
        self.assertIn(("Tests/T.swift", 9), [(f["file"], f["line"]) for f in fails])


if __name__ == "__main__":
    unittest.main()
