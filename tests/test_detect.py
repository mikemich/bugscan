import unittest

from tests.helpers import TempProject
from bugscan import detect


class DetectTests(unittest.TestCase):
    def setUp(self):
        self.p = TempProject({
            "src/app.ts": "", "src/util.ts": "", "web/index.html": "", "tool.py": "", "run.sh": "",
            "package-lock.json": "{}", "requirements-dev.txt": "", "go.mod": "module x",
            "node_modules/dep/index.js": "", "vendor/lib.py": "", ".build/x.swift": "",
            ".github/workflows/ci.yml": "", "Dockerfile": "",
        })

    def tearDown(self):
        self.p.cleanup()

    def test_languages_lockfiles_and_flags(self):
        info = detect.detect(self.p.root)
        self.assertEqual(info["languages"][0], "TypeScript")
        self.assertIn("Python", info["languages"])
        self.assertNotIn("JavaScript", info["languages"])  # node_modules is skipped
        self.assertNotIn("Swift", info["languages"])       # .build is skipped
        self.assertEqual(sorted(info["lockfiles"]), ["go.mod", "package-lock.json", "requirements-dev.txt"])
        self.assertTrue(info["go"] and info["workflows"] and info["docker"] and info["html"])
        self.assertFalse(info["git"] or info["swiftpm"] or info["harness"])
        self.assertEqual(info["packs"], ["p/typescript", "p/python", "p/secrets", "p/github-actions", "p/dockerfile", "p/xss"])

    def test_exclude_and_skipped(self):
        files = list(detect.walk(self.p.root, exclude=["src"]))
        self.assertNotIn("src/app.ts", files)
        self.assertTrue(detect.skipped("node_modules/a/b.js"))
        self.assertTrue(detect.skipped("src/x.js", exclude=["src"]))
        self.assertFalse(detect.skipped("src/x.js"))

    def test_harness_and_describe(self):
        self.p.write({".bugscan/fuzz/harness.py": "SEEDS=[1]\nTARGETS={}"})
        info = detect.detect(self.p.root)
        self.assertTrue(info["harness"].endswith("harness.py"))
        self.assertIn("fuzz harness", detect.describe(info))

    def test_empty_folder(self):
        e = TempProject()
        info = detect.detect(e.root)
        self.assertEqual(info["packs"], ["p/default", "p/secrets"])
        self.assertEqual(detect.describe(info), "no source files found")
        e.cleanup()
