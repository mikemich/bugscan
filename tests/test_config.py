import unittest

from tests.helpers import TempProject
from bugscan import config
from bugscan.config import ConfigError, MiniToml

FULL = '''
# comment
[scan]
level = "deep"            # trailing comment
exclude = ["vendor", "docs/"]
fail_on = "any"
min_severity = "high"
fuzz_seconds = 30

[[check]]
name = "unit-tests"
title = "Unit tests"
run = "npm test -- --reporter=dot"
levels = [
  "standard",
  "deep",
]
requires = ["npm"]
timeout = 600
severity = "medium"
matchers = [
  { regex = '^(?P<file>\\S+):(?P<line>\\d+): (?P<message>.*)$', severity = "low", rule = "test" },
]

[[check]]
name = "swift6"
run = 'xcodebuild -scheme "My App" build'
sarif = false

[[seed]]
name = "sample"
url = "https://example.com/a.json"
'''


class TomlTests(unittest.TestCase):
    def test_mini_parser_matches_tomllib(self):
        mini = MiniToml(FULL).parse()
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        self.assertEqual(mini, tomllib.loads(FULL))

    def test_mini_parser_values(self):
        d = MiniToml('a = "x\\ty\\u00e9"\nb = 1_000\nc = 1.5\nd = true\ne = []\nf = """\nmulti\nline"""\n').parse()
        self.assertEqual(d, {"a": "x\tyé", "b": 1000, "c": 1.5, "d": True, "e": [], "f": "multi\nline"})

    def test_mini_parser_errors_have_line_numbers(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            MiniToml('a = 1\nb = "unterminated\n').parse()


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.p = TempProject()

    def tearDown(self):
        self.p.cleanup()

    def test_defaults_without_file(self):
        c = config.load(self.p.root)
        self.assertEqual(c["scan"], {"level": "standard", "exclude": [], "fail_on": "new", "min_severity": "medium", "fuzz_seconds": None})
        self.assertEqual(c["checks"], [])

    def test_full_config(self):
        self.p.write({".bugscan/config.toml": FULL})
        c = config.load(self.p.root)
        self.assertEqual(c["scan"]["exclude"], ["vendor", "docs"])
        self.assertEqual([k["name"] for k in c["checks"]], ["unit-tests", "swift6"])
        ut = c["checks"][0]
        self.assertEqual((ut["timeout"], ut["severity"], ut["requires"]), (600, "medium", ["npm"]))
        m = ut["matchers"][0]
        self.assertEqual(m["severity"], "low")
        self.assertTrue(m["regex"].search("src/a.js:3: boom"))
        self.assertEqual(c["checks"][1]["levels"], ["standard", "deep"])
        self.assertFalse(c["checks"][1]["sarif"])
        self.assertEqual(c["seeds"], [{"name": "sample", "url": "https://example.com/a.json"}])

    def test_template_is_valid(self):
        from bugscan import paths
        with open(paths.data("config.toml")) as fh:
            self.assertEqual(config.validate(config.parse_toml(fh.read()))["checks"], [])

    def bad(self, text, msg):
        self.p.write({".bugscan/config.toml": text})
        with self.assertRaisesRegex(ConfigError, msg):
            config.load(self.p.root)

    def test_errors(self):
        self.bad('[scan]\nlevel = "turbo"', "scan.level")
        self.bad('[scan]\nfail_on = "maybe"', "fail_on")
        self.bad('[[check]]\nname = "Bad Name"\nrun = "x"', "lowercase")
        self.bad('[[check]]\nname = "a"', "needs a `run`")
        self.bad('[[check]]\nname = "a"\nrun = "x"\n[[check]]\nname = "a"\nrun = "y"', "two checks")
        self.bad('[[check]]\nname = "lint"\nrun = "x"', "built-in")
        self.bad('[[check]]\nname = "a"\nrun = "x"\nlevels = ["fast"]', "unknown level")
        self.bad("[[check]]\nname = \"a\"\nrun = \"x\"\nmatchers = [{ regex = '(' }]", "bad matcher")
        self.bad("[[check]]\nname = \"a\"\nrun = \"x\"\nmatchers = [{ regex = 'x' }]", "message")
        self.bad('[[seed]]\nname = "a b"\nurl = "u"', "seed")
        self.bad('not toml at all [', "config.toml")
