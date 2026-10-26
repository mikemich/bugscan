"""Per-project settings in `.bugscan/config.toml` (all optional).

    [scan]
    level = "standard"            # default scan level: quick | standard | deep
    exclude = ["vendor", "docs"]  # folders to skip everywhere
    fail_on = "new"               # what fails `bugscan scan`: new | any | none
    min_severity = "medium"       # ignore anything below this when deciding failure
    fuzz_seconds = 60             # override the level's fuzzing time

    [[check]]                     # your own checks: any command, any language
    name = "unit-tests"
    run = "npm test"
    levels = ["standard", "deep"]
    requires = ["npm"]
    matchers = [{ regex = '^(?P<file>\\S+):(?P<line>\\d+): (?P<message>.*)$', severity = "medium" }]

    [[seed]]                      # real inputs downloaded by `bugscan sync` as extra fuzz seeds
    name = "example"
    url = "https://api.example.com/sample.json"

On Python < 3.11 (no tomllib) a built-in reader handles the subset above.
"""
import os
import re

from . import paths

LEVELS = ("quick", "standard", "deep")
SEVERITIES = ("critical", "high", "medium", "low", "info")
RESERVED = {"secrets", "sast", "lint", "deps", "fuzz", "memory"}


class ConfigError(Exception):
    pass


def path_for(target):
    return os.path.join(paths.project_dir(target), "config.toml")


def load(target):
    path = path_for(target)
    raw = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                raw = parse_toml(fh.read())
        except Exception as e:
            raise ConfigError(f"{path}: {e}")
    return validate(raw, path)


def validate(raw, where="config"):
    scan = dict(raw.get("scan") or {})
    cfg = {
        "scan": {
            "level": scan.get("level", "standard"),
            "exclude": [str(x).strip("/") for x in scan.get("exclude", [])],
            "fail_on": scan.get("fail_on", "new"),
            "min_severity": scan.get("min_severity", "medium"),
            "fuzz_seconds": scan.get("fuzz_seconds"),
        },
        "checks": [],
        "seeds": [],
    }
    s = cfg["scan"]
    if s["level"] not in LEVELS:
        raise ConfigError(f"{where}: scan.level must be one of {', '.join(LEVELS)}")
    if s["fail_on"] not in ("new", "any", "none"):
        raise ConfigError(f"{where}: scan.fail_on must be new, any or none")
    if s["min_severity"] not in SEVERITIES:
        raise ConfigError(f"{where}: scan.min_severity must be one of {', '.join(SEVERITIES)}")
    if s["fuzz_seconds"] is not None and not isinstance(s["fuzz_seconds"], int):
        raise ConfigError(f"{where}: scan.fuzz_seconds must be a whole number")
    names = set()
    for i, c in enumerate(raw.get("check") or []):
        name = c.get("name")
        if not name or not re.match(r"^[a-z0-9][a-z0-9-]*$", str(name)):
            raise ConfigError(f"{where}: check #{i + 1} needs a name made of lowercase letters, digits and dashes")
        if name in RESERVED:
            raise ConfigError(f"{where}: check name {name!r} is taken by a built-in check; pick another")
        if name in names:
            raise ConfigError(f"{where}: two checks are named {name!r}")
        names.add(name)
        if not c.get("run"):
            raise ConfigError(f"{where}: check {name!r} needs a `run` command")
        levels = c.get("levels", ["standard", "deep"])
        if any(l not in LEVELS for l in levels):
            raise ConfigError(f"{where}: check {name!r} has an unknown level in `levels`")
        sev = c.get("severity", "high")
        if sev not in SEVERITIES:
            raise ConfigError(f"{where}: check {name!r} has an unknown severity {sev!r}")
        matchers = []
        for m in c.get("matchers", []):
            try:
                rx = re.compile(m["regex"], re.M)
            except (KeyError, re.error) as e:
                raise ConfigError(f"{where}: check {name!r} has a bad matcher: {e}")
            if "message" not in rx.groupindex:
                raise ConfigError(f"{where}: check {name!r}: each matcher regex needs a (?P<message>…) group")
            matchers.append({"regex": rx, "severity": m.get("severity", sev), "rule": m.get("rule", name)})
        cfg["checks"].append({
            "name": name, "title": c.get("title") or name.replace("-", " ").capitalize(),
            "description": c.get("description", c["run"]), "run": c["run"], "levels": list(levels),
            "requires": list(c.get("requires", [])), "timeout": c.get("timeout"), "severity": sev,
            "matchers": matchers, "sarif": c.get("sarif", True),
        })
    for i, sd in enumerate(raw.get("seed") or []):
        if not sd.get("url") or not sd.get("name") or not re.match(r"^[\w.-]+$", str(sd["name"])):
            raise ConfigError(f"{where}: seed #{i + 1} needs a `name` (letters, digits, - _ .) and a `url`")
        cfg["seeds"].append({"name": sd["name"], "url": sd["url"]})
    return cfg


# ── TOML ────────────────────────────────────────────────────────────────────────────────────────────

def parse_toml(text):
    try:
        import tomllib
    except ImportError:  # Python < 3.11
        return MiniToml(text).parse()
    return tomllib.loads(text)


class MiniToml:
    """Reads the TOML subset bugscan configs use: tables, arrays of tables, strings, numbers,
    booleans, arrays (multi-line ok) and inline tables."""

    def __init__(self, text):
        self.s, self.i = text, 0

    def error(self, msg):
        line = self.s.count("\n", 0, self.i) + 1
        raise ValueError(f"line {line}: {msg}")

    def ws(self, newlines=False):
        while self.i < len(self.s):
            c = self.s[self.i]
            if c in " \t\r" or (newlines and c == "\n"):
                self.i += 1
            elif c == "#":
                while self.i < len(self.s) and self.s[self.i] != "\n":
                    self.i += 1
            else:
                break

    def parse(self):
        root, cur = {}, None
        cur = root
        while True:
            self.ws(newlines=True)
            if self.i >= len(self.s):
                return root
            if self.s.startswith("[[", self.i):
                end = self.s.index("]]", self.i)
                keys = [k.strip() for k in self.s[self.i + 2:end].split(".")]
                self.i = end + 2
                parent = self._table(root, keys[:-1])
                arr = parent.setdefault(keys[-1], [])
                if not isinstance(arr, list):
                    self.error(f"{keys[-1]} is not an array of tables")
                cur = {}
                arr.append(cur)
            elif self.s[self.i] == "[":
                end = self.s.index("]", self.i)
                keys = [k.strip() for k in self.s[self.i + 1:end].split(".")]
                self.i = end + 1
                cur = self._table(root, keys)
            else:
                key = self.key()
                self.ws()
                if self.s[self.i:self.i + 1] != "=":
                    self.error("expected =")
                self.i += 1
                self.ws()
                cur[key] = self.value()
            self.ws()
            if self.i < len(self.s) and self.s[self.i] != "\n":
                self.error("expected end of line")

    def _table(self, root, keys):
        t = root
        for k in keys:
            t = t.setdefault(k, {})
            if isinstance(t, list):
                t = t[-1]
        return t

    def key(self):
        if self.s[self.i] in "\"'":
            return self.string()
        m = re.compile(r"[A-Za-z0-9_-]+").match(self.s, self.i)
        if not m:
            self.error("expected a key")
        self.i = m.end()
        return m.group()

    def string(self):
        q = self.s[self.i]
        if self.s.startswith(q * 3, self.i):
            end = self.s.index(q * 3, self.i + 3)
            body = self.s[self.i + 3:end].lstrip("\n")
            self.i = end + 3
            return body if q == "'" else self._unescape(body)
        end = self.i + 1
        while True:
            if end >= len(self.s) or self.s[end] == "\n":
                self.error("unterminated string")
            if q == '"' and self.s[end] == "\\":
                end += 2
                continue
            if self.s[end] == q:
                break
            end += 1
        body = self.s[self.i + 1:end]
        self.i = end + 1
        return body if q == "'" else self._unescape(body)

    @staticmethod
    def _unescape(s):
        out, k = [], 0
        while k < len(s):
            c = s[k]
            if c == "\\" and k + 1 < len(s):
                n = s[k + 1]
                if n == "u":
                    out.append(chr(int(s[k + 2:k + 6], 16)))
                    k += 6
                    continue
                out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(n, n))
                k += 2
            else:
                out.append(c)
                k += 1
        return "".join(out)

    def value(self):
        c = self.s[self.i:self.i + 1]
        if c in ("\"", "'"):
            return self.string()
        if c == "[":
            self.i += 1
            arr = []
            while True:
                self.ws(newlines=True)
                if self.s[self.i] == "]":
                    self.i += 1
                    return arr
                arr.append(self.value())
                self.ws(newlines=True)
                if self.s[self.i] == ",":
                    self.i += 1
        if c == "{":
            self.i += 1
            t = {}
            while True:
                self.ws()
                if self.s[self.i] == "}":
                    self.i += 1
                    return t
                k = self.key()
                self.ws()
                self.i += 1  # =
                self.ws()
                t[k] = self.value()
                self.ws()
                if self.s[self.i] == ",":
                    self.i += 1
        m = re.compile(r"true|false|[+-]?\d[\d_]*(\.\d+)?([eE][+-]?\d+)?").match(self.s, self.i)
        if not m:
            self.error("unsupported value")
        self.i = m.end()
        v = m.group().replace("_", "")
        return v == "true" if v in ("true", "false") else float(v) if any(ch in v for ch in ".eE") else int(v)
