"""Run the project's own test suites (npm test, pytest, cargo test); each failing test is a finding."""
import os
import re

from .. import findings
from .base import Result, Stage, skip
from .suites import suites


class Tests(Stage):
    key, title, description = "tests", "Your tests", "npm test / pytest / cargo test"

    def applies(self, info, config):
        return (True, "") if suites(info["target"], config["scan"]["exclude"]) else (False, "no test suite found")

    def run(self, ctx):
        items, ran, notes = [], 0, []
        for kind, d, cmd, why in suites(ctx.target, ctx.exclude):
            where = d or "."
            if why:
                notes.append(f"{kind} in {where}: {why}")
                ctx.log(f"── {kind} in {where}: skipped, {why}")
                continue
            if ctx.should_stop():
                break
            ctx.log(f"── {kind} in {where}")
            rc, out = ctx.run(cmd, cwd=os.path.join(ctx.target, d), env={"CI": "1", "FORCE_COLOR": "0"}, timeout=1200)
            if kind == "unittest" and re.search(r"^Ran 0 tests|NO TESTS RAN", out, re.M):
                ctx.log("   no unittest-style tests found (install pytest to run plain test functions)")
                continue
            ran += 1
            found = PARSERS[kind](out, d, ctx.src)
            if rc != 0 and not found:
                tail = "\n".join(out.strip().splitlines()[-10:])
                found = [findings.make("tests", kind, "tests-fail", "medium", os.path.join(d, "package.json") if kind == "npm" else d or None,
                                       None, f"`{' '.join(cmd)}` in {where} failed (exit {rc}).\n{tail}", key=f"{kind}|{d}|exit")]
            items += found
            ctx.log(f"   {len(found)} failing" if found else "   all passing")
        if not ran:
            return skip("; ".join(notes) or "no test suite could run")
        return Result("ok", items)


def _j(d, f):
    return os.path.normpath(os.path.join(d, f)) if f else None


def parse_pytest(out, d, src):
    items = []
    for m in re.finditer(r"^(?:FAILED|ERROR) (?P<file>[^:\s]+)::(?P<name>\S+)(?: - (?P<msg>.*))?$", out, re.M):
        file = _j(d, m.group("file"))
        line = None
        lm = re.search(re.escape(m.group("file")) + r":(\d+): ", out)
        if lm:
            line = int(lm.group(1))
        items.append(findings.make("tests", "pytest", "test-failure", "medium", file, line,
                                   f"Test {m.group('name')} fails: {m.group('msg') or 'see the log'}", src.line(file, line),
                                   key=f"pytest|{file}|{m.group('name')}"))
    return items


def parse_cargo(out, d, src):
    items, seen = [], set()
    for m in re.finditer(r"thread '(?P<name>[^']+)'(?: \(\d+\))? panicked at (?P<file>[^:\s]+):(?P<line>\d+):\d+:\n(?P<msg>.*)", out):
        if m.group("name") in seen:
            continue
        seen.add(m.group("name"))
        file, line = _j(d, m.group("file")), int(m.group("line"))
        items.append(findings.make("tests", "cargo test", "test-failure", "medium", file, line,
                                   f"Test {m.group('name')} fails: {m.group('msg').strip()}", src.line(file, line),
                                   key=f"cargo|{d}|{m.group('name')}"))
    names = re.findall(r"^test (\S+) \.\.\. FAILED$", out, re.M)
    for block in re.findall(r"^failures:\n((?:    \S+\n)+)", out, re.M):  # --quiet only lists the names
        names += block.split()
    for name in names:  # failures without a panic location (e.g. a test returning Err)
        if name not in seen:
            seen.add(name)
            items.append(findings.make("tests", "cargo test", "test-failure", "medium", d or None, None,
                                       f"Test {name} fails", key=f"cargo|{d}|{name}"))
    return items


def parse_npm(out, d, src):
    """vitest / jest / node:test summaries."""
    items, seen = [], set()
    pats = [r"^\s*FAIL\s+(?P<file>\S+\.(?:test|spec)\.[cm]?[jt]sx?)\s*>?\s*(?P<name>.*)$",   # vitest/jest file lines
            r"^\s*(?:×|✕|✖)\s+(?P<name>.+?)(?:\s+\d+ms)?$",                                   # failed test names
            r"^not ok \d+ - (?P<name>.+)$"]                                                      # node:test / TAP
    for p in pats:
        for m in re.finditer(p, out, re.M):
            g = m.groupdict()
            file = _j(d, g.get("file"))
            name = (g.get("name") or "").strip() or os.path.basename(file or "")
            k = (file, name)
            if k in seen or not name:
                continue
            seen.add(k)
            items.append(findings.make("tests", "npm test", "test-failure", "medium", file, None, f"Test fails: {name}",
                                       key=f"npm|{d}|{file}|{name}"))
    return items


def parse_unittest(out, d, src):
    items = []
    for m in re.finditer(r"^(?:FAIL|ERROR): (?P<name>\S+) \((?P<where>[^)]+)\)\n-+\n(?P<body>.*?)(?=\n={10,}|\n-{10,}\nRan )", out, re.M | re.S):
        frames = re.findall(r'File "([^"]+)", line (\d+)', m.group("body"))
        frames = [(src.rel(f), int(n)) for f, n in frames if not os.path.isabs(src.rel(f))]
        file, line = frames[-1] if frames else (None, None)
        last = [l for l in m.group("body").strip().splitlines() if l.strip()][-1:] or [""]
        items.append(findings.make("tests", "unittest", "test-failure", "medium", file, line,
                                   f"Test {m.group('name')} ({m.group('where')}) fails: {last[0].strip()}",
                                   src.line(file, line), key=f"unittest|{d}|{m.group('where')}|{m.group('name')}"))
    return items


PARSERS = {"pytest": parse_pytest, "cargo": parse_cargo, "npm": parse_npm, "unittest": parse_unittest}
