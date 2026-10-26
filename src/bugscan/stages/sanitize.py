"""Memory and concurrency bugs in Swift packages and Go modules:
Swift: strict-concurrency build, then the tests under ThreadSanitizer and AddressSanitizer.
Go: go vet, then the tests under the race detector."""
import os
import re
import shutil
import time

from .. import detect, findings
from .base import Result, Stage, skip

SANITIZER_TIMEOUT = int(os.environ.get("BUGSCAN_SANITIZER_TIMEOUT", "600"))
CONCURRENCY = re.compile(r"concurren|Sendable|data race|actor|isolat|sending", re.I)


class Sanitize(Stage):
    key, title, description = "memory", "Memory & races", "sanitizers, race detector, strict concurrency"

    def applies(self, info, config):
        return (True, "") if info["swiftpm"] or info["go"] else (False, "needs a Swift package or Go module")

    def run(self, ctx):
        items, ran, notes = [], False, []
        for flag, tool, fn in (("swiftpm", "swift", swift), ("go", "go", go)):
            if ctx.info[flag]:
                if shutil.which(tool):
                    items += fn(ctx)
                    ran = True
                else:
                    notes.append(f"{tool} is not installed")
            if ctx.should_stop():
                break
        if not ran:
            return skip("; ".join(notes))
        uniq = {f["fp"]: f for f in items}
        return Result("ok", list(uniq.values()))


# ── Swift ──────────────────────────────────────────────────────────────────────────────────────────

def _swift_index(target):
    idx = {}
    for rel in detect.walk(target):
        if rel.endswith(".swift"):
            idx.setdefault(os.path.basename(rel), []).append(rel)
    return {k: sorted(v, key=lambda r: (not r.startswith("Sources/"), r)) for k, v in idx.items()}


def swift(ctx):
    items = []
    ctx.log("── strict concurrency build")
    rc, out = ctx.run(["swift", "build", "-Xswiftc", "-strict-concurrency=complete"])
    items += swift_diagnostics(out, ctx.src)
    if rc != 0:
        return items  # build errors are reported; tests can't run
    if not os.path.isdir(os.path.join(ctx.target, "Tests")):
        ctx.log("no Tests folder: skipping sanitizer test runs")
        return items
    index = _swift_index(ctx.target)
    for san in ("thread", "address"):
        if ctx.should_stop():
            break
        ctx.log(f"── swift test --sanitize={san}")
        t0 = time.monotonic()
        _, out = ctx.run(["swift", "test", f"--sanitize={san}"], timeout=SANITIZER_TIMEOUT)
        if time.monotonic() - t0 >= SANITIZER_TIMEOUT - 1:
            ctx.log(f"   stopped after {SANITIZER_TIMEOUT // 60} min (sanitizers can hang in some Linux/Docker setups)")
        items += sanitizer_reports(out, ctx.src, index) + xctest_failures(out, ctx.src)
    return items


def swift_diagnostics(text, src):
    out, seen = [], set()
    for m in re.finditer(r"^(/\S+\.swift):(\d+):\d+: (warning|error): (.*?)(?: \[#\w+\])?$", text, re.M):
        path, line, kind, msg = m.groups()
        file = src.rel(path)
        if os.path.isabs(file) or "/.build/" in path or (file, line, msg) in seen:
            continue
        seen.add((file, line, msg))
        if kind == "error":
            out.append(findings.make("memory", "swiftc", "build-error", "high", file, line, msg, src.line(file, int(line))))
        elif CONCURRENCY.search(msg):
            out.append(findings.make("memory", "swiftc", "swift-concurrency", "medium", file, line, msg, src.line(file, int(line))))
    return out


SAN_BLOCK = re.compile(r"(?=(?:WARNING|ERROR): (?:Thread|Address|UndefinedBehavior)Sanitizer:)")
FRAME = re.compile(r"#\d+ (?:0x[0-9a-f]+ in )?(.+?) (\S+?\.swift):(\d+)")


def sanitizer_reports(text, src, index):
    out = []
    for block in SAN_BLOCK.split(text)[1:]:
        m = re.match(r"(?:WARNING|ERROR): (\w+)Sanitizer: ([^(\n]+)", block)
        if not m:
            continue
        san, kind = m.group(1), re.sub(r" on (address|unknown address) .*", "", m.group(2)).strip()
        frame = next((f for f in FRAME.finditer(block.split("\n\n")[0]) if "<compiler-generated>" not in f.group(2)), None)
        file = line = func = None
        if frame:
            func, base, line = frame.group(1), os.path.basename(frame.group(2)), int(frame.group(3))
            file = src.rel(frame.group(2)) if os.path.isabs(frame.group(2)) else (index.get(base) or [base])[0]
        label = {"Thread": "ThreadSanitizer", "Address": "AddressSanitizer", "UndefinedBehavior": "UBSan"}[san]
        msg = f"{label}: {kind}" + (f" in {func}" if func else "")
        out.append(findings.make("memory", label, re.sub(r"\W+", "-", kind.lower()).strip("-"), "high", file, line, msg,
                                 src.line(file, line), key=f"{kind}|{file}|{func}"))
    return out


def xctest_failures(text, src):
    out = []
    # macOS: "-[Module.Class testName] : msg"   Linux: "Class.testName : msg"
    for m in re.finditer(r"^(/\S+\.swift):(\d+): error: (?:-\[\S+ (\w+)\]|[\w.]*?\.?(\w+)) : (.*)$", text, re.M):
        file, line = src.rel(m.group(1)), int(m.group(2))
        name = m.group(3) or m.group(4)
        out.append(findings.make("memory", "xctest", "test-failure", "medium", file, line,
                                 f"Test {name} fails: {m.group(5)}", src.line(file, line), key=f"{name}|{m.group(5)}"))
    for m in re.finditer(r"✘ Test (\S+) recorded an issue at (\S+?):(\d+):\d+: (.*)$", text, re.M):
        out.append(findings.make("memory", "swift-testing", "test-failure", "medium", m.group(2), int(m.group(3)),
                                 f"Test {m.group(1)} fails: {m.group(4)}", key=f"{m.group(1)}|{m.group(4)}"))
    return out


# ── Go ─────────────────────────────────────────────────────────────────────────────────────────────

def go(ctx):
    items = []
    ctx.log("── go vet ./...")
    _, out = ctx.run(["go", "vet", "./..."])
    for m in re.finditer(r"^(?:vet: )?(\S+?\.go):(\d+):(?:\d+:)? (.*)$", out, re.M):
        file, line = ctx.src.rel(m.group(1)), int(m.group(2))
        items.append(findings.make("memory", "go vet", "go-vet", "medium", file, line, m.group(3), ctx.src.line(file, line)))
    ctx.log("── go test -race ./...")
    _, out = ctx.run(["go", "test", "-race", "-vet=off", "-count=1", "./..."])
    items += go_races(out, ctx.src) + go_failures(out, ctx.src)
    if "[build failed]" in out:
        for m in re.finditer(r"^(\S+?\.go):(\d+):\d+: (.*)$", out, re.M):
            file = ctx.src.rel(m.group(1))
            items.append(findings.make("memory", "go", "build-error", "high", file, int(m.group(2)), m.group(3)))
    return items


def go_races(text, src):
    out = []
    for block in text.split("WARNING: DATA RACE")[1:]:
        block = block.split("==================")[0]
        lines = block.strip().splitlines()
        access = lines[0].split(" at ")[0] if lines else "Access"
        func = file = line = None
        for i, l in enumerate(lines):
            m = re.match(r"^\s+(/\S+\.go):(\d+) \+0x", l)
            if m and not os.path.isabs(src.rel(m.group(1))):
                file, line, func = src.rel(m.group(1)), int(m.group(2)), lines[i - 1].strip()
                break
        prev = next((l.split(" at ")[0] for l in lines if l.startswith("Previous")), "")
        msg = f"Data race: {access.lower()} in {func or 'unknown code'}" + (f" conflicts with a {prev.lower()}" if prev else "")
        out.append(findings.make("memory", "go race detector", "data-race", "high", file, line, msg,
                                 src.line(file, line), key=f"{file}|{func}"))
    return out


def go_failures(text, src):
    out = []
    current = None
    for l in text.splitlines():
        m = re.match(r"^--- FAIL: (\S+)", l)
        if m:
            current = m.group(1)
            continue
        m = re.match(r"^\s+(\S+_test\.go):(\d+): (.*)$", l)
        if m and current:
            file, line = src.rel(m.group(1)), int(m.group(2))
            out.append(findings.make("memory", "go test", "test-failure", "medium", file, line,
                                     f"Test {current} fails: {m.group(3)}", src.line(file, line), key=f"{current}|{file}:{line}"))
    return out
