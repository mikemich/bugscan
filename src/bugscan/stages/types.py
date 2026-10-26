"""Type checkers and linters that find real bugs: tsc for TypeScript, ruff for Python, clippy for Rust."""
import json
import os
import re
import shutil

from .. import findings
from .base import Result, Stage, skip
from .suites import _dirs_with, has_local_bin

RUFF_HIGH = {"F821", "F822", "F823", "F811", "F632", "E999", "B006", "B008"}  # undefined names, syntax, mutable defaults…


class Types(Stage):
    key, title, description = "types", "Types & linters", "tsc / ruff / cargo clippy"

    def applies(self, info, config):
        langs = set(info["languages"])
        return (True, "") if langs & {"TypeScript", "Python", "Rust"} else (False, "for TypeScript, Python or Rust")

    def run(self, ctx):
        items, ran, notes = [], 0, []
        langs = set(ctx.info["languages"])
        if "TypeScript" in langs:
            for d in _dirs_with(ctx.target, {"tsconfig.json"}, ctx.exclude):
                if not has_local_bin(ctx.target, d, "tsc"):
                    notes.append(f"tsc in {d or '.'}: dependencies aren't installed")
                    continue
                ctx.log(f"── tsc --noEmit in {d or '.'}")
                rc, out = ctx.run(["npx", "--no-install", "tsc", "--noEmit", "--pretty", "false", "-p", "."], cwd=os.path.join(ctx.target, d))
                items += parse_tsc(out, d, ctx.src)
                ran += 1
        if "Python" in langs:
            if shutil.which("ruff"):
                ctx.log("── ruff check")
                rc, out = ctx.run(["ruff", "check", "--output-format", "json", "--select", "F,E9,B", "--exit-zero",
                                   *[f"--extend-exclude={e}" for e in ctx.exclude], "."], quiet=True)
                items += parse_ruff(out, ctx.src)
                ran += 1
            else:
                notes.append("ruff isn't installed (brew install ruff)")
        if "Rust" in langs and shutil.which("cargo"):
            for d in _dirs_with(ctx.target, {"Cargo.toml"}, ctx.exclude):
                ctx.log(f"── cargo clippy in {d or '.'}")
                rc, out = ctx.run(["cargo", "clippy", "--quiet", "--message-format=json"], cwd=os.path.join(ctx.target, d), quiet=True)
                items += parse_clippy(out, d, ctx.src)
                ran += 1
        for n in notes:
            ctx.log(f"skipped: {n}")
        if not ran:
            return skip("; ".join(notes) or "nothing to check")
        ctx.log(f"{len(items)} problems")
        return Result("ok", items)


def parse_tsc(out, d, src):
    items = []
    for m in re.finditer(r"^(?P<file>[^(\s][^(]*)\((?P<line>\d+),\d+\): error (?P<code>TS\d+): (?P<msg>.*)$", out, re.M):
        file = os.path.normpath(os.path.join(d, m.group("file")))
        line = int(m.group("line"))
        items.append(findings.make("types", "tsc", m.group("code"), "medium", file, line, m.group("msg"), src.line(file, line)))
    return items


def parse_ruff(out, src):
    try:
        data = json.loads(out[out.index("["):]) if "[" in out else []
    except ValueError:
        return []
    items = []
    for r in data:
        code = r.get("code") or "ruff"
        file, line = src.rel(r.get("filename")), (r.get("location") or {}).get("row")
        sev = "high" if code in RUFF_HIGH else "medium" if code.startswith("B") else "low"
        items.append(findings.make("types", "ruff", code, sev, file, line, r.get("message", ""), src.line(file, line),
                                   url=r.get("url")))
    return items


def parse_clippy(out, d, src):
    items, seen = [], set()
    for raw in out.splitlines():
        try:
            m = json.loads(raw)
        except ValueError:
            continue
        msg = m.get("message") if m.get("reason") == "compiler-message" else None
        if not msg or msg.get("level") not in ("error", "warning"):
            continue
        span = next((s for s in msg.get("spans", []) if s.get("is_primary")), None)
        if not span:
            continue
        file, line = os.path.normpath(os.path.join(d, span["file_name"])), span["line_start"]
        code = (msg.get("code") or {}).get("code") or "rustc"
        k = (file, line, code)
        if k in seen:
            continue
        seen.add(k)
        sev = "high" if msg["level"] == "error" else "low"
        items.append(findings.make("types", "clippy", code, sev, file, line, msg["message"], src.line(file, line)))
    return items
