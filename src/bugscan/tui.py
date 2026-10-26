#!/usr/bin/env python3
"""bugscan interactive UI: pick a folder, press Enter, review findings, let Claude explain or fix them.

Usage: bugscan [folder]          (standard library only: curses)
"""
import collections
import curses
import locale
import os
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time

from . import claude, detect, engine, findings, hooks, paths, report, setup, sync
from .config import ConfigError

SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPARK = "▁▂▃▄▅▆▇█"
FUZZ_TIMES = [15, 30, 60, 120, 300, 600, 1800, 3600]
GREEN, RED, YELLOW, ACCENT, TITLE, MAGENTA = 1, 2, 3, 4, 5, 6
SEV_ATTR = {}
START = os.getcwd()
ERR_RE = re.compile(r"FAIL|CRASH|[Ee]rror|leaks found|REGRESSION|NEW  ")


def put(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w or x < 0:
        return
    try:
        win.addstr(y, x, text[: max(0, w - x - (1 if y == h - 1 else 0))], attr)
    except curses.error:
        pass


def short(path, width):
    path = path.replace(os.path.expanduser("~"), "~", 1)
    if len(path) <= width:
        return path
    keep = max(4, width - 1)
    return path[: keep // 3] + "…" + path[-(keep - keep // 3):]


def ago(ts):
    s = int(time.time() - ts)
    return "just now" if s < 60 else f"{s // 60} min ago" if s < 3600 else f"{s // 3600} h ago" if s < 86400 else f"{s // 86400} d ago"


def fmt_secs(s):
    return f"{s // 60} min" if s >= 60 and s % 60 == 0 else f"{s}s"


class Task:
    """A background job (scan, Claude request, sync) whose output lines stream into the UI."""

    def __init__(self, app, title, fn, on_done=None):
        self.app, self.title, self.fn, self.on_done = app, title, fn, on_done
        self.lines = collections.deque(maxlen=3000)
        self.result = self.error = None
        self.started = self.stage_started = time.time()
        self.cancelled = False
        self.procs = []  # subprocesses to kill on cancel
        self.cancel_hook = None
        self.fp = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        try:
            self.result = self.fn(self)
        except Exception as e:  # surface instead of dying silently
            self.error = f"{type(e).__name__}: {e}"
            self.lines.append(self.error)
        self.app.done.put(self)

    def log(self, line):
        for part in str(line).splitlines() or [""]:
            self.lines.append(part)

    def cancel(self):
        self.cancelled = True
        if self.cancel_hook:
            self.cancel_hook()
        for p in self.procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass

    @property
    def running(self):
        return self.thread.is_alive()


# ── views ────────────────────────────────────────────────────────────────────────────────────────────

class View:
    keys = ""

    def draw(self, app, scr): ...

    def key(self, app, ch): ...


class MainView(View):
    keys = "enter scan  tab level  space tick  f findings  t folder  u update  g fuzzer  s summary  o report  ? help  q quit"

    def __init__(self):
        self.cursor = self.top = 0

    def draw(self, app, scr):
        h, w = scr.getmaxyx()
        put(scr, 2, 2, "Folder  ", curses.A_DIM)
        pth = short(app.target, w - 32)
        put(scr, 2, 10, pth, curses.A_BOLD)
        put(scr, 2, w - 18, "[t] change", curses.color_pair(ACCENT))
        put(scr, 3, 2, "Found   ", curses.A_DIM)
        put(scr, 3, 10, detect.describe(app.info)[: w - 30])
        put(scr, 3, w - 18, "[u] update data", curses.color_pair(ACCENT))
        put(scr, 4, 2, "Level   ", curses.A_DIM)
        x = 10
        for p in engine.PROFILE_ORDER:
            label = f" {engine.PROFILES[p]['title']} "
            put(scr, 4, x, label, (curses.A_REVERSE | curses.A_BOLD) if p == app.profile else curses.A_DIM)
            x += len(label) + 1
        desc = engine.PROFILES[app.profile]["desc"]
        if app.profile != "quick":
            desc = re.sub(r"[\d.]+ (min|s) fuzzing", f"{fmt_secs(app.fuzz)} fuzzing", desc)
        if w > 80:
            put(scr, 4, x + 1, desc, curses.A_DIM)
        put(scr, 4, w - 18, "[tab] [+/-]", curses.color_pair(ACCENT))

        y0 = 6
        stages = app.project.stages
        rows_for_list = max(3, min(len(stages), h - y0 - 6))
        self.cursor = max(0, min(self.cursor, len(stages) - 1))
        self.top = min(max(self.top, self.cursor - rows_for_list + 1), self.cursor)
        for j, st in enumerate(stages[self.top: self.top + rows_for_list]):
            i = self.top + j
            key, title, desc = st.key, st.title, st.description
            y = y0 + j
            ok, why = app.project.availability(key)
            here = i == self.cursor
            box = "[x]" if key in app.selected and ok else "[ ]"
            attr = (curses.A_REVERSE | curses.A_BOLD) if here else 0
            put(scr, y, 1, f"{'›' if here else ' '} {box} {title:<19}", attr | (0 if ok else curses.A_DIM))
            if w > 74:
                put(scr, y, 27, (desc if ok else why)[: w - 47], curses.A_DIM)
            text, a = app.stage_text(key, ok)
            put(scr, y, w - 19, text, a)

        if len(stages) > rows_for_list:
            put(scr, y0 + rows_for_list - 1, w - 22, f"↓ {len(stages) - self.top - rows_for_list} more" if self.top + rows_for_list < len(stages) else "", curses.A_DIM)
        top = y0 + rows_for_list + 1
        t = app.task
        if t and t.running:
            label = f" {t.title} · {int(time.time() - t.started)}s  [c] cancel "
        elif t:
            label = f" {t.title} · {'error' if t.error else 'cancelled' if t.cancelled else 'done'} "
        else:
            label = " Output "
        put(scr, top, 0, "─" * w, curses.A_DIM)
        put(scr, top, 2, label, curses.A_BOLD)
        rows = h - top - 2
        lines = list(t.lines)[-rows:] if t else []
        if lines:
            for j, line in enumerate(lines):
                a = curses.A_BOLD if line.startswith("━━") else curses.color_pair(RED) if ERR_RE.search(line) else 0
                put(scr, top + 1 + j, 1, line.replace("\t", "  "), a)
        else:
            for j, line in enumerate(app.idle_hint()[:rows]):
                put(scr, top + 2 + j, 3, line, curses.A_DIM)

    def key(self, app, ch):
        stages = app.project.stages
        key = stages[self.cursor].key
        if ch in (curses.KEY_UP, ord("k")):
            self.cursor = (self.cursor - 1) % len(stages)
        elif ch in (curses.KEY_DOWN, ord("j")):
            self.cursor = (self.cursor + 1) % len(stages)
        elif ch == ord(" "):
            ok, why = app.project.availability(key)
            if not ok:
                app.say(f"Can't run {app.project.titles[key]} here: {why}.")
            elif not app.busy():
                app.selected ^= {key}
        elif ch == ord("a") and not app.busy():
            avail = {st.key for st in stages if app.project.availability(st.key)[0]}
            app.selected = set() if avail <= app.selected else avail
        elif ch in (9, curses.KEY_BTAB, ord("1"), ord("2"), ord("3")):
            if app.busy():
                app.say("Wait for the scan to finish before changing level.")
                return
            order = engine.PROFILE_ORDER
            i = order.index(app.profile)
            i = {9: (i + 1) % 3, curses.KEY_BTAB: (i - 1) % 3}.get(ch, ch - ord("1"))
            app.set_profile(order[i])
        elif ch in (ord("+"), ord("=")):
            app.fuzz = next((s for s in FUZZ_TIMES if s > app.fuzz), FUZZ_TIMES[-1])
        elif ch in (ord("-"), ord("_")):
            app.fuzz = next((s for s in reversed(FUZZ_TIMES) if s < app.fuzz), FUZZ_TIMES[0])
        elif ch in (10, 13, curses.KEY_ENTER, ord("r")):
            app.start_scan()
        elif ch in (ord("l"), curses.KEY_RIGHT):
            app.show_log(key)
        elif ch == ord("f"):
            app.push(FindingsView(app))
        elif ch == ord("t"):
            if app.busy():
                app.say("Wait for the current job to finish (or press c) before changing folder.")
            else:
                app.push(PickerView(app.target))
        else:
            app.global_key(ch)


def state_attr(state):
    return {"new": curses.color_pair(RED) | curses.A_BOLD, "came back": curses.color_pair(RED) | curses.A_BOLD,
            "open": curses.color_pair(YELLOW), "fixed": curses.color_pair(GREEN), "ignored": curses.A_DIM}.get(state, 0)


class FindingsView(View):
    keys = "↑↓ move  enter details  e explain  x fix  i ignore  o open file  tab filter  / search  v severity  q back"
    FILTERS = [("new", "New"), ("open", "Open"), ("all", "All")]

    def __init__(self, app):
        self.cursor = self.top = 0
        self.filter = "new" if any(f["state"] in ("new", "came back") for f in app.items()) else "open"
        self.search = ""
        self.min_sev = 4  # index into SEVERITIES: 4 = show everything

    def visible(self, app):
        items = app.items(all_=self.filter == "all")
        if self.filter == "new":
            items = [f for f in items if f["state"] in ("new", "came back")]
        elif self.filter == "open":
            items = [f for f in items if f["status"] == "open"]
        items = [f for f in items if findings.SEVERITIES.index(f["severity"]) <= self.min_sev]
        if self.search:
            s = self.search.lower()
            items = [f for f in items if s in (f["message"] + " " + (f["file"] or "") + " " + f["rule"]).lower()]
        return items

    def draw(self, app, scr):
        h, w = scr.getmaxyx()
        allf = app.items(all_=True)
        counts = {"new": sum(f["state"] in ("new", "came back") for f in allf), "open": sum(f["status"] == "open" for f in allf), "all": len(allf)}
        x = 2
        for key, label in self.FILTERS:
            t = f" {label} {counts[key]} "
            put(scr, 2, x, t, (curses.A_REVERSE | curses.A_BOLD) if key == self.filter else curses.A_DIM)
            x += len(t) + 1
        sev = "all severities" if self.min_sev == 4 else f"{findings.SEVERITIES[self.min_sev]} and worse"
        put(scr, 2, x + 2, f"[v] {sev}" + (f"   [/] “{self.search}”" if self.search else ""), curses.A_DIM)
        items = self.visible(app)
        self.cursor = max(0, min(self.cursor, len(items) - 1))
        rows = h - 6
        self.top = min(max(self.top, self.cursor - rows + 1), self.cursor)
        put(scr, 4, 1, f"  {'STATE':<10}{'SEVERITY':<10}{'CHECK':<16}{'WHERE':<30}ISSUE", curses.A_DIM)
        if not items:
            msg = {"new": "Nothing new since the last scan. Press tab to see all open findings.",
                   "open": "No open findings." if not self.search else "No matches.",
                   "all": "No findings yet. Run a scan from the main screen."}[self.filter]
            put(scr, 6, 4, msg, curses.A_DIM)
        for j, f in enumerate(items[self.top: self.top + rows]):
            i = self.top + j
            here = i == self.cursor
            base = curses.A_REVERSE if here else 0
            loc = f"{f['file']}:{f['line']}" if f["file"] and f["line"] else (f["file"] or "-")
            loc = loc if len(loc) <= 28 else "…" + loc[-27:]
            put(scr, 5 + j, 1, ("› " if here else "  ") + " " * (w - 3), base)
            put(scr, 5 + j, 3, f"{f['state']:<10}", base | state_attr(f["state"]))
            put(scr, 5 + j, 13, f"{f['severity']:<10}", base | SEV_ATTR.get(f["severity"], 0))
            put(scr, 5 + j, 23, f"{app.project.titles.get(f['stage'], f['stage'])[:15]:<16}{loc:<30}{f['message']}"[: w - 25], base)

    def key(self, app, ch):
        items = self.visible(app)
        f = items[self.cursor] if items else None
        if ch in (curses.KEY_UP, ord("k")):
            self.cursor -= 1
        elif ch in (curses.KEY_DOWN, ord("j")):
            self.cursor += 1
        elif ch == curses.KEY_PPAGE:
            self.cursor -= 10
        elif ch == curses.KEY_NPAGE:
            self.cursor += 10
        elif ch == 9:
            keys = [k for k, _ in self.FILTERS]
            self.filter = keys[(keys.index(self.filter) + 1) % len(keys)]
            self.cursor = 0
        elif ch == ord("v"):
            self.min_sev = self.min_sev - 1 if self.min_sev else 4
        elif ch == ord("/"):
            s = app.prompt("Search: ", self.search)
            if s is not None:
                self.search, self.cursor = s.strip(), 0
        elif ch in (ord("q"), 27, curses.KEY_LEFT):
            app.pop()
        elif f and ch in (10, 13, curses.KEY_ENTER, curses.KEY_RIGHT):
            app.push(DetailView(f["fp"]))
        elif f and ch == ord("e"):
            app.push(DetailView(f["fp"]))
            app.explain(f["fp"])
        elif f and ch == ord("x"):
            app.push(DetailView(f["fp"]))
            app.fix(f["fp"])
        elif f and ch == ord("i"):
            app.toggle_ignore(f["fp"])
        elif f and ch == ord("o"):
            app.open_editor(f)
        else:
            app.global_key(ch)


class DetailView(View):
    keys = "e explain  x fix  r make rule  i ignore  o open file  ↑↓ scroll  q back"

    def __init__(self, fp):
        self.fp, self.scroll = fp, 0

    def draw(self, app, scr):
        h, w = scr.getmaxyx()
        f = app.db.get(self.fp)
        if not f:
            put(scr, 2, 2, "This finding no longer exists.")
            return
        out = []  # (text, attr)
        loc = f"{f['file']}:{f['line']}" if f["file"] and f["line"] else (f["file"] or "-")
        out.append((f"{f['severity'].upper()} · {f['state']} · {app.project.titles.get(f['stage'], f['stage'])} · {f['rule']}",
                    SEV_ATTR.get(f["severity"], 0) | curses.A_BOLD))
        out.append((loc, curses.A_BOLD))
        out.append(("", 0))
        for para in f["message"].splitlines():
            out += [(l, 0) for l in textwrap.wrap(para, w - 6) or [""]]
        ex = f["extra"]
        facts = [f"package {ex['package']} {ex['version']}" if ex.get("package") else "", f"fixed in {ex['fixed']}" if ex.get("fixed") else "",
                 "ACTIVELY EXPLOITED (CISA KEV)" if ex.get("kev") else "", ex.get("url") or "", f"reproducer: {ex['repro']}" if ex.get("repro") else ""]
        for fact in filter(None, facts):
            out.append(("  " + fact, curses.A_DIM))
        code = claude.context(f, app.target, radius=6)
        if code:
            out += [("", 0), ("Code", curses.A_BOLD)]
            for l in code.splitlines():
                out.append((l[: w - 4], curses.color_pair(YELLOW) | curses.A_BOLD if l.startswith(">") else curses.A_DIM))
        out += [("", 0), ("Claude", curses.A_BOLD)]
        t = app.task
        mine = t is not None and t.fp == self.fp
        if mine and t.running:
            out.append((f"{SPIN[int(time.time() * 10) % 10]} {t.title}… {int(time.time() - t.started)}s   [c] cancel", curses.color_pair(YELLOW)))
        elif f.get("explanation"):
            if "false positive" in f["explanation"].split("\n")[0].lower() and f["status"] == "open":
                out.append(("Claude thinks this is a false positive: press i to ignore it.", curses.color_pair(ACCENT)))
            for para in f["explanation"].splitlines():
                head = re.match(r"^\**(Verdict|What's wrong|Why it matters|How to fix)", para)
                for k, l in enumerate(textwrap.wrap(para, w - 6) or [""]):
                    out.append((l, curses.A_BOLD if head and k == 0 else 0))
        elif f["status"] == "fixed":
            out.append(("Fixed ✓  The latest full run of this check no longer reports it.", curses.color_pair(GREEN)))
        elif not claude.available():
            out.append(("Claude Code isn't installed. Press d to see how to install it.", curses.A_DIM))
        else:
            out.append(("Press e to have Claude explain this, or x to have it fix it (you review the change first).", curses.A_DIM))
        if app.fixes.get(self.fp, {}).get("kept"):
            out += [("", 0), ("Fix applied. Press r to turn it into a Semgrep rule that catches this bug pattern everywhere.", curses.color_pair(GREEN))]
        rows = h - 4
        self.scroll = max(0, min(self.scroll, len(out) - rows))
        for j, (text, a) in enumerate(out[self.scroll: self.scroll + rows]):
            put(scr, 2 + j, 3, text, a)

    def key(self, app, ch):
        f = app.db.get(self.fp)
        if ch in (ord("q"), 27, curses.KEY_LEFT):
            app.pop()
        elif ch in (curses.KEY_DOWN, ord("j")):
            self.scroll += 1
        elif ch in (curses.KEY_UP, ord("k")):
            self.scroll -= 1
        elif ch == ord(" "):
            self.scroll += 10
        elif not f:
            return
        elif ch == ord("e"):
            app.explain(self.fp)
        elif ch == ord("x"):
            app.fix(self.fp)
        elif ch == ord("r"):
            app.make_rule(self.fp)
        elif ch == ord("i"):
            app.toggle_ignore(self.fp)
        elif ch == ord("o"):
            app.open_editor(f)
        else:
            app.global_key(ch)


class TextView(View):
    """Scrollable text: logs, summaries, help, diffs. `actions` maps keys to (label, callback)."""

    def __init__(self, title, text, actions=None, colorize=None):
        self.title, self.raw = title, text.splitlines()
        self.actions = actions or {}
        self.colorize = colorize
        self.top = 0
        self.keys = "  ".join(f"{k} {label}" for k, (label, _) in self.actions.items()) + ("  " if self.actions else "") + "↑↓ scroll  q back"

    def draw(self, app, scr):
        h, w = scr.getmaxyx()
        put(scr, 1, 2, self.title[: w - 18], curses.A_BOLD)
        lines = []
        for l in self.raw:
            a = self.colorize(l) if self.colorize else (curses.color_pair(RED) if ERR_RE.search(l) else 0)
            for seg in textwrap.wrap(l.replace("\t", "  "), w - 4, drop_whitespace=False, replace_whitespace=False) or [""]:
                lines.append((seg, a))
        rows = h - 5
        self.top = max(0, min(self.top, len(lines) - rows))
        for j, (l, a) in enumerate(lines[self.top: self.top + rows]):
            put(scr, 3 + j, 2, l, a)
        if len(lines) > rows:
            put(scr, 1, w - 14, f"{min(self.top + rows, len(lines))}/{len(lines)}", curses.A_DIM)

    def key(self, app, ch):
        h = app.scr.getmaxyx()[0]
        if ch in (ord("q"), 27, curses.KEY_LEFT):
            app.pop()
        elif 0 <= ch < 256 and chr(ch) in self.actions:
            self.actions[chr(ch)][1]()
        else:
            self.top += {curses.KEY_DOWN: 1, ord("j"): 1, curses.KEY_UP: -1, ord("k"): -1, ord(" "): h - 6,
                         curses.KEY_NPAGE: h - 6, ord("b"): -(h - 6), curses.KEY_PPAGE: -(h - 6)}.get(ch, 0)
            if ch in (ord("g"), curses.KEY_HOME):
                self.top = 0
            elif ch in (ord("G"), curses.KEY_END):
                self.top = 10 ** 9


def diff_color(line):
    if line.startswith("+") and not line.startswith("+++"):
        return curses.color_pair(GREEN)
    if line.startswith("-") and not line.startswith("---"):
        return curses.color_pair(RED)
    if line.startswith("@@"):
        return curses.color_pair(ACCENT)
    return curses.A_BOLD if line.startswith(("diff --git", "Claude:")) else 0


class PickerView(View):
    keys = "enter open  s scan this folder  / type path  r start folder  ~ home  . hidden  q cancel"

    def __init__(self, start):
        self.cwd = start if os.path.isdir(start) else os.path.expanduser("~")
        self.cursor = self.top = 0
        self.hidden = False

    def entries(self):
        try:
            names = sorted((n for n in os.listdir(self.cwd) if os.path.isdir(os.path.join(self.cwd, n)) and (self.hidden or not n.startswith("."))),
                           key=str.lower)
        except OSError:
            names = []
        return [("scan", "✓ Scan this folder")] + ([("up", "..")] if self.cwd != "/" else []) + [("dir", n) for n in names]

    def draw(self, app, scr):
        h, w = scr.getmaxyx()
        put(scr, 1, 2, "Choose a folder to scan", curses.A_BOLD)
        put(scr, 2, 2, short(self.cwd, w - 4), curses.color_pair(ACCENT))
        ents = self.entries()
        self.cursor = max(0, min(self.cursor, len(ents) - 1))
        rows = h - 6
        self.top = min(max(self.top, self.cursor - rows + 1), self.cursor)
        for j, (kind, name) in enumerate(ents[self.top: self.top + rows]):
            i = self.top + j
            label = name + ("/" if kind == "dir" else "")
            if kind == "dir":
                p = os.path.join(self.cwd, name)
                if os.path.isdir(os.path.join(p, ".git")):
                    label += "   git"
                if os.path.isdir(os.path.join(p, ".bugscan")):
                    label += "  has fuzzer/rules"
            a = curses.A_REVERSE if i == self.cursor else 0
            if kind == "scan":
                a |= curses.color_pair(GREEN) | curses.A_BOLD
            put(scr, 4 + j, 2, ("› " if i == self.cursor else "  ") + label, a)

    def go(self, path):
        self.cwd, self.cursor, self.top = path, 0, 0

    def key(self, app, ch):
        ents = self.entries()
        kind, name = ents[self.cursor] if ents else ("scan", "")
        if ch in (27, ord("q")):
            app.pop()
        elif ch in (curses.KEY_UP, ord("k")):
            self.cursor -= 1
        elif ch in (curses.KEY_DOWN, ord("j")):
            self.cursor += 1
        elif ch == curses.KEY_PPAGE:
            self.cursor -= 10
        elif ch == curses.KEY_NPAGE:
            self.cursor += 10
        elif ch == ord("s") or (kind == "scan" and ch in (10, 13, curses.KEY_ENTER)):
            app.pop()
            app.set_target(self.cwd)
        elif ch in (10, 13, curses.KEY_ENTER, curses.KEY_RIGHT, ord("l")):
            self.go(os.path.dirname(self.cwd) if kind == "up" else os.path.join(self.cwd, name))
        elif ch in (curses.KEY_LEFT, curses.KEY_BACKSPACE, 127, ord("h")):
            self.go(os.path.dirname(self.cwd))
        elif ch == ord("~"):
            self.go(os.path.expanduser("~"))
        elif ch == ord("r"):
            self.go(START)
        elif ch == ord("."):
            self.hidden = not self.hidden
        elif ch == ord("/"):
            typed = app.prompt("Path: ", self.cwd + "/")
            if typed:
                p = os.path.realpath(os.path.expanduser(typed.strip()))
                if os.path.isdir(p):
                    self.go(p)
                else:
                    app.say(f"Not a folder: {typed}")


class DoctorView(View):
    keys = "enter install / start the selected tool  r recheck  q back"

    def __init__(self):
        self.cursor = 0
        self.tools = setup.check()

    def draw(self, app, scr):
        h, w = scr.getmaxyx()
        put(scr, 1, 2, "Tools", curses.A_BOLD)
        put(scr, 1, 9, "what bugscan uses, and what's missing", curses.A_DIM)
        for i, t in enumerate(self.tools):
            y = 3 + i
            here = i == self.cursor
            put(scr, y, 2, ("› " if here else "  ") + ("✓" if t["ok"] else "✗"),
                (curses.color_pair(GREEN) if t["ok"] else curses.color_pair(RED)) | curses.A_BOLD)
            put(scr, y, 7, f"{t['name']:<12}", (curses.A_REVERSE if here else 0) | curses.A_BOLD)
            put(scr, y, 20, f"{t['purpose']:<40}"[: max(0, w - 52)], curses.A_DIM)
            put(scr, y, max(20, w - 31), (t["detail"] if t["ok"] else t["install"])[:30], 0 if t["ok"] else curses.color_pair(YELLOW))
        y = 4 + len(self.tools)
        sel = self.tools[self.cursor]
        if not sel["ok"]:
            how = f"Press enter to run: {sel['install']}" if sel["runnable"] else f"To install: {sel['install']}"
            put(scr, y, 4, how, curses.color_pair(ACCENT))
            if sel["stages"]:
                put(scr, y + 1, 4, "Needed for: " + ", ".join(app.project.titles.get(s, s) for s in sel["stages"]), curses.A_DIM)

    def key(self, app, ch):
        if ch in (27, ord("q")):
            app.pop()
        elif ch in (curses.KEY_UP, ord("k")):
            self.cursor = (self.cursor - 1) % len(self.tools)
        elif ch in (curses.KEY_DOWN, ord("j")):
            self.cursor = (self.cursor + 1) % len(self.tools)
        elif ch == ord("r"):
            self.tools = setup.check()
        elif ch in (10, 13, curses.KEY_ENTER):
            t = self.tools[self.cursor]
            if t["ok"]:
                app.say(f"{t['name']} is already installed.")
            elif not t["runnable"]:
                app.say(f"Install {t['name']} yourself: {t['install']}")
            else:
                app.run_in_terminal(t["install"], f"Installing {t['name']}")
                self.tools = setup.check()


HELP = """bugscan finds bugs automatically. Pick a folder, press Enter, then review what it found.

MAIN SCREEN
  enter        scan with the ticked checks (picked automatically for the folder)
  tab / 1 2 3  scan level: Quick (changed files, ~10 s) · Standard (everything, 1 min fuzzing) · Deep (30 min fuzzing)
  + / -        fuzzing time        space / a   tick one check / all      l   full log of a check
  f            findings            t           choose another folder     u   update rules & vulnerability data
  g            have Claude write a fuzzer for this project (JavaScript/TypeScript or Python)
  Custom checks from .bugscan/config.toml appear in the list too (bugscan init creates one).
  s            Claude summary of the whole scan        o   HTML report in your browser
  w            watch mode: quick rescan whenever you save a file
  h            install / remove a git pre-commit hook that runs a quick scan before every commit
  d            tools: what's installed, install what's missing
  c            cancel the running job                   q   quit

FINDINGS
  tab  New / Open / All     v  minimum severity     /  search
  enter details   e  Claude explains   x  Claude fixes (you see the diff: y keeps it, n undoes it)
  r  (after a fix) Claude writes a Semgrep rule so the same bug is caught everywhere
  i  ignore / un-ignore     o  open the file at that line ($VISUAL, $EDITOR, VS Code, Cursor, Zed, Xcode)

STATES
  new        first seen in the latest scan          came back   was fixed, then reappeared
  open       seen before, still there               fixed       gone in the latest full scan
  ignored    you marked it as not a problem

Only new and came-back issues fail a scan (and the git hook), so old issues never block you.
Every crash a fuzzer finds is saved and replayed on later scans, so fixed bugs stay fixed.
Claude actions run through your local Claude Code login and only send code when you press the key.
"""


# ── app ──────────────────────────────────────────────────────────────────────────────────────────────

class App:
    def __init__(self, scr, target):
        self.scr = scr
        self.done = queue.Queue()
        self.task = None
        self.views = []
        self.message = ""
        self.message_at = 0
        self.watch = False
        self.watch_sig = None
        self.watch_checked = 0
        self.fixes = {}  # fp -> fix result (snapshot, diff, kept)
        self._items = None
        self.set_target(target, initial=True)
        self.push(MainView())

    # state
    def set_target(self, target, initial=False):
        try:
            project = engine.Project(target)
        except ConfigError as e:
            if initial:
                raise
            self.say(f"Can't open that folder: {e}")
            return
        self.project = project
        self.target = project.target
        self.info = project.info
        self.db = findings.DB(self.target)
        self.stage_state = {}
        self.fixes = {}
        self._items = None
        self.watch_sig = None
        self.hook = hooks.installed(self.target)
        self.set_profile("standard")
        if self.db.latest_run():
            for k, st in self.db.latest_stage_results().items():
                self.stage_state[k] = {"status": st["status"], "secs": st["secs"], "found": st["found"], "new": st["new"], "old": True}
        if not initial:
            self.task = None
            self.say(f"Ready to scan {short(self.target, 60)} · press enter to start")

    def reload(self):
        """Re-read the folder (after Claude wrote a fuzzer or a rule); newly available checks get ticked."""
        before = set(self.project.default_stages(self.profile))
        self.project = engine.Project(self.target)
        self.info = self.project.info
        self.selected |= set(self.project.default_stages(self.profile)) - before

    def set_profile(self, p):
        self.profile = p
        cfg = self.project.config["scan"]["fuzz_seconds"]
        self.fuzz = cfg if cfg is not None else engine.PROFILES[p]["fuzz"] or 60
        self.selected = set(self.project.default_stages(p))

    def items(self, all_=False):
        if self._items is None:
            self._items = self.db.findings(include_closed=True)
        return self._items if all_ else [f for f in self._items if f["status"] != "fixed"]

    def refresh(self):
        self._items = None

    def busy(self):
        return bool(self.task and self.task.running)

    def say(self, msg):
        self.message, self.message_at = msg, time.time()

    def push(self, view):
        self.views.append(view)

    def pop(self):
        if len(self.views) > 1:
            self.views.pop()

    # display helpers
    def stage_text(self, key, ok):
        if not ok:
            return "", 0
        st = self.stage_state.get(key)
        if not st:
            return "", 0
        s = st["status"]
        if s == "running" and self.busy():
            return f"{SPIN[int(time.time() * 10) % 10]} running {int(time.time() - st.get('started', time.time()))}s", curses.color_pair(YELLOW) | curses.A_BOLD
        old = curses.A_DIM if st.get("old") else 0
        secs = f"{st.get('secs', 0)}s"
        return {
            "queued": ("· queued", curses.A_DIM),
            "clean": (f"✓ clean   {secs}", curses.color_pair(GREEN) | curses.A_BOLD | old),
            "issues": (f"● {st.get('found', 0)} open {secs}", curses.color_pair(YELLOW) | old),
            "new": (f"✗ {st.get('new', 0) + st.get('came_back', 0)} new  {secs}", curses.color_pair(RED) | curses.A_BOLD | old),
            "skipped": ("– skipped", curses.A_DIM),
            "error": (f"! error   {secs}", curses.color_pair(RED)),
            "cancelled": ("cancelled", curses.color_pair(YELLOW)),
        }.get(s, ("", 0))

    def idle_hint(self):
        last = self.db.latest_run()
        if not last:
            return ["Press Enter to scan. The checks above were picked for this folder automatically.",
                    "Tab switches between Quick, Standard and Deep. Press ? for everything else."]
        items = self.items()
        new = sum(f["state"] in ("new", "came back") for f in items)
        score, grade = self.db.score()
        lines = [f"Last scan {ago(last['finished'])}: health {score} ({grade}), {sum(f['status'] == 'open' for f in items)} open, {new} new.",
                 "Press f to review findings" + (" (start with the new ones)." if new else ".")]
        if not self.info["harness"] and set(self.info["languages"]) & {"JavaScript", "TypeScript", "Python"}:
            lines.append("Tip: press g and Claude writes a fuzzer for this project, so fuzzing works here too.")
        if not self.info["config"]:
            lines.append("Tip: your own checks (tests, linters…) can run here too: see bugscan init.")
        if self.info["git"] and not self.hook:
            lines.append("Tip: press h to scan automatically before every commit, or w to rescan on every save.")
        return lines

    def header(self):
        h, w = self.scr.getmaxyx()
        put(self.scr, 0, 0, " BUG SCANNER".ljust(w), curses.color_pair(TITLE) | curses.A_BOLD)
        tags = []
        if self.watch:
            tags.append("● watching")
        if self.hook:
            tags.append("hook on")
        runs = [r["score"] for r in self.db.runs(12) if r["score"] is not None]
        if runs:
            score, grade = self.db.score()
            spark = " " + "".join(SPARK[min(7, s * 8 // 101)] for s in runs) if len(runs) > 1 else ""
            tags.append(f"health {score} {grade}{spark}")
        right = "   ".join(tags) + " "
        put(self.scr, 0, max(14, w - len(right)), right, curses.color_pair(TITLE) | curses.A_BOLD)

    def footer(self):
        h, w = self.scr.getmaxyx()
        text = self.message if self.message and time.time() - self.message_at < 8 else self.views[-1].keys
        if self.busy() and not isinstance(self.views[-1], MainView):
            text = f"{SPIN[int(time.time() * 10) % 10]} {self.task.title}… {int(time.time() - self.task.started)}s (c cancels)   " + text
        put(self.scr, h - 1, 0, (" " + text).ljust(w), curses.color_pair(TITLE))

    # loop
    def loop(self):
        self.scr.timeout(100)
        while self.views:
            self.poll()
            self.scr.erase()
            h, w = self.scr.getmaxyx()
            if h < 18 or w < 64:
                put(self.scr, 0, 0, f"Make the terminal bigger ({w}x{h}); bugscan needs at least 64x18.")
            else:
                self.header()
                self.views[-1].draw(self, self.scr)
                self.footer()
            ch = self.scr.getch()
            if ch in (-1, curses.KEY_RESIZE):
                continue
            self.message = ""
            if ch == ord("q") and isinstance(self.views[-1], MainView):
                if self.busy():
                    self.task.cancel()
                    self.task.thread.join(3)
                return
            self.views[-1].key(self, ch)

    def global_key(self, ch):
        if ch == ord("c") and self.busy():
            self.task.cancel()
            self.say("Cancelling…")
        elif ch == ord("?"):
            self.push(TextView("Help", HELP))
        elif ch == ord("d"):
            self.push(DoctorView())
        elif ch == ord("u"):
            self.start("Updating rules and data", lambda t: sync.sync_all(self.project, force=True, log=t.log),
                       lambda t: self.say("Rules and vulnerability data are up to date."))
        elif ch == ord("g"):
            self.write_harness()
        elif ch == ord("s"):
            self.summary()
        elif ch == ord("o"):
            p = report.write(self.project)
            subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.say(f"Report opened in your browser ({short(p, 50)})")
        elif ch == ord("w"):
            self.watch = not self.watch
            self.watch_sig = None
            self.say("Watching: a quick scan runs whenever you save a file." if self.watch else "Watch mode off.")
        elif ch == ord("h"):
            msg = hooks.uninstall(self.target) if self.hook else hooks.install(self.target)
            self.hook = hooks.installed(self.target)
            self.say(msg)

    def poll(self):
        while not self.done.empty():
            t = self.done.get()
            if t.cancelled:
                self.say(f"{t.title}: cancelled")
            elif t.error:
                self.say(f"{t.title} failed: {t.error}")
            elif t.on_done:
                try:
                    t.on_done(t)
                except Exception as e:
                    self.say(f"Error: {type(e).__name__}: {e}")
        if self.watch and not self.busy() and time.time() - self.watch_checked > 2:
            self.watch_checked = time.time()
            sig = watch_signature(self.target, self.info)
            if self.watch_sig is not None and sig != self.watch_sig:
                self.say("Change detected: running a quick scan")
                self.start_scan(profile="quick")
            self.watch_sig = sig

    def start(self, title, fn, on_done=None, claude_task=False, fp=None):
        if self.busy():
            self.say(f"Busy with “{self.task.title}”. Press c to cancel it first.")
            return None
        if claude_task and not claude.available():
            self.say("Claude Code isn't installed. Press d to set it up.")
            return None
        t = Task(self, title, fn, on_done)
        t.fp = fp
        self.task = t
        return t

    # actions
    def start_scan(self, profile=None):
        mine = profile in (None, self.profile)
        profile = profile or self.profile
        stages = [st.key for st in self.project.stages if st.key in self.selected] if mine else None
        if mine and not stages:
            self.say("Nothing ticked. Use space to tick a check.")
            return
        fuzz = self.fuzz if mine else None

        def run(t):
            def on_stage(k, st):
                self.stage_state[k] = st
            scan = engine.Scan(self.project, profile, stages, fuzz, on_line=t.log, on_stage=on_stage)
            for k in scan.stages:
                self.stage_state[k] = {"status": "queued"}
            t.cancel_hook = scan.cancel
            return scan.run()

        def done(t):
            self.refresh()
            res = t.result
            new = sum(st.get("new", 0) + st.get("came_back", 0) for st in res["stages"].values())
            fixed = sum(st.get("fixed", 0) for st in res["stages"].values())
            self.say(f"Scan done · health {res['score']} ({res['grade']}) · {new} new, {fixed} fixed" + (" · press f to review" if new else ""))
            if new:
                curses.beep()
        self.start(f"{engine.PROFILES[profile]['title']} scan", run, done)

    def show_log(self, key):
        path = os.path.join(paths.workspace(self.target), f"{key}.log")
        if not os.path.exists(path):
            self.say(f"No log yet for {self.project.titles[key]}. Run a scan first.")
            return
        with open(path, errors="replace") as fh:
            text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", fh.read())
        self.push(TextView(f"{self.project.titles[key]} · full log", text))

    def explain(self, fp):
        f = self.db.get(fp)

        def done(t):
            if t.result:
                self.db.set_explanation(fp, t.result)
                self.refresh()
            else:
                self.say("Claude didn't return an explanation.")
        self.start("Claude is explaining", lambda t: claude.explain(f, self.target, proc_holder=t.procs)[1], done, claude_task=True, fp=fp)

    def fix(self, fp):
        f = self.db.get(fp)

        def done(t):
            r = t.result
            if r.get("error"):
                self.say(r["error"])
                return
            if not r["diff"].strip():
                self.push(TextView("Claude made no changes", r["summary"] or "No reply.",
                                   actions={"i": ("ignore this finding", lambda: (self.pop(), self.toggle_ignore(fp)))}))
                return
            self.fixes[fp] = r
            header = "Claude: " + (r["summary"] or "").strip().replace("\n", " ") + "\n\n"
            self.push(TextView(f"Proposed fix · {len(r['tracked']) + len(r['new_files'])} file(s) changed", header + r["diff"],
                               actions={"y": ("keep it", lambda: self.keep_fix(fp)), "n": ("undo it", lambda: self.undo_fix(fp))},
                               colorize=diff_color))
        self.start("Claude is fixing", lambda t: claude.fix(f, self.target, proc_holder=t.procs), done, claude_task=True, fp=fp)

    def keep_fix(self, fp):
        self.pop()
        self.fixes[fp]["kept"] = True
        f = self.db.get(fp)

        def run(t):  # re-run the check that found it, to prove the fix
            fuzz = 15 if f["stage"] == "fuzz" else None
            return engine.Scan(self.project, "standard", [f["stage"]], fuzz, on_line=t.log).run()

        def done(t):
            self.refresh()
            g = self.db.get(fp)
            if g and g["status"] == "fixed":
                self.say("Verified: the check no longer reports it ✓  Press r to turn the fix into a rule.")
            else:
                self.say("Kept the change, but the check still reports this. Press e to ask Claude why.")
        self.start(f"Verifying the fix ({self.project.titles.get(f['stage'], f['stage'])})", run, done, fp=fp)

    def undo_fix(self, fp):
        r = self.fixes.pop(fp)
        claude.revert(self.target, r["snapshot"], r["tracked"], r["new_files"])
        self.pop()
        self.say("Change undone; your files are back as they were.")

    def make_rule(self, fp):
        f = self.db.get(fp)
        diff = self.fixes.get(fp, {}).get("diff", "")

        def done(t):
            r = t.result
            if r.get("error"):
                self.say(r["error"])
                return
            where = "it matches nothing else right now" if not r["matches"] else f"it matches {r['matches']} place(s): scan to see them"
            self.reload()
            self.push(TextView(f"New rule added to .bugscan/rules.yml ({where})", r["rule"]))
        self.start("Claude is writing a rule", lambda t: claude.write_rule(f, self.target, diff, proc_holder=t.procs), done, claude_task=True, fp=fp)

    def write_harness(self):
        if self.info["harness"] and not self.confirm("This project already has a fuzzer. Have Claude write a new one? (y/n)"):
            return

        def run(t):
            t.log("Claude is reading the project to find functions worth fuzzing (this takes a minute or two)…")
            return claude.write_harness(self.target, self.info, on_line=t.log, proc_holder=t.procs)

        def done(t):
            r = t.result
            self.reload()
            if r.get("error"):
                self.push(TextView("Couldn't write a fuzzer", r["error"] + "\n\n" + (r.get("summary") or "")))
                return
            self.selected.add("fuzz")
            self.push(TextView(f"Fuzzer written: {short(r['path'], 60)}", (r.get("check", "") + "\n\n" + r["summary"]).strip()))
            self.say("Fuzzer ready and ticked. Press enter to scan with it.")
        self.start("Claude is writing a fuzzer", run, done, claude_task=True)

    def summary(self):
        if not self.db.latest_run():
            self.say("Run a scan first.")
            return
        self.start("Claude is summarizing", lambda t: claude.summarize(self.target, self.db, proc_holder=t.procs),
                   lambda t: self.push(TextView("Summary", t.result["text"] or "No reply.")), claude_task=True)

    def toggle_ignore(self, fp):
        f = self.db.get(fp)
        self.db.set_status(fp, "open" if f["status"] == "ignored" else "ignored")
        self.refresh()
        self.say("Un-ignored." if f["status"] == "ignored" else "Ignored: it no longer counts against health or fails scans.")

    def open_editor(self, f):
        if not f["file"]:
            self.say("This finding isn't tied to a file.")
            return
        path, line = os.path.join(self.target, f["file"]), f["line"] or 1
        if not os.path.exists(path):
            self.say(f"File not found: {f['file']}")
            return
        ed = os.environ.get("VISUAL") or os.environ.get("EDITOR")
        if ed:
            argv = shlex.split(ed)
            prog = os.path.basename(argv[0])
            if prog in ("code", "cursor"):
                # Your $EDITOR, no shell.
                subprocess.Popen(argv + ["-g", f"{path}:{line}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # nosemgrep
            elif prog in ("zed", "subl"):
                # Your $EDITOR, no shell.
                subprocess.Popen(argv + [f"{path}:{line}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # nosemgrep
            else:  # terminal editor: hand it the screen, then come back
                # Your $EDITOR, no shell.
                self.suspend(lambda: subprocess.call(argv + [f"+{line}", path]))  # nosemgrep
            return
        for prog, args in (("code", ["-g", f"{path}:{line}"]), ("cursor", ["-g", f"{path}:{line}"]), ("zed", [f"{path}:{line}"])):
            if shutil.which(prog):
                subprocess.Popen([prog] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.say(f"Opened in {prog}")
                return
        if path.endswith(".swift") and shutil.which("xed"):
            subprocess.Popen(["xed", "--line", str(line), path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.say("Opened in Xcode")
        else:
            subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.say(f"Opened {f['file']} (set $EDITOR to jump straight to line {line})")

    # terminal helpers
    def suspend(self, fn):
        curses.def_prog_mode()
        curses.endwin()
        try:
            fn()
        finally:
            curses.reset_prog_mode()
            self.scr.refresh()

    def run_in_terminal(self, cmd, title):
        def go():
            print(f"\n── {title} ──\n$ {cmd}\n", flush=True)
            rc = subprocess.call(shlex.split(cmd))
            input(f"\n{'Done' if rc == 0 else f'Failed (exit {rc})'}. Press Enter to go back to bugscan… ")
        self.suspend(go)

    def prompt(self, label, initial):
        text = initial
        curses.curs_set(1)
        self.scr.timeout(-1)
        try:
            while True:
                h, w = self.scr.getmaxyx()
                shown = text[-(w - len(label) - 3):]
                put(self.scr, h - 1, 0, (" " + label + shown).ljust(w), curses.color_pair(TITLE))
                self.scr.move(h - 1, min(w - 2, 1 + len(label) + len(shown)))
                ch = self.scr.get_wch()
                if ch in ("\n", "\r", curses.KEY_ENTER):
                    return text
                if ch == "\x1b":
                    return None
                if ch in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                    text = text[:-1]
                elif ch == "\x15":
                    text = ""
                elif isinstance(ch, str) and ch.isprintable():
                    text += ch
        finally:
            curses.curs_set(0)
            self.scr.timeout(100)

    def confirm(self, question):
        h, w = self.scr.getmaxyx()
        put(self.scr, h - 1, 0, (" " + question).ljust(w), curses.color_pair(TITLE) | curses.A_BOLD)
        self.scr.timeout(-1)
        ch = self.scr.getch()
        self.scr.timeout(100)
        return ch in (ord("y"), ord("Y"))


def watch_signature(target, info):
    """Changes whenever a file is saved: git status + mtimes of changed files, or mtimes of all files."""
    if info["git"]:
        r = subprocess.run(["git", "-C", target, "status", "--porcelain"], capture_output=True, text=True)
        files = [l[3:] for l in r.stdout.splitlines()]
    else:
        files = list(detect.walk(target, limit=5000))
    sig = []
    for f in files:
        try:
            sig.append((f, os.path.getmtime(os.path.join(target, f))))
        except OSError:
            sig.append((f, 0))
    return hash(tuple(sig))


def main(scr, target):
    curses.curs_set(0)
    curses.use_default_colors()
    for pair, fg in ((GREEN, curses.COLOR_GREEN), (RED, curses.COLOR_RED), (YELLOW, curses.COLOR_YELLOW),
                     (ACCENT, curses.COLOR_CYAN), (MAGENTA, curses.COLOR_MAGENTA)):
        curses.init_pair(pair, fg, -1)
    curses.init_pair(TITLE, curses.COLOR_BLACK, curses.COLOR_CYAN)
    SEV_ATTR.update({"critical": curses.color_pair(MAGENTA) | curses.A_BOLD, "high": curses.color_pair(RED) | curses.A_BOLD,
                     "medium": curses.color_pair(YELLOW), "low": curses.color_pair(ACCENT), "info": curses.A_DIM})
    app = App(scr, target)

    def stop(signum, frame):  # terminal closed or killed: don't leave a scan running in the background
        raise SystemExit(1)
    signal.signal(signal.SIGHUP, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        app.loop()
    finally:
        if app.busy():
            app.task.cancel()


def run(target):
    locale.setlocale(locale.LC_ALL, "")
    target = os.path.realpath(os.path.expanduser(target))
    if not os.path.isdir(target):
        print(f"Not a folder: {target}", file=sys.stderr)
        return 2
    try:
        engine.Project(target)
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2
    if not sys.stdout.isatty():
        print("The interactive UI needs a terminal. For scripts and CI use: bugscan scan", file=sys.stderr)
        return 2
    os.environ.setdefault("ESCDELAY", "25")
    curses.wrapper(main, target)
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else os.getcwd()))
