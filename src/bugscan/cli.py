"""bugscan: find bugs in any folder. Run without arguments for the interactive UI.

  bugscan [FOLDER]                      interactive UI
  bugscan scan [-t FOLDER] [options]    scan from the command line or CI (see bugscan scan -h)
  bugscan findings [-t FOLDER]          list findings          bugscan show ID     one finding in full
  bugscan explain ID / fix ID           ask Claude to explain / fix a finding (you confirm the change)
  bugscan ignore ID                     mark a finding as not a problem (again to undo)
  bugscan sync | report | doctor        update data · HTML report · check installed tools
  bugscan hook install|uninstall        quick scan before every git commit
  bugscan init                          create .bugscan/config.toml
"""
import argparse
import json
import os
import shutil
import sys

from . import __version__, findings, paths
from .config import ConfigError

SEV_COLOR = {"critical": "\033[1;35m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
STATE_COLOR = {"new": "\033[1;31m", "came back": "\033[1;31m", "open": "\033[33m", "fixed": "\033[32m", "ignored": "\033[2m"}


def color(code, text):
    return f"{code}{text}\033[0m" if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else text


def where(f):
    return f"{f['file']}:{f['line']}" if f["file"] and f["line"] else f["file"] or "-"


def print_findings(items, titles, limit=None):
    for f in items[:limit]:
        state = color(STATE_COLOR[f["state"]], f"{f['state']:<9}")
        sev = color(SEV_COLOR.get(f["severity"], ""), f"{f['severity']:<8}")
        check = titles.get(f["stage"], f["stage"])[:16]
        print(f"  {f['id']}  {state} {sev} {check:<16} {where(f)[:34]:<34} {f['message'].splitlines()[0][:100]}")
    if limit and len(items) > limit:
        print(f"  … and {len(items) - limit} more (bugscan findings)")


def project(a):
    from .engine import Project
    if getattr(a, "out", None):
        paths.set_workspace(a.target, a.out)
    return Project(a.target)


def cmd_scan(a):
    from .engine import PROFILES, Scan
    p = project(a)
    cfg = p.config["scan"]
    fail_on = a.fail_on or cfg["fail_on"]
    min_sev = a.min_severity or cfg["min_severity"]
    level = a.level or cfg["level"]

    def stage(k, st):
        if st["status"] in ("running", "queued"):
            return
        extra = f"  {st.get('found', 0)} found, {st.get('new', 0) + st.get('came_back', 0)} new, {st.get('fixed', 0)} fixed" if "found" in st else (f"  {st.get('note')}" if st.get("note") else "")
        print(f"  {p.titles[k]:<18} {st['status']:<9} {st.get('secs', 0):>4}s{extra}", flush=True)

    def line(s):
        if a.verbose:
            print("    " + s, flush=True)

    scan = Scan(p, level, a.stages.split(",") if a.stages else None, a.fuzz, a.staged, on_line=line, on_stage=stage)
    from .detect import describe
    print(f"Scanning {p.target}  ({describe(p.info)}) · {PROFILES[level]['title']}", flush=True)
    res = scan.run()
    items = scan.db.findings()
    new = [f for f in items if f["state"] in ("new", "came back")]
    print(f"\nHealth {res['score']} ({res['grade']}) · {len(items)} open findings, {len(new)} new")
    if new:
        print_findings(new, p.titles, 25)
    elif items:
        print("  Nothing new. `bugscan findings` lists the open ones.")
    if a.sarif:
        with open(a.sarif, "w") as fh:
            json.dump(findings.to_sarif(items), fh, indent=1)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"score": res["score"], "grade": res["grade"], "stages": res["stages"], "findings": findings.to_json(items)}, fh, indent=1)
    if fail_on == "none":
        return 0
    failing = new if fail_on == "new" else items
    limit = findings.SEVERITIES.index(min_sev)
    bad = [f for f in failing if findings.SEVERITIES.index(f["severity"]) <= limit]
    errors = [k for k, st in res["stages"].items() if st["status"] == "error"]
    if errors:
        print(f"\n{len(errors)} check(s) couldn't run: {', '.join(errors)} (see the logs in {paths.workspace(p.target)})")
    return 1 if bad or errors else 0


def cmd_findings(a):
    p = project(a)
    db = findings.DB(p.target)
    items = db.findings(include_closed=a.all)
    if a.json:
        json.dump(findings.to_json(items), sys.stdout, indent=1)
        print()
        return 0
    s, g = db.score()
    print(f"Health {s} ({g}) · {sum(f['status'] == 'open' for f in items)} open")
    print_findings(items, p.titles)
    return 0


def _get(a):
    p = project(a)
    db = findings.DB(p.target)
    f = db.get(a.id)
    if not f:
        print(f"No single finding matches {a.id!r}. Run `bugscan findings` to see the ids.", file=sys.stderr)
        return p, db, None
    return p, db, f


def cmd_show(a):
    p, db, f = _get(a)
    if not f:
        return 2
    print(f"{f['id']}  {f['severity'].upper()} · {f['state']} · {p.titles.get(f['stage'], f['stage'])} · {f['rule']}\n{where(f)}\n\n{f['message']}")
    for k, v in f["extra"].items():
        print(f"  {k}: {v}")
    from .claude import context
    code = context(f, p.target)
    if code:
        print("\n" + code)
    if f.get("explanation"):
        print("\n" + f["explanation"])
    return 0


def cmd_explain(a):
    from . import claude
    p, db, f = _get(a)
    if not f:
        return 2
    if not claude.available():
        print("Claude Code isn't installed (see bugscan doctor).", file=sys.stderr)
        return 2
    print("Asking Claude…", file=sys.stderr)
    rc, text = claude.explain(f, p.target)
    if text:
        db.set_explanation(f["fp"], text)
    print(text)
    return 0 if rc == 0 else 1


def cmd_fix(a):
    from . import claude
    p, db, f = _get(a)
    if not f:
        return 2
    if not claude.available():
        print("Claude Code isn't installed (see bugscan doctor).", file=sys.stderr)
        return 2
    print("Claude is fixing it…", file=sys.stderr)
    r = claude.fix(f, p.target)
    if r.get("error"):
        print(r["error"], file=sys.stderr)
        return 2
    print(r["summary"])
    if not r["diff"].strip():
        print("\nNo changes were made.")
        return 0
    print("\n" + r["diff"])
    answer = "y" if a.yes else ""
    if not a.yes:
        try:  # no terminal or Ctrl-C: never leave an unconfirmed change behind
            answer = input("Keep this change? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nNo answer (use --yes to keep changes without asking).")
    if answer != "y":
        claude.revert(p.target, r["snapshot"], r["tracked"], r["new_files"])
        print("Undone; your files are back as they were.")
        return 0
    from .engine import Scan
    print(f"Kept. Re-running {p.titles[f['stage']]} to verify…")
    Scan(p, "standard", [f["stage"]], 15 if f["stage"] == "fuzz" else None).run()
    g = db.get(f["fp"])
    print("Verified: no longer reported." if g and g["status"] == "fixed" else "The check still reports it; have a look.")
    return 0


def cmd_ignore(a):
    p, db, f = _get(a)
    if not f:
        return 2
    new = "open" if f["status"] == "ignored" else "ignored"
    db.set_status(f["fp"], new)
    print("Ignored." if new == "ignored" else "Un-ignored.")
    return 0


def cmd_sync(a):
    from . import sync
    sync.sync_all(project(a), force=a.force)
    return 0


def cmd_report(a):
    from . import report
    path = report.write(project(a))
    print(path)
    if a.open:
        import subprocess
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0


def cmd_doctor(a):
    from . import setup
    tools = setup.check()
    for t in tools:
        mark = color("\033[32m", "✓") if t["ok"] else color("\033[31m", "✗")
        tail = t["detail"] if t["ok"] else "install: " + t["install"]
        print(f"  {mark} {t['name']:<12} {t['purpose']:<42} {tail}")
    missing = [t["name"] for t in tools if t["required"] and not t["ok"]]
    if missing:
        print(f"\nThe core checks need: {', '.join(missing)}")
    return 1 if missing else 0


def cmd_hook(a):
    from . import hooks
    print(hooks.install(a.target) if a.action == "install" else hooks.uninstall(a.target))
    return 0


def cmd_init(a):
    dest = os.path.join(paths.project_dir(a.target), "config.toml")
    if os.path.exists(dest):
        print(f"{dest} already exists.")
        return 1
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy(paths.data("config.toml"), dest)
    print(f"Created {dest}")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or (len(argv) == 1 and not argv[0].startswith("-") and os.path.isdir(argv[0])):
        from . import tui
        return tui.run(argv[0] if argv else os.getcwd())
    p = argparse.ArgumentParser(prog="bugscan", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"bugscan {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def add(name, fn, help, ident=False):
        sp = sub.add_parser(name, help=help)
        sp.add_argument("-t", "--target", default=".", help="project folder (default: current folder)")
        sp.add_argument("--out", help="folder for results (default: ~/.cache/bugscan/projects/…)")
        if ident:
            sp.add_argument("id", help="finding id (from bugscan findings)")
        sp.set_defaults(fn=fn)
        return sp
    s = add("scan", cmd_scan, "run a scan")
    s.add_argument("--level", choices=["quick", "standard", "deep"], help="default: from config, else standard")
    s.add_argument("--stages", help="comma-separated checks to run (default: all that apply to the level)")
    s.add_argument("--fuzz", type=int, help="seconds of fuzzing")
    s.add_argument("--staged", action="store_true", help="quick level: only staged changes (used by the git hook)")
    s.add_argument("--fail-on", choices=["new", "any", "none"], help="exit 1 on new findings (default), any, or never")
    s.add_argument("--min-severity", choices=findings.SEVERITIES, help="ignore findings below this when deciding failure")
    s.add_argument("--sarif", help="also write findings as SARIF (for GitHub code scanning)")
    s.add_argument("--json", help="also write results as JSON")
    s.add_argument("-v", "--verbose", action="store_true", help="show tool output")
    f = add("findings", cmd_findings, "list findings")
    f.add_argument("--all", action="store_true", help="include fixed and ignored")
    f.add_argument("--json", action="store_true", help="print JSON")
    add("show", cmd_show, "show one finding", ident=True)
    add("explain", cmd_explain, "Claude explains a finding", ident=True)
    x = add("fix", cmd_fix, "Claude fixes a finding (you confirm)", ident=True)
    x.add_argument("--yes", action="store_true", help="keep the change without asking")
    add("ignore", cmd_ignore, "ignore / un-ignore a finding", ident=True)
    y = add("sync", cmd_sync, "update rules, vulnerability data and fuzz seeds")
    y.add_argument("--force", action="store_true")
    r = add("report", cmd_report, "write an HTML report")
    r.add_argument("--open", action="store_true")
    add("doctor", cmd_doctor, "check installed tools")
    h = add("hook", cmd_hook, "git pre-commit hook")
    h.add_argument("action", choices=["install", "uninstall"])
    add("init", cmd_init, "create .bugscan/config.toml")
    a = p.parse_args(argv)
    if not a.cmd:
        p.print_help()
        return 2
    a.target = os.path.realpath(os.path.expanduser(a.target))
    if not os.path.isdir(a.target):
        print(f"Not a folder: {a.target}", file=sys.stderr)
        return 2
    try:
        return a.fn(a)
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
