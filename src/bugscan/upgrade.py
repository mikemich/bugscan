"""Upgrade a vulnerable dependency without Claude, when the package manager can do it deterministically:
npm (package.json + package-lock.json, via npm itself) and pinned lines in requirements*.txt.
Everything else falls back to Claude. Changes are snapshotted so they can be reviewed and undone."""
import json
import os
import re
import shutil
import subprocess

from . import claude


def plan(f, target):
    """A dict describing the upgrade, or None when it needs Claude."""
    ex = f.get("extra") or {}
    if f["stage"] != "deps" or not ex.get("fixed") or not f.get("file"):
        return None
    name, fix, eco = ex["package"], ex["fixed"], ex.get("ecosystem")
    folder = os.path.dirname(os.path.join(target, f["file"]))
    if eco == "npm" and os.path.basename(f["file"]) == "package-lock.json" and shutil.which("npm"):
        try:
            with open(os.path.join(folder, "package.json")) as fh:
                pj = json.load(fh)
        except (OSError, ValueError):
            return None
        dev = name in (pj.get("devDependencies") or {})
        direct = dev or name in (pj.get("dependencies") or {})
        base = ["npm", "--ignore-scripts", "--package-lock-only", "--no-audit", "--no-fund"]
        cmd = base + (["install", f"{name}@^{fix}"] + (["--save-dev"] if dev else []) if direct else ["update", name])
        how = f"npm {'install' if direct else 'update'} {name}" + (f"@^{fix}" if direct else "")
        return {"kind": "npm", "cwd": folder, "cmd": cmd, "package": name, "fixed": fix, "direct": direct,
                "lockfile": os.path.join(folder, "package-lock.json"),
                "describe": f"{how} in {os.path.relpath(folder, target)} (updates package.json and the lockfile, installs nothing)"}
    if eco == "PyPI" and f["file"].endswith((".txt", ".in")):
        path = os.path.join(target, f["file"])
        with open(path) as fh:
            text = fh.read()
        rx = re.compile(rf"^(?P<pre>{re.escape(name)}(?:\[[^\]]*\])?\s*==\s*){re.escape(ex['version'])}(?P<post>\s*(?:[;#].*)?)$", re.M | re.I)
        if not rx.search(text):
            return None
        family = sorted({m.group(1) for m in re.finditer(rf"^({re.escape(name)}[\w-]+)\s*==\s*{re.escape(ex['version'])}\b", text, re.M | re.I)})
        note = f" Also pinned to {ex['version']}: {', '.join(family)} (these usually have to match)." if family else ""
        return {"kind": "pip", "file": path, "regex": rx, "package": name, "fixed": fix,
                "describe": f"pin {name}=={fix} in {f['file']}.{note}"}
    return None


def lock_version(lockfile, name):
    try:
        with open(lockfile) as fh:
            pkgs = json.load(fh).get("packages") or {}
    except (OSError, ValueError):
        return None
    meta = pkgs.get(f"node_modules/{name}")
    return meta.get("version") if meta else None


def apply(p, target, log=lambda s: None):
    """Run the plan. Returns the same shape as claude.fix: snapshot, changed files, diff, summary."""
    if not claude.is_git(target):
        return {"error": "Upgrading needs a git repository (so the change can be reviewed and undone)."}
    snap = claude.snapshot(target)
    summary = p["describe"]
    if p["kind"] == "npm":
        log("$ " + " ".join(p["cmd"]))
        r = subprocess.run(p["cmd"], cwd=p["cwd"], capture_output=True, text=True, timeout=600)
        for line in (r.stdout + r.stderr).strip().splitlines()[-5:]:
            log(line)
        if r.returncode != 0:
            tracked, new_files, _ = claude.changes_since(target, snap)
            claude.revert(target, snap, tracked, new_files)
            return {"error": f"npm couldn't upgrade {p['package']}: {(r.stderr or r.stdout).strip().splitlines()[-1:] or ['unknown error']}"}
        got = lock_version(p["lockfile"], p["package"])
        from .stages.deps import _ver
        if got and _ver(got) < _ver(p["fixed"]):
            summary += (f"\nnpm could only move {p['package']} to {got}: a package that depends on it pins an older range. "
                        f"Upgrade that package instead, or ask Claude (C).")
    else:
        with open(p["file"]) as fh:
            text = fh.read()
        with open(p["file"], "w") as fh:
            fh.write(p["regex"].sub(lambda m: m.group("pre") + p["fixed"] + m.group("post"), text))
    tracked, new_files, diff = claude.changes_since(target, snap)
    return {"snapshot": snap, "tracked": tracked, "new_files": new_files, "diff": diff, "summary": summary, "rc": 0}
