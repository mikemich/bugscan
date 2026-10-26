"""A git pre-commit hook that runs a quick bugscan on the staged changes."""
import os
import shlex
import subprocess
import sys

MARK = "# bugscan pre-commit hook"


def _hook_path(target):
    r = subprocess.run(["git", "-C", target, "rev-parse", "--git-path", "hooks/pre-commit"], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    p = r.stdout.strip()
    return p if os.path.isabs(p) else os.path.join(target, p)


def installed(target):
    p = _hook_path(target)
    if not (p and os.path.exists(p)):
        return False
    with open(p, errors="replace") as fh:
        return MARK in fh.read()


def install(target):
    p = _hook_path(target)
    if not p:
        return "Not a git repository, so there is nothing to hook into."
    if installed(target):
        return "The pre-commit hook is already installed."
    os.makedirs(os.path.dirname(p), exist_ok=True)
    chained = ""
    if os.path.exists(p):  # keep the existing hook and run it first
        os.rename(p, p + ".bugscan-orig")
        chained = f'"{p}.bugscan-orig" "$@" || exit $?\n'
    launcher = f"{shlex.quote(sys.executable)} -m bugscan"
    with open(p, "w") as fh:
        fh.write(f"""#!/bin/sh
{MARK} (remove with: bugscan hook uninstall)
{chained}{launcher} scan -t {shlex.quote(os.path.realpath(target))} --level quick --staged --fail-on new || {{
  echo "bugscan found new issues in the staged changes. Fix them, or commit with --no-verify to skip the check."
  exit 1
}}
""")
    # Git hooks must be executable.
    os.chmod(p, 0o755)  # nosemgrep
    return "Installed: every commit now runs a quick scan of the staged changes." + (" Your existing hook still runs first." if chained else "")


def uninstall(target):
    p = _hook_path(target)
    if not p or not installed(target):
        return "No bugscan hook installed."
    os.remove(p)
    if os.path.exists(p + ".bugscan-orig"):
        os.rename(p + ".bugscan-orig", p)
        return "Removed; your original pre-commit hook is restored."
    return "Removed the pre-commit hook."
