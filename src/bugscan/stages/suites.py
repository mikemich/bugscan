"""Find the project's own test suites and type-check/lint configs (including in subfolders)."""
import functools
import json
import os
import shutil
import subprocess

from .. import detect


def _dirs_with(info_target, names, exclude=(), max_depth=3):
    found = []
    for rel in detect.walk(info_target, exclude=exclude):
        if os.path.basename(rel) in names and rel.count("/") < max_depth:
            found.append(os.path.dirname(rel))
    return sorted(set(found))


def has_local_bin(target, d, name):
    """node_modules/.bin/<name> in d or any parent up to the project root."""
    cur = os.path.join(target, d)
    while True:
        if os.path.exists(os.path.join(cur, "node_modules", ".bin", name)):
            return True
        if os.path.realpath(cur) == os.path.realpath(target):
            return False
        cur = os.path.dirname(cur)


@functools.lru_cache(maxsize=1)
def pytest_available():
    return subprocess.run(["python3", "-c", "import pytest"], capture_output=True).returncode == 0


def suites(target, exclude=()):
    """[(kind, folder, command, skip_reason or None)] for every test suite found."""
    out = []
    for d in _dirs_with(target, {"package.json"}, exclude):
        try:
            with open(os.path.join(target, d, "package.json")) as fh:
                script = (json.load(fh).get("scripts") or {}).get("test", "")
        except (OSError, ValueError):
            continue
        if not script or "no test specified" in script:
            continue
        why = None if os.path.isdir(os.path.join(target, d, "node_modules")) else "dependencies aren't installed (run npm install)"
        out.append(("npm", d, ["npm", "test", "--silent"], why if shutil.which("npm") else "npm isn't installed"))
    for d in _dirs_with(target, {"Cargo.toml"}, exclude):
        if any(o[0] == "cargo" and (d + "/").startswith(o[1] + "/") and o[1] != d for o in out):
            continue  # a member of a workspace already listed
        out.append(("cargo", d, ["cargo", "test", "--quiet"], None if shutil.which("cargo") else "cargo isn't installed"))
    def packaging_root(d):  # a setup.py only counts if it really is a packaging script
        if os.path.exists(os.path.join(target, d, "setup.py")) and not any(
                os.path.exists(os.path.join(target, d, n)) for n in ("pyproject.toml", "setup.cfg", "pytest.ini", "conftest.py")):
            with open(os.path.join(target, d, "setup.py"), errors="replace") as fh:
                return "setup(" in fh.read()
        return True
    py_roots = [d for d in _dirs_with(target, {"pyproject.toml", "setup.py", "setup.cfg", "pytest.ini", "conftest.py"}, exclude)
                if packaging_root(d)]
    has_tests = any(os.path.basename(f).startswith("test_") and f.endswith(".py") or f.endswith("_test.py")
                    for f in detect.walk(target, exclude=exclude))
    if has_tests:
        roots = py_roots or [""]
        roots = [r for r in roots if not any(r != o and (r + "/").startswith(o + "/") for o in roots if o)]  # outermost only
        for d in roots:
            if pytest_available():
                out.append(("pytest", d, ["python3", "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider"], None))
            else:  # the standard library runner finds unittest-style tests (and plain test_ functions in classes)
                out.append(("unittest", d, ["python3", "-m", "unittest", "discover"], None))
    return out
