"""Where things live.

Scan results go to a private workspace under ~/.cache/bugscan, so scanning never writes into the
scanned project, except `<project>/.bugscan/`: user-owned, committable files (config, fuzz harness,
saved crash inputs, custom rules)."""
import hashlib
import os

PKG = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(PKG, "data")


def cache_root():
    return os.environ.get("BUGSCAN_CACHE") or os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "bugscan")


def cache(*parts):
    p = os.path.join(cache_root(), *parts)
    os.makedirs(os.path.dirname(p) if os.path.splitext(p)[1] else p, exist_ok=True)
    return p


_overrides = {}


def set_workspace(target, path):
    """Use `path` for this target's results (bugscan scan --out DIR)."""
    _overrides[os.path.realpath(target)] = os.path.abspath(path)


def workspace(target):
    t = os.path.realpath(target)
    d = _overrides.get(t) or os.path.join(
        cache_root(), "projects", f"{os.path.basename(t) or 'root'}-{hashlib.sha256(t.encode()).hexdigest()[:8]}")
    os.makedirs(d, exist_ok=True)
    return d


def project_dir(target):
    return os.path.join(os.path.realpath(target), ".bugscan")


def data(name):
    return os.path.join(DATA, name)
