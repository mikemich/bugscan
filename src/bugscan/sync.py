"""Download and cache outside knowledge so scans are fast and work offline: Semgrep registry rules,
CISA's Known Exploited Vulnerabilities list, OSV offline databases, a public fuzzing dictionary, and
real inputs listed as [[seed]] in a project's config (saved as extra fuzz seeds)."""
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request

from . import __version__, paths

UA = {"User-Agent": f"bugscan/{__version__}"}
DAY = 86400


def fetch(url, timeout=30):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def _fresh(path, max_age):
    return os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age


def rule_file(pack):
    return paths.cache("rules", pack.replace("/", "_") + ".yml")


def missing_packs():
    f = paths.cache("rules", "missing.json")
    try:
        with open(f) as fh:
            return set(json.load(fh))
    except (OSError, ValueError):
        return set()


def rules(packs, force=False, max_age=7 * DAY, log=print):
    """Cache each Semgrep registry pack as a local file. Returns {pack: path} for those available."""
    missing = missing_packs()
    out = {}
    for pack in packs:
        path = rule_file(pack)
        if pack in missing and not force:
            continue
        if force or not _fresh(path, max_age):
            try:
                data = fetch(f"https://semgrep.dev/c/{pack}")
                if not data.lstrip().startswith(b"rules:"):
                    raise ValueError("not a rules file")
                with open(path, "wb") as fh:
                    fh.write(data)
                missing.discard(pack)
                log(f"  rules  {pack}: {data.count(b'- id:')} rules")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    missing.add(pack)
                    log(f"  rules  {pack}: not in the registry, skipped")
                else:
                    log(f"  rules  {pack}: download failed ({e}){'; using cached copy' if os.path.exists(path) else ''}")
            except Exception as e:  # offline etc.: keep the cached copy
                log(f"  rules  {pack}: download failed ({e}){'; using cached copy' if os.path.exists(path) else ''}")
        if os.path.exists(path):
            out[pack] = path
    with open(paths.cache("rules", "missing.json"), "w") as fh:
        json.dump(sorted(missing), fh)
    return out


def kev(force=False, log=print):
    path = paths.cache("kev.json")
    if force or not _fresh(path, DAY):
        try:
            data = fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            n = json.loads(data)["count"]
            with open(path, "wb") as fh:
                fh.write(data)
            log(f"  KEV    {n} actively exploited vulnerabilities (CISA)")
        except Exception as e:
            log(f"  KEV    download failed ({e})")
    return path if os.path.exists(path) else None


def dictionary(force=False, log=print):
    path = paths.cache("dicts", "json.dict")
    if force or not _fresh(path, 30 * DAY):
        try:
            data = fetch("https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/dictionaries/json.dict")
            with open(path, "wb") as fh:
                fh.write(data)
            log("  dict   AFL++ JSON fuzzing dictionary")
        except Exception as e:
            log(f"  dict   download failed ({e})")
    return path if os.path.exists(path) else None


def osv_databases(target, log=print):
    """Download OSV databases for the ecosystems this project uses, for offline dependency checks."""
    if not shutil.which("osv-scanner"):
        log("  osv    osv-scanner not installed, skipped")
        return
    r = subprocess.run(["osv-scanner", "scan", "source", "-r", target, "--offline-vulnerabilities", "--download-offline-databases",
                        "--x-exclude", "node_modules", "--format", "json", "--verbosity", "error"],
                       capture_output=True, text=True, timeout=1800)
    if r.returncode == 128:
        log("  osv    no lockfiles here, nothing to download")
    elif r.returncode in (0, 1):
        log("  osv    offline vulnerability databases ready")
    else:
        log(f"  osv    download failed: {(r.stderr or r.stdout).strip()[:160]}")


def seeds(target, config, log=print):
    """Fetch the project's [[seed]] URLs into its workspace as extra fuzz seeds."""
    if not config["seeds"]:
        return 0
    d = os.path.join(paths.workspace(target), "seeds")
    os.makedirs(d, exist_ok=True)
    n = 0
    for s in config["seeds"]:
        try:
            data = fetch(s["url"])
            try:
                json.loads(data)
                ext = ".json"
            except ValueError:
                ext = ".txt"
            name = s["name"] if os.path.splitext(s["name"])[1] else s["name"] + ext
            with open(os.path.join(d, name), "wb") as fh:
                fh.write(data)
            n += 1
        except Exception as e:
            log(f"  seed   {s['name']}: download failed ({e})")
    log(f"  seeds  {n} of {len(config['seeds'])} real inputs saved as fuzz seeds")
    return n


def sync_all(project, force=False, log=print):
    from .detect import packs_for
    log("Updating rules and vulnerability data…")
    got = rules(packs_for(project.info, deep=True), force=force, log=log)
    log(f"  rules  {len(got)} Semgrep rule packs ready ({', '.join(got)})")
    kev(force=force, log=log)
    dictionary(force=force, log=log)
    osv_databases(project.target, log=log)
    seeds(project.target, project.config, log=log)
    log("Done.")
