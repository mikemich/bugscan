import functools
import json
import os
import re
import subprocess

from .. import findings, paths
from .base import Result, Stage, error, skip


@functools.lru_cache(maxsize=1)
def exclude_flag():
    """osv-scanner renamed --experimental-exclude to --x-exclude (2.6); use whichever this version has."""
    try:
        help_text = subprocess.run(["osv-scanner", "scan", "source", "--help"], capture_output=True, text=True, timeout=30)
        return "--x-exclude" if "--x-exclude" in (help_text.stdout + help_text.stderr) else "--experimental-exclude"
    except (OSError, subprocess.TimeoutExpired):
        return "--x-exclude"


class Deps(Stage):
    key, title, description = "deps", "Dependencies", "known vulnerable packages (OSV)"
    levels = ("quick", "standard", "deep")
    tools = ("osv-scanner",)

    def applies(self, info, config):
        return (True, "") if info["lockfiles"] else (False, "no lockfiles found")

    def run(self, ctx):
        if self.missing_tool():
            return skip("osv-scanner is not installed (see bugscan doctor)")
        report = ctx.out("osv.json")
        if os.path.exists(report):
            os.remove(report)
        cmd = ["osv-scanner", "scan", "source", "-r", ctx.target, "--format", "json", "--output-file", report,
               "--verbosity", "error", exclude_flag(), "node_modules"]
        for e in ctx.exclude:
            cmd += [exclude_flag(), e]
        offline = os.environ.get("BUGSCAN_OFFLINE") == "1"
        rc, _ = ctx.run(cmd + (["--offline-vulnerabilities"] if offline else []))
        if rc not in (0, 1, 128) and not offline:
            ctx.log(f"online lookup failed (exit {rc}); retrying with the cached offline database")
            rc, _ = ctx.run(cmd + ["--offline-vulnerabilities"])
        if rc == 128:
            return skip("no lockfiles or manifests found")
        if rc not in (0, 1) or not os.path.exists(report):
            return error(f"osv-scanner failed (exit {rc})")
        items = parse(report, ctx.src)
        total = sum(len(f["extra"]["advisories"]) for f in items)
        ctx.log(f"{total} known vulnerabilities in {len(items)} packages")
        for f in items:
            ctx.log(f"  {f['file']}: {f['message'].split(' Worst:')[0]}")
        return Result("ok", items)


def _ver(v):
    """Sortable version key: '4.17.21' -> (4, 17, 21); non-numeric parts sort after numbers."""
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-+_]", str(v)) if p)


def _severity(score, text):
    try:
        s = float(score)
        return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
    except (TypeError, ValueError):
        return {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}.get((text or "").upper(), "medium")


def kev_ids():
    try:
        with open(paths.cache("kev.json")) as fh:
            return {v["cveID"] for v in json.load(fh).get("vulnerabilities", [])}
    except (OSError, ValueError):
        return set()


SEV_ORDER = ["critical", "high", "medium", "low", "info"]
DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "low", "info": "info"}


def dev_packages(lockfile):
    """npm packages that are only needed for development/builds, from package-lock.json's `dev` flags."""
    try:
        with open(lockfile) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return set()
    entries = {}
    for key, meta in (data.get("packages") or {}).items():
        if "node_modules/" in key:
            name = key.rsplit("node_modules/", 1)[1]
            entries.setdefault(name, []).append(bool(meta.get("dev") or meta.get("devOptional")))
    return {name for name, flags in entries.items() if flags and all(flags)}


def is_dev_manifest(path):
    name = os.path.basename(path or "").lower()
    return any(w in name for w in ("dev", "test", "lint", "docs")) and name.endswith((".txt", ".in"))


def parse(report, src):
    """One finding per vulnerable package (per manifest): how many advisories, the worst severity, and the
    version that fixes all of them. Dev-only packages are ranked one level lower."""
    with open(report) as fh:
        data = json.load(fh)
    kev, out = kev_ids(), []
    for r in data.get("results", []):
        path = r.get("source", {}).get("path")
        file = src.rel(path)
        devs = dev_packages(path) if os.path.basename(path or "") == "package-lock.json" else set()
        dev_manifest = is_dev_manifest(path)
        for p in r.get("packages", []):
            pkg = p["package"]
            vulns = {v["id"]: v for v in p.get("vulnerabilities", [])}
            advisories = []
            # one group per distinct issue (aliases merged); without groups, one per advisory
            groups = p.get("groups") or [{"ids": [v["id"]], "aliases": v.get("aliases", []), "max_severity": ""} for v in vulns.values()]
            for g in groups:
                ids, aliases = g.get("ids", []), g.get("aliases", [])
                v = next((vulns[i] for i in ids if i in vulns), {})
                cves = sorted(a for a in set(aliases) | set(ids) if a.startswith("CVE-"))
                fixes = {e["fixed"] for a in v.get("affected", []) if a.get("package", {}).get("name") == pkg["name"]
                         for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e}
                above = sorted((f for f in fixes if _ver(f) > _ver(pkg["version"])), key=_ver)  # nearest fix above installed
                exploited = bool(kev & set(cves))
                summary = v.get("summary") or (v.get("details") or "").strip().split("\n")[0].split(". ")[0][:140] or "known vulnerability"
                advisories.append({
                    "id": cves[0] if cves else ids[0] if ids else "advisory", "summary": summary,
                    "severity": "critical" if exploited else _severity(g.get("max_severity"), v.get("database_specific", {}).get("severity")),
                    "fixed": (above or sorted(fixes, key=_ver)[-1:] or [None])[0], "kev": exploited,
                    "url": f"https://osv.dev/vulnerability/{ids[0]}" if ids else None})
            if not advisories:
                continue
            advisories.sort(key=lambda a: SEV_ORDER.index(a["severity"]))
            worst = advisories[0]["severity"]
            fixes = [a["fixed"] for a in advisories if a["fixed"]]
            fix = max(fixes, key=_ver) if fixes else None  # one upgrade that clears every advisory
            unfixed = sum(1 for a in advisories if not a["fixed"])
            dev = pkg["name"] in devs or dev_manifest
            sev = DOWNGRADE[worst] if dev and not any(a["kev"] for a in advisories) else worst
            counts = {s: sum(a["severity"] == s for a in advisories) for s in SEV_ORDER}
            breakdown = ", ".join(f"{n} {s}" for s, n in counts.items() if n)
            n = len(advisories)
            msg = f"{pkg['name']} {pkg['version']}: {n} known vulnerabilit{'y' if n == 1 else 'ies'} ({breakdown})."
            if fix:
                msg += f" Upgrade to {fix} to fix {'it' if n == 1 else 'them' if not unfixed else f'{n - unfixed} of them'}."
            else:
                msg += " No fixed version yet."
            if any(a["kev"] for a in advisories):
                msg += " Actively exploited (CISA KEV)."
            if dev:
                msg += " Dev dependency: only affects development and builds."
            msg += " Worst: " + advisories[0]["summary"]
            out.append(findings.make("deps", "osv-scanner", "vulnerable-dependency", sev, file, None, msg,
                                     key=f"{pkg['ecosystem']}|{pkg['name']}|{file}",
                                     package=pkg["name"], version=pkg["version"], ecosystem=pkg["ecosystem"],
                                     fixed=fix, dev=dev or None, kev=any(a["kev"] for a in advisories) or None,
                                     advisories=advisories, url=advisories[0]["url"]))
    return out
