import json
import os
import re

from .. import findings, paths
from .base import Result, Stage, error, skip


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
               "--verbosity", "error", "--x-exclude", "node_modules"]
        for e in ctx.exclude:
            cmd += ["--x-exclude", e]
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
        ctx.log(f"{len(items)} known vulnerabilities in {len({f['extra']['package'] for f in items})} packages")
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


def parse(report, src):
    with open(report) as fh:
        data = json.load(fh)
    kev, out = kev_ids(), []
    for r in data.get("results", []):
        file = src.rel(r.get("source", {}).get("path"))
        for p in r.get("packages", []):
            pkg = p["package"]
            vulns = {v["id"]: v for v in p.get("vulnerabilities", [])}
            for g in p.get("groups", []):
                ids, aliases = g.get("ids", []), g.get("aliases", [])
                v = next((vulns[i] for i in ids if i in vulns), {})
                cves = sorted(a for a in set(aliases) | set(ids) if a.startswith("CVE-"))
                fixes = {e["fixed"] for a in v.get("affected", []) if a.get("package", {}).get("name") == pkg["name"]
                         for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e}
                above = sorted((f for f in fixes if _ver(f) > _ver(pkg["version"])), key=_ver)  # nearest fix above installed
                fix = (above or sorted(fixes, key=_ver)[-1:] or [None])[0]
                exploited = bool(kev & set(cves))
                sev = "critical" if exploited else _severity(g.get("max_severity"), v.get("database_specific", {}).get("severity"))
                label = cves[0] if cves else ids[0] if ids else "advisory"
                summary = v.get("summary") or (v.get("details") or "").strip().split("\n")[0].split(". ")[0][:140] or "known vulnerability"
                msg = f"{pkg['name']} {pkg['version']}: {summary} ({label})"
                if exploited:
                    msg += " - actively exploited (CISA KEV)"
                if fix:
                    msg += f". Fixed in {fix}."
                out.append(findings.make("deps", "osv-scanner", label, sev, file, None, msg,
                                         key=f"{pkg['ecosystem']}|{pkg['name']}|{ids[0] if ids else label}",
                                         package=pkg["name"], version=pkg["version"], ecosystem=pkg["ecosystem"],
                                         fixed=fix, kev=exploited or None,
                                         url=f"https://osv.dev/vulnerability/{ids[0]}" if ids else None))
    return out
