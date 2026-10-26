"""Look at a folder and work out what it is: languages, lockfiles, build systems, git, fuzz harness."""
import os
from collections import Counter

from . import paths

SKIP_DIRS = {"node_modules", ".git", "Pods", "DerivedData", ".venv", "venv", "__pycache__", "dist", "build",
             ".next", "target", "vendor", ".gradle", ".idea", ".swiftpm", "Carthage", ".bugscan", ".tox",
             ".mypy_cache", ".pytest_cache", "coverage", ".terraform"}
LANG_EXT = {
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".py": "Python", ".swift": "Swift", ".go": "Go",
    ".rs": "Rust", ".java": "Java", ".kt": "Kotlin", ".rb": "Ruby", ".php": "PHP", ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".cs": "C#", ".m": "Objective-C", ".sh": "Shell",
}
# Semgrep registry packs per language (packs missing from the registry are skipped at sync time).
PACKS = {"JavaScript": ["p/javascript"], "TypeScript": ["p/typescript"], "Python": ["p/python"],
         "Swift": ["p/swift"], "Go": ["p/golang"], "Java": ["p/java"], "Kotlin": ["p/kotlin"],
         "Ruby": ["p/ruby"], "PHP": ["p/php"], "C": ["p/c"], "C++": ["p/c"], "C#": ["p/csharp"], "Rust": ["p/rust"]}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "poetry.lock", "uv.lock",
             "go.mod", "Cargo.lock", "Gemfile.lock", "composer.lock", "Package.resolved", "Podfile.lock",
             "pom.xml", "gradle.lockfile", "mix.lock", "pubspec.lock", "packages.lock.json"}


def walk(target, limit=20000, exclude=()):
    """Yield file paths relative to `target`, skipping dependency/build folders and `exclude` paths."""
    target = os.path.realpath(target)
    excl = {os.path.join(target, e) for e in exclude}
    n = 0
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".build")
                             and not d.endswith((".xcassets", ".xcodeproj", ".xcworkspace"))
                             and os.path.join(dirpath, d) not in excl)
        for f in sorted(filenames):
            yield os.path.relpath(os.path.join(dirpath, f), target)
            n += 1
            if n >= limit:
                return


def skipped(rel, exclude=()):
    """True if a relative path lies in a folder `walk` would skip."""
    parts = rel.split("/")
    return any(p in SKIP_DIRS or p.startswith(".build") for p in parts[:-1]) or \
        any(rel == e or rel.startswith(e + "/") for e in exclude)


def detect(target, exclude=()):
    target = os.path.realpath(target)
    langs, lockfiles, files, html = Counter(), [], 0, False
    for rel in walk(target, exclude=exclude):
        files += 1
        name = os.path.basename(rel)
        ext = os.path.splitext(name)[1].lower()
        if ext in LANG_EXT:
            langs[LANG_EXT[ext]] += 1
        html |= ext in (".html", ".htm", ".vue", ".svelte")
        if name in LOCKFILES or (name.startswith("requirements") and name.endswith(".txt")):
            lockfiles.append(rel)
    try:
        top = set(os.listdir(target))
    except OSError:
        top = set()
    fuzzdir = os.path.join(paths.project_dir(target), "fuzz")
    harness = next((os.path.join(fuzzdir, h) for h in ("harness.mjs", "harness.py") if os.path.exists(os.path.join(fuzzdir, h))), None)
    info = {
        "target": target,
        "languages": [l for l, _ in langs.most_common() if l != "Shell" or len(langs) == 1],
        "lang_counts": dict(langs),
        "lockfiles": lockfiles,
        "files": files,
        "git": os.path.isdir(os.path.join(target, ".git")),
        "swiftpm": "Package.swift" in top,
        "go": "go.mod" in top,
        "cargo": "Cargo.toml" in top,
        "xcode": any(t.endswith((".xcodeproj", ".xcworkspace")) for t in top),
        "workflows": os.path.isdir(os.path.join(target, ".github", "workflows")),
        "docker": any(t.startswith("Dockerfile") for t in top),
        "html": html,
        "harness": harness,
        "rules": os.path.exists(os.path.join(paths.project_dir(target), "rules.yml")),
        "config": os.path.exists(os.path.join(paths.project_dir(target), "config.toml")),
    }
    info["packs"] = packs_for(info)
    return info


def packs_for(info, deep=False):
    packs = []
    for lang in info["languages"]:
        packs += [p for p in PACKS.get(lang, []) if p not in packs]
    if not packs:
        packs.append("p/default")
    packs.append("p/secrets")
    if info["workflows"]:
        packs.append("p/github-actions")
    if info["docker"]:
        packs.append("p/dockerfile")
    if info["html"] and {"JavaScript", "TypeScript"} & set(info["languages"]):
        packs.append("p/xss")
    if deep:
        packs.append("p/owasp-top-ten")
    return packs


def describe(info):
    """One-line summary, e.g. 'TypeScript, Python · 2 lockfiles · git · fuzz harness'."""
    bits = [", ".join(info["languages"][:3]) or "no source files found"]
    if info["lockfiles"]:
        bits.append(f"{len(info['lockfiles'])} lockfile{'s' * (len(info['lockfiles']) != 1)}")
    for flag, label in (("swiftpm", "SwiftPM"), ("go", "Go module"), ("cargo", "Cargo")):
        if info[flag]:
            bits.append(label)
    if info["git"]:
        bits.append("git")
    if info["harness"]:
        bits.append("fuzz harness")
    return " · ".join(bits)
