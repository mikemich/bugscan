"""Which tools are installed, what each is for, and how to install the missing ones."""
import shutil
import subprocess
import sys

MAC = sys.platform == "darwin"
# name, purpose, version command, install (macOS, Linux), checks that need it
TOOLS = [
    ("git", "change tracking, quick scans, Claude fixes", ["git", "--version"], ("xcode-select --install", "sudo apt install git"), ["secrets"]),
    ("semgrep", "static analysis", ["semgrep", "--version"], ("brew install semgrep", "pipx install semgrep"), ["sast"]),
    ("gitleaks", "secret scanning", ["gitleaks", "version"], ("brew install gitleaks", "see github.com/gitleaks/gitleaks/releases"), ["secrets"]),
    ("osv-scanner", "dependency vulnerabilities", ["osv-scanner", "--version"], ("brew install osv-scanner", "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"), ["deps"]),
    ("node", "JS lint and JS fuzz harnesses", ["node", "--version"], ("brew install node", "sudo apt install nodejs"), ["lint", "fuzz"]),
    ("swift", "Swift sanitizers and strict concurrency", ["swift", "--version"], ("xcode-select --install", "see swift.org/install"), ["memory"]),
    ("go", "Go race detector and vet", ["go", "version"], ("brew install go", "see go.dev/dl"), ["memory"]),
    ("claude", "explain, fix, write rules and fuzzers", ["claude", "--version"], ("npm install -g @anthropic-ai/claude-code", "npm install -g @anthropic-ai/claude-code"), []),
]
REQUIRED = {"git", "semgrep", "gitleaks", "osv-scanner"}


def check():
    out = []
    for name, purpose, cmd, installs, stages in TOOLS:
        install = installs[0] if MAC else installs[1]
        ok, detail = False, "not installed"
        if shutil.which(cmd[0]):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                ok = r.returncode == 0
                detail = (r.stdout or r.stderr).strip().splitlines()[0][:60] if ok else "installed but not working"
            except (subprocess.TimeoutExpired, IndexError):
                ok, detail = True, "installed"
        first = install.split()[0]
        out.append({"name": name, "purpose": purpose, "ok": ok, "detail": detail, "install": install,
                    "runnable": first in ("brew", "npm", "pipx", "xcode-select", "go") and bool(shutil.which(first)),
                    "stages": stages, "required": name in REQUIRED})
    return out
