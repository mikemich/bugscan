# bugscan

Find bugs in any folder, mostly automatically. Open a folder and press Enter: bugscan works out what the project is, runs the checks that fit, remembers what it found between scans, and lets Claude explain or fix each issue.

- **Secrets:** gitleaks over the whole git history.
- **Static analysis:** Semgrep rule packs picked for your languages, plus built-in and project rules.
- **Vulnerable dependencies:** osv-scanner, ranked by CISA's actively-exploited list, with the version that fixes each one.
- **Syntax lint:** JS, Python, shell, JSON and plist.
- **Fuzzing:** of any JS/TS or Python project. Claude can write the harness for you.
- **Memory & races:** Swift strict concurrency plus Thread/AddressSanitizer test runs, and the Go race detector plus `go vet`.
- **Your own checks:** any command, reporting through SARIF, regex matchers or its exit code.

Pure Python standard library (3.9+), no dependencies. Works on macOS and Linux.

## Install

```bash
pipx install git+https://github.com/mikemich/bugscan
bugscan doctor          # shows which scanners are installed and how to get the missing ones
```

The core checks use [semgrep](https://semgrep.dev), [gitleaks](https://github.com/gitleaks/gitleaks) and [osv-scanner](https://github.com/google/osv-scanner) (`brew install semgrep gitleaks osv-scanner`). Node, Swift and Go are used when the project needs them. The Claude features use [Claude Code](https://claude.com/claude-code).

## Use

```bash
bugscan                 # interactive UI in the current folder
bugscan ~/code/app      # … in another folder
bugscan scan            # command line / CI
```

### Interactive UI

| Key | Action |
|---|---|
| `enter` | scan with the ticked checks (ticked automatically for the folder) |
| `tab` · `1` `2` `3` | **Quick** (changed files only, seconds) · **Standard** (everything, 1 min fuzzing) · **Deep** (30 min fuzzing) |
| `f` | findings: `tab` New / Open / All · `v` minimum severity · `/` search |
| `e` | Claude explains the finding: a verdict (real issue or false positive), what's wrong, why it matters, how to fix it |
| `x` | Claude fixes it. You see the diff, `y` keeps it and the check re-runs to verify, `n` undoes it |
| `r` | after a fix: Claude writes a Semgrep rule for that bug pattern into `.bugscan/rules.yml`, used on every later scan |
| `g` | Claude writes a fuzz harness for the project |
| `i` · `o` | ignore a finding · open the file at that line (`$VISUAL`/`$EDITOR`, VS Code, Cursor, Zed, Xcode) |
| `s` · `o` | Claude summary of the scan · HTML report (health score, trend, every finding) |
| `w` · `h` | watch mode (quick rescan on every save) · git pre-commit hook |
| `t` · `u` · `d` | choose a folder · update rules and vulnerability data · tools |

### How findings are tracked

Every finding gets a fingerprint that survives line shifts, so between scans it's **new**, **open**, **fixed**, **came back** or **ignored**. Only new and came-back issues fail `bugscan scan` and the git hook, so existing issues never block you. Health (0–100, graded A–F) is computed from the open findings, weighted by severity.

Fuzzer crashes are saved to `.bugscan/fuzz/regressions/` and replayed first on every later run, so a fixed bug stays fixed. Commit that folder.

## Claude

Claude features run through your local Claude Code (`claude -p`), so they use your existing login. Code is only sent when you press a key, and each action gets only the tools it needs:
- **Explain and summary:** read-only.
- **Fix:** may edit files. A git snapshot is taken first so every change can be undone, including new files, without touching your own uncommitted work.
- **Harness:** may run `node`/`python3` to test itself.

## Command line

```bash
bugscan scan [-t DIR] [--level quick|standard|deep] [--stages sast,deps] [--fuzz SECS]
             [--fail-on new|any|none] [--min-severity high] [--sarif out.sarif] [--json out.json] [--out DIR]
bugscan findings [--all] [--json]       bugscan show|explain|fix|ignore ID
bugscan sync | report [--open] | doctor | init | hook install|uninstall
```

`scan` exits 1 when findings at or above `--min-severity` fail the run (new ones by default), or when a check couldn't run. Otherwise it exits 0.

### GitHub Actions

```yaml
- run: brew install semgrep gitleaks osv-scanner        # or pipx/apt on Linux
- run: pipx install git+https://github.com/mikemich/bugscan
- run: bugscan scan --sarif bugscan.sarif --min-severity high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: {sarif_file: bugscan.sarif}
```

## Configuration

Everything is optional. `bugscan init` writes a commented `.bugscan/config.toml`:

```toml
[scan]
level = "standard"            # default level
exclude = ["vendor", "docs"]  # skipped by every check
fail_on = "new"               # new | any | none
min_severity = "medium"
fuzz_seconds = 60

[[check]]                     # your own checks
name = "unit-tests"
run = "npm test"
levels = ["standard", "deep"]
requires = ["npm"]            # skipped if missing
severity = "medium"
matchers = [{ regex = '^(?P<file>\S+):(?P<line>\d+): (?P<message>.*)$' }]

[[seed]]                      # real inputs, downloaded by `bugscan sync` as extra fuzz seeds
name = "sample"
url = "https://api.example.com/sample.json"
```

A custom check reports findings in one of three ways:
- **SARIF:** writes a SARIF file to `$BUGSCAN_SARIF`. Most analyzers can.
- **Regex matchers:** named groups `message` (required), plus `file`, `line`, `severity` and `rule`.
- **Exit code:** if it does neither, a non-zero exit becomes one finding.

Exit code **77** means "can't run here" and skips the check. The command also gets `$BUGSCAN_TARGET`, `$BUGSCAN_OUT`, `$BUGSCAN_LEVEL`, `$BUGSCAN_FUZZ_SECONDS`, `$BUGSCAN_SEEDS` and, at the quick level, `$BUGSCAN_CHANGED` (a file listing the changed paths).

### Fuzz harnesses

`.bugscan/fuzz/harness.mjs` (or `harness.py`) tells the fuzzer what to call. Press `g` and Claude writes one, or write it yourself:

```js
import {parseOrder} from '../../src/orders.js';
export const seeds = [{id: 1, items: [{sku: 'A', qty: 2}]}];          // realistic inputs
export const targets = {parseOrder: input => { parseOrder(input); }};  // throw only on real bugs
export const expected = e => e instanceof ValidationError;             // optional: fine errors
export const prepareSeed = (value, name) => value;                     // optional: adapt recorded seeds
```

```python
from shop.coupons import parse
SEEDS = ["SAVE20-2026-12-31", "FREESHIP"]
TARGETS = {"parse": lambda s: parse(s) if isinstance(s, str) else None}
def expected(e): return isinstance(e, ValueError)
```

How the fuzzer works:
- **Inputs:** it mutates the seeds structurally (deleting keys, odd types, extreme numbers, broken strings, injection payloads) and calls every target.
- **Grouping:** crashes are grouped by the first stack frame in your code.
- **Accepting a crash:** list its signature in `.bugscan/fuzz/known-crashes.txt`.
- **Extra seeds:** anything in `.bugscan/fuzz/seeds/` is used too.

## Where things live

| Path | What |
|---|---|
| `<project>/.bugscan/` | yours to commit: `config.toml`, `rules.yml`, `fuzz/harness.*`, `fuzz/regressions/`, `fuzz/known-crashes.txt` |
| `~/.cache/bugscan/projects/<name>-<hash>/` | results per project: `findings.db`, per-check logs, `report.html`. bugscan never writes into a project outside `.bugscan/` |
| `~/.cache/bugscan/` | cached Semgrep packs, the CISA KEV list, a fuzzing dictionary |

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
python3 -m unittest discover -s tests -t .        # the whole suite (~2 min)
BUGSCAN_TEST_FAST=1 BUGSCAN_TEST_OFFLINE=1 python3 -m unittest discover -s tests -t .   # no Swift/Go builds, no network
```

How the tests work:
- **Real tools:** they drive the real scanners (each test skips if its tool is missing).
- **Claude:** they use a fake `claude` executable via `BUGSCAN_CLAUDE`, so no tokens are spent.
- **UI:** they drive the curses UI through a pseudo-terminal.
- **Fixtures:** `tests/fixtures/` holds captured tool outputs and small Go/Swift projects with planted races.

## License

MIT
