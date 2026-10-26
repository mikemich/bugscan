# Changelog

## 0.2.0

Less noise:
- Respects .gitignore everywhere (git's own file list) and includes nested repositories.
- One finding per vulnerable package and manifest: "upgrade torch to 2.13.0 fixes 19 vulnerabilities",
  with every advisory listed in the details. Dev-only packages rank one level lower (unless actively exploited).
- Clean Semgrep rule ids for cached registry packs; no "fuzzing" label when nothing will fuzz.

Fixing faster:
- `x` on a vulnerable dependency upgrades it without Claude (npm, or the pin in requirements.txt), then
  re-checks dependencies and runs your tests. `C` asks Claude instead.
- Triage: Claude labels every open finding real / likely false positive / unsure (`T` in the UI, `bugscan triage`);
  `I` ignores everything it flagged.

More bugs found:
- New check "Your tests": runs npm test, pytest and cargo test; failing tests become findings.
- New check "Types & linters": tsc --noEmit, ruff, cargo clippy.

Faster:
- Secrets, static analysis, lint and dependencies run in parallel.
- Tagging a release publishes it and bumps the Homebrew formula automatically.

Also:
- `scan.skip` in the config turns off built-in checks; Python projects without pytest run their tests with unittest.
- Fixed on Linux: XCTest failures from swift-corelibs-xctest are recognized.
- Dependency results no longer depend on osv-scanner grouping advisories, and work with osv-scanner 2.5 (older exclude flag).

## 0.1.0

First standalone release (extracted from the RegenRadar repo's bug pipeline).

- Checks: secrets (gitleaks), static analysis (Semgrep: per-language packs, built-in and project rules),
  syntax lint, vulnerable dependencies (osv-scanner + CISA KEV), fuzzing of JS/TS and Python projects,
  memory & races (Swift sanitizers and strict concurrency, Go race detector and vet), custom checks
  (SARIF, regex matchers, exit codes, exit 77 = skip).
- Quick / Standard / Deep levels; quick scans only changed files.
- Findings database: new / open / fixed / came back / ignored; only new issues fail; health score.
- Claude (through Claude Code): explain, fix with review + verification, rules from fixes, fuzz harnesses, summaries.
- Interactive curses UI, CLI with SARIF/JSON output, HTML report, git pre-commit hook, watch mode, `bugscan sync`.
