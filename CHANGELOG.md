# Changelog

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
