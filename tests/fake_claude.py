"""Stand-in for the `claude` CLI in tests. Behaviour comes from $FAKE_CLAUDE (JSON):
  explain:  text to print for explain prompts
  fix:      {"file": rel, "old": text, "new": text} edit to make for fix prompts (omit to change nothing)
  rule:     YAML to print for rule prompts
  harness:  {"path": rel, "content": text} file to write for harness prompts
  summary:  text to print for summary prompts
  stderr:   text to print to stderr (must be captured, never leak onto the UI)
Every call is appended to the `log` file as JSON (argv + which kind of prompt it was)."""
import json
import os
import sys

conf = json.loads(os.environ.get("FAKE_CLAUDE", "{}"))
args = sys.argv[1:]
if "--version" in args:
    print("0.0.0 (Fake Claude)")
    sys.exit(0)
prompt = args[args.index("-p") + 1] if "-p" in args else ""
tools = args[args.index("--allowedTools") + 1] if "--allowedTools" in args else ""
mode = args[args.index("--permission-mode") + 1] if "--permission-mode" in args else None
kind = ("harness" if "Write a fuzz harness" in prompt else "rule" if "Semgrep rule" in prompt else
        "fix" if "Fix it with the smallest" in prompt else "summary" if "Write a short report" in prompt else "explain")
with open(conf["log"], "a") as fh:
    fh.write(json.dumps({"kind": kind, "tools": tools, "mode": mode, "cwd": os.getcwd(), "prompt": prompt[:4000]}) + "\n")

if conf.get("stderr"):
    print(conf["stderr"], file=sys.stderr)
if kind == "fix" and conf.get("fix"):
    f = conf["fix"]
    with open(f["file"]) as fh:
        text = fh.read()
    with open(f["file"], "w") as fh:
        fh.write(text.replace(f["old"], f["new"]))
    print("Fixed the bug by guarding the input.")
elif kind == "fix":
    print("This is a false positive; no change made.")
elif kind == "harness" and conf.get("harness"):
    h = conf["harness"]
    os.makedirs(os.path.dirname(h["path"]), exist_ok=True)
    with open(h["path"], "w") as fh:
        fh.write(h["content"])
    print("Chose `parse` because it handles untrusted input.")
else:
    print(conf.get(kind, f"Verdict: Real issue - fake {kind}."))
