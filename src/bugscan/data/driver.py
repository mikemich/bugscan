"""Fuzzes any Python project through its harness, .bugscan/fuzz/harness.py:

    SEEDS = [...]                       # realistic example inputs: JSON-like values or strings
    TARGETS = {"name": func}            # func(input) calls project code; raise only on real bugs
    def expected(error): return False   # optional: exceptions that are fine (e.g. ValueError on bad input)
    def prepare_seed(value, name): return value   # optional: adapt extra seeds (return None to drop one)

Extra seeds come from .bugscan/fuzz/seeds/ and inputs recorded by `bugscan sync` ($BUGSCAN_SEEDS):
.json files are parsed, anything else is passed as a string.

Usage: python3 driver.py <harness.py> <seconds> <work-dir>
Crashes are grouped by the deepest traceback frame inside the project, saved to <work-dir> and to
.bugscan/fuzz/regressions/ (replayed on every later run). known-crashes.txt there lists accepted ones.
"""
import copy, hashlib, importlib.util, json, os, random, sys, time, traceback

INTERESTING = [0, -1, 1, 1e308, -1e308, 2**31 - 1, -(2**53), 0.0001, None, "", "x", "<img src=x onerror=FUZZXSS>", [], {},
               True, False, "\x00", "%s%n%x", "../../etc/passwd", '{"a":', "A" * 5000, "‮😀", "0x1F", "1e999"]
CHARS = "\n\r\t |:;,{}[]\"'\\/<>0123456789-+.eE"


def mutate_str(r, v):
    if not v or r.randrange(6) == 0:
        return str(r.choice(INTERESTING))
    i = r.randrange(len(v)); j = min(len(v), i + 1 + r.randrange(32))
    return r.choice([v[:i] + r.choice(CHARS) + v[i:], v[:i] + v[j:], v[:j] + v[i:j] + v[j:],
                     v[:i] + r.choice(CHARS) + v[i + 1:], v[:i], v[:i] + str(r.choice(INTERESTING)) + v[i:]])


def mutate(r, v):
    if isinstance(v, list) and v:
        a = list(v); op = r.randrange(7)
        if op == 0: del a[r.randrange(len(a)):]
        elif op == 1: a += [r.choice(a) for _ in range(r.randrange(1, 40))]
        elif op == 2: r.shuffle(a)
        elif op == 3: a[r.randrange(len(a))] = copy.deepcopy(r.choice(INTERESTING))
        else: i = r.randrange(len(a)); a[i] = mutate(r, a[i])
        return a
    if isinstance(v, dict) and v:
        o = dict(v); k = r.choice(list(o)); op = r.randrange(7)
        if op == 0: del o[k]
        elif op == 1: o[k] = copy.deepcopy(r.choice(INTERESTING))
        elif op == 2: o[str(r.choice(INTERESTING))] = copy.deepcopy(r.choice(INTERESTING))
        else: o[k] = mutate(r, o[k])
        return o
    if isinstance(v, bool) or v is None:
        return copy.deepcopy(r.choice(INTERESTING))
    if isinstance(v, (int, float)):
        return r.choice([v + r.uniform(-5000, 5000), -v, v * 10**6, int(v) if abs(v) < 1e300 else 0, copy.deepcopy(r.choice(INTERESTING))])
    if isinstance(v, str):
        return mutate_str(r, v)
    return copy.deepcopy(r.choice(INTERESTING))


def main(harness_path, seconds="30", work="fuzz-auto-out"):
    hdir = os.path.dirname(os.path.abspath(harness_path)); project = os.path.dirname(os.path.dirname(hdir))
    sys.path.insert(0, project)
    try:
        spec = importlib.util.spec_from_file_location("bugscan_harness", harness_path)
        h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
        seeds, targets = list(h.SEEDS), dict(h.TARGETS)
        assert seeds and targets
    except Exception:
        print(f"HARNESS ERROR: could not load {harness_path}\n{traceback.format_exc()}")
        return 2
    expected = getattr(h, "expected", lambda e: False)
    prepare = getattr(h, "prepare_seed", lambda v, name: v)
    for d in filter(None, os.environ.get("BUGSCAN_SEEDS", "").split(os.pathsep)):
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                raw = open(os.path.join(d, f), errors="replace").read()
                try:
                    v = json.loads(raw) if f.endswith(".json") else raw
                except ValueError:
                    continue
                v = prepare(v, f)
                if v is not None:
                    seeds.append(v)
    known = set()
    kf = os.path.join(hdir, "known-crashes.txt")
    if os.path.exists(kf):
        known = {l.strip() for l in open(kf) if l.strip() and not l.startswith("#")}
    regdir = os.path.join(hdir, "regressions")
    os.makedirs(work, exist_ok=True)
    crashes, stats = {}, {"runs": 0, "regfail": 0}
    r = random.Random(int(time.time()))

    def where(exc):
        frames = [f for f in traceback.extract_tb(exc.__traceback__)
                  if f.filename.startswith(project + os.sep) and "/.bugscan/" not in f.filename and "site-packages" not in f.filename]
        return (os.path.relpath(frames[-1].filename, project), frames[-1].lineno) if frames else (None, None)

    def run_one(name, inp, from_reg=False):
        stats["runs"] += 1
        try:
            targets[name](copy.deepcopy(inp))
        except Exception as e:
            if expected(e):
                return
            f, line = where(e)
            sig = f"{name} | {type(e).__name__} @ {f}:{line}" if f else f"{name} | {type(e).__name__} @ {str(e)[:80]}"
            stats["regfail"] += from_reg
            if sig in crashes:
                return
            crash = {"target": name, "signature": sig, "message": f"{type(e).__name__}: {e}"[:500], "file": f, "line": line, "input": inp}
            path = os.path.join(work, f"crash-{len(crashes)}.json")
            json.dump(crash, open(path, "w"), indent=1, default=repr)
            crashes[sig] = dict(crash, repro=path)
            if not from_reg:
                os.makedirs(regdir, exist_ok=True)
                key = hashlib.sha256(json.dumps(inp, default=repr).encode()).hexdigest()[:12]
                json.dump({"target": name, "signature": sig, "input": inp}, open(os.path.join(regdir, f"{key}.json"), "w"), indent=1, default=repr)

    saved = sorted(f for f in os.listdir(regdir) if f.endswith(".json")) if os.path.isdir(regdir) else []
    for f in saved:
        d = json.load(open(os.path.join(regdir, f)))
        if d["target"] in targets:
            run_one(d["target"], d["input"], True)
    for s in seeds:
        for name in targets:
            run_one(name, s)
    deadline = time.time() + float(seconds)
    while time.time() < deadline:
        inp = r.choice(seeds)
        for _ in range(r.randrange(1, 5)):
            inp = mutate(r, inp)
        for name in targets:
            run_one(name, inp)
    fresh = [s for s in crashes if s not in known]
    reg = f", {len(saved)} saved crash inputs replayed ({stats['regfail']} still crash)" if saved else ""
    print(f"fuzz ({', '.join(targets)}): {stats['runs']} runs, {len(seeds)} seeds{reg}, {len(crashes)} unique crash signatures ({len(fresh)} new)")
    for sig, c in crashes.items():
        print(f"  {'known' if sig in known else 'NEW  '}  {sig}  — {c['message'][:70]}\n         repro: {c['repro']}")
    return 1 if fresh else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
