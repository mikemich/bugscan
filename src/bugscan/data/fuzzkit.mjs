// Shared structure-aware fuzzing loop for JS targets: pipeline/fuzz-js (this repo) and
// pipeline/fuzz-auto/driver.mjs (any project's .bugscan/fuzz/harness.mjs).
// Every crash is written to <work>/crash-N.json and, if a regressions dir is given, saved there too,
// so it is replayed on every later run until the bug is fixed.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const XSS_MARK = '<img src=x onerror=FUZZXSS>';
const INTERESTING = [0, -1, 1, 1e308, -1e308, 2 ** 31 - 1, -(2 ** 53), 0.0001, null, '', 'x', XSS_MARK, [], {}, true, false,
  'Not/AZone', '\u0000', '%s%n%x', '../../etc/passwd', '{"a":', 'A'.repeat(5000), '‮😀', '0x1F', '1e999'];
const CHARS = '\n\r\t |:;,{}[]"\'\\/<>0123456789-+.eE';

export function rng(seed) {
  let s = BigInt(seed ?? Date.now()) & 0xffffffffn;
  const rand = () => { s = (s * 1103515245n + 12345n) & 0x7fffffffn; return Number(s) / 0x7fffffff; };
  const ri = n => Math.floor(rand() * n);
  return {rand, ri, pick: a => a[ri(a.length)]};
}

export function mutator(r, extra = []) {
  const interesting = [...INTERESTING, ...extra];
  const str = v => {
    if (!v.length || r.ri(6) === 0) return String(r.pick(interesting));
    const i = r.ri(v.length), j = Math.min(v.length, i + 1 + r.ri(32));
    switch (r.ri(6)) {
      case 0: return v.slice(0, i) + r.pick(CHARS) + v.slice(i);
      case 1: return v.slice(0, i) + v.slice(j);
      case 2: return v.slice(0, j) + v.slice(i, j) + v.slice(j);
      case 3: return v.slice(0, i) + r.pick(CHARS) + v.slice(i + 1);
      case 4: return v.slice(0, i);
      default: return v.slice(0, i) + String(r.pick(interesting)) + v.slice(i);
    }
  };
  const mutate = v => {
    if (Array.isArray(v) && v.length) {
      const a = [...v];
      switch (r.ri(7)) {
        case 0: a.length = r.ri(a.length); break;
        case 1: for (let n = r.ri(40) + 1; n--;) a.push(r.pick(a)); break;
        case 2: a.sort(() => r.rand() - 0.5); break;
        case 3: a[r.ri(a.length)] = r.pick(interesting); break;
        default: { const i = r.ri(a.length); a[i] = mutate(a[i]); }
      }
      return a;
    }
    if (v && typeof v === 'object' && Object.keys(v).length) {
      const o = {...v}, k = r.pick(Object.keys(o));
      switch (r.ri(7)) {
        case 0: delete o[k]; break;
        case 1: o[k] = r.pick(interesting); break;
        case 2: o[String(r.pick(interesting))] = r.pick(interesting); break;
        default: o[k] = mutate(o[k]);
      }
      return o;
    }
    if (typeof v === 'number') return r.pick([v + (r.rand() - 0.5) * 1e4, -v, v * 1e6, Math.trunc(v), r.pick(interesting)]);
    if (typeof v === 'string') return str(v);
    return r.pick(interesting);
  };
  return mutate;
}

const hash = v => crypto.createHash('sha256').update(JSON.stringify(v) ?? 'undefined').digest('hex').slice(0, 12);

/** Run targets on seeds + mutations until `seconds` pass. fileRe must capture (file, line) of a project frame. */
export async function fuzz({targets, seeds, seconds, work, regressions, fileRe, seed, extra, expected = () => false}) {
  fs.mkdirSync(work, {recursive: true});
  const r = rng(seed), mutate = mutator(r, extra);
  const crashes = new Map();
  let runs = 0, regressionFailures = 0;

  const record = (name, input, e, fromRegression) => {
    const at = (e?.stack || '').match(fileRe);
    const where = at ? `${at[1]}:${at[2]}` : String(e?.message ?? e).replace(/-?\b\d[\d.e+]*|-?Infinity|NaN/g, 'N').slice(0, 80);
    const sig = `${name} | ${e?.constructor?.name ?? 'Error'} @ ${where}`;
    if (fromRegression) regressionFailures++;
    if (crashes.has(sig)) return;
    const crash = {target: name, signature: sig, message: String(e?.message ?? e), file: at?.[1] ?? null, line: at ? +at[2] : null, input};
    const file = path.join(work, `crash-${crashes.size}.json`);
    fs.writeFileSync(file, JSON.stringify(crash, null, 1));
    crashes.set(sig, {...crash, repro: file, regression: fromRegression});
    if (regressions && !fromRegression) {
      fs.mkdirSync(regressions, {recursive: true});
      fs.writeFileSync(path.join(regressions, `${hash(input)}.json`), JSON.stringify({target: name, signature: sig, input}, null, 1));
    }
  };
  const runOne = async (name, input, fromRegression = false) => {
    runs++;
    try { await targets[name](structuredClone(input)); } catch (e) { if (!expected(e)) record(name, input, e, fromRegression); }
  };

  // 1. Every crash ever found is replayed first.
  const saved = regressions && fs.existsSync(regressions) ? fs.readdirSync(regressions).filter(f => f.endsWith('.json')) : [];
  for (const f of saved) {
    const {target, input} = JSON.parse(fs.readFileSync(path.join(regressions, f), 'utf8'));
    if (targets[target]) await runOne(target, input, true);
  }
  // 2. Seeds as-is, then 3. mutations until the deadline.
  for (const s of seeds) for (const name of Object.keys(targets)) await runOne(name, s);
  const deadline = Date.now() + Number(seconds) * 1e3;
  while (Date.now() < deadline) {
    let input = r.pick(seeds);
    for (let n = r.ri(4) + 1; n--;) input = mutate(input);
    for (const name of Object.keys(targets)) await runOne(name, input);
  }
  return {runs, crashes, regressions: saved.length, regressionFailures};
}

/** Print the outcome; returns the exit code (1 if any crash isn't in `known`). */
export function report(label, res, known, extraStat = '') {
  const fresh = [...res.crashes].filter(([sig]) => !known.has(sig));
  const reg = res.regressions ? `, ${res.regressions} saved crash inputs replayed (${res.regressionFailures} still crash)` : '';
  console.log(`${label}: ${res.runs} runs${extraStat}${reg}, ${res.crashes.size} unique crash signatures (${fresh.length} new)`);
  for (const [sig, c] of res.crashes)
    console.log(`  ${known.has(sig) ? 'known' : 'NEW  '}  ${sig}  — ${c.message.slice(0, 70)}\n         repro: ${c.repro}`);
  return fresh.length ? 1 : 0;
}

export function readKnown(file) {
  return new Set(fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#')) : []);
}

/** Shift every `time` array so recorded API responses look current. */
export function rebaseTimes(obj, now = Math.floor(Date.now() / 1e3 / 900) * 900) {
  const first = obj?.minutely_15?.time?.[0] ?? obj?.hourly?.time?.[0];
  if (typeof first !== 'number') return obj;
  const delta = Math.round((now - first) / 900) * 900;
  const walk = o => {
    if (Array.isArray(o)) return o.map(walk);
    if (o && typeof o === 'object')
      return Object.fromEntries(Object.entries(o).map(([k, v]) => [k, k === 'time' && Array.isArray(v) ? v.map(t => typeof t === 'number' ? t + delta : t) : walk(v)]));
    return o;
  };
  return walk(obj);
}
