// Fuzzes any project through its harness, .bugscan/fuzz/harness.mjs (written by `bugscan` + Claude, or by hand):
//
//   export const seeds = [ /* realistic example inputs: JSON values or strings */ ];
//   export const targets = { name: async (input) => { /* call project code; throw only on real bugs */ } };
//   export const expected = (error) => false;   // optional: errors that are fine (e.g. "invalid input" rejections)
//   export const prepareSeed = (value, name) => value;  // optional: adapt extra seeds (return undefined to drop one)
//
// Extra seeds come from .bugscan/fuzz/seeds/ and inputs recorded by `bugscan sync` ($BUGSCAN_SEEDS):
// .json files are parsed, anything else is passed as a string.
// Usage: node driver.mjs <harness.mjs> <seconds> <work-dir>
// Crashes are grouped by the first stack frame inside the project, saved to <work-dir>, and also to
// .bugscan/fuzz/regressions/ so they replay on every later run. known-crashes.txt there lists accepted ones.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {fuzz, readKnown, report} from './fuzzkit.mjs';

const [harnessPath, seconds = '30', work = 'fuzz-auto-out'] = process.argv.slice(2);
const dir = path.dirname(path.resolve(harnessPath));
const project = path.resolve(dir, '../..');
let h;
try {
  h = await import(pathToFileURL(path.resolve(harnessPath)).href);
} catch (e) {
  console.log(`HARNESS ERROR: could not load ${harnessPath}\n${e.stack}`);
  process.exit(2);
}
if (!Array.isArray(h.seeds) || !h.seeds.length || !h.targets || !Object.keys(h.targets).length) {
  console.log('HARNESS ERROR: harness must export a non-empty `seeds` array and a non-empty `targets` object');
  process.exit(2);
}
const extra = [];
for (const d of (process.env.BUGSCAN_SEEDS || '').split(path.delimiter).filter(Boolean)) {
  if (!fs.existsSync(d)) continue;
  for (const f of fs.readdirSync(d).sort()) {
    const raw = fs.readFileSync(path.join(d, f), 'utf8');
    let v = raw;
    if (f.endsWith('.json')) { try { v = JSON.parse(raw); } catch { continue; } }
    if (typeof h.prepareSeed === 'function') v = h.prepareSeed(v, f);
    if (v !== undefined) extra.push(v);
  }
}
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// A frame in the project's own code (not node_modules, not the harness itself): captures (relative file, line).
const fileRe = new RegExp(`(?:file://)?${esc(project)}/((?!node_modules/|\\.bugscan/)[^:)\\s?]+)(?:\\?[^:)\\s]*)?:(\\d+)`);
const res = await fuzz({
  targets: h.targets, seeds: [...h.seeds, ...extra], seconds, work, fileRe,
  regressions: path.join(dir, 'regressions'),
  expected: typeof h.expected === 'function' ? h.expected : undefined,
});
process.exit(report(`fuzz (${Object.keys(h.targets).join(', ')})`, res, readKnown(path.join(dir, 'known-crashes.txt')), `, ${h.seeds.length + extra.length} seeds`));
