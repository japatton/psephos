import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';

/*
  Nothing in this repository may name a real network.

  The engagement's terrain, plan, roster and threads live in a gitignored
  mission profile, but that only covers whole files. An address pasted into a
  test fixture, a hostname left in a comment, or a worked example in a plan
  generator all leak the same way — and this repository is pushed.

  Expressed as ranges and suffixes rather than as a list of one engagement's
  values, so the guard keeps working for whoever uses this next and names
  nothing itself.
*/

const tracked = () => execSync('git ls-files', { encoding: 'utf8' })
  .trim().split('\n').filter(Boolean);

/*
  Text only, and binary returns null rather than mojibake.

  Reading a PNG as UTF-8 does not throw — it yields a few hundred kilobytes of
  replacement characters, which the address pattern below then scans. That is
  worse than not scanning it: it cannot find anything real, and it can match
  four numbers that happen to fall next to each other in compressed pixel data,
  so the guard would fail at random on a file it never had any ability to
  check. The binaries are covered by the allowlist test instead.
*/
const readable = (f) => {
  let buf;
  try { buf = readFileSync(f); } catch { return null; }
  if (buf.subarray(0, 4096).includes(0)) return null;
  return buf.toString('utf8');
};

/** Ranges reserved for private use, examples, or the wire itself. */
const forExamples = (a, b, c) =>
  a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)   // RFC 1918
  || (a === 192 && b === 0 && c === 2)                                        // RFC 5737
  || (a === 198 && b === 51 && c === 100)
  || (a === 203 && b === 0 && c === 113)
  || a === 0 || a === 127 || a === 255                                        // unspecified, loopback
  || (a === 169 && b === 254)                                                 // link-local
  || a >= 224                                                                 // multicast and above
  || (a === 100 && b >= 64 && b <= 127);                                      // CGNAT

test('no tracked file names a routable address', () => {
  const found = [];
  for (const f of tracked()) {
    const body = readable(f);
    if (body === null) continue;
    for (const m of body.matchAll(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g)) {
      const [a, b, c, d] = m.slice(1).map(Number);
      if ([a, b, c, d].some(o => o > 255)) continue;   // a version string, not an address
      if (forExamples(a, b, c)) continue;
      found.push(`${a}.${b}.${c}.${d} in ${f}`);
    }
  }
  assert.deepEqual([...new Set(found)], [],
    'use 192.0.2.x, 198.51.100.x or 203.0.113.x for examples');
});

test('no tracked file names a government or military domain', () => {
  // Assembled from fragments so this file does not match itself.
  const suffixes = ['m' + 'il', 'g' + 'ov'];
  const re = new RegExp(`\\b[a-z0-9][a-z0-9-]*\\.(${suffixes.join('|')})\\b`, 'i');
  const hits = [];
  for (const f of tracked()) {
    const body = readable(f);
    if (body !== null && re.test(body)) hits.push(f);
  }
  assert.deepEqual(hits, []);
});

/**
 * Everyone named in a mission profile on this machine, minus the example one.
 *
 * Read at runtime rather than listed here, so this file names nobody and keeps
 * working for whoever uses the repository next. The example profile is
 * deliberately excluded: its people are fixtures, they are meant to be in the
 * tree, and half the test suite files things as Okafor.
 */
function rosterNames() {
  const names = new Set();
  let profiles = [];
  try {
    profiles = readdirSync('missions', { withFileTypes: true })
      .filter(d => d.isDirectory() && d.name !== 'example')
      .map(d => d.name);
  } catch { /* no profiles on this clone */ }

  for (const p of profiles) {
    const body = readable(join('missions', p, 'roster.json'));
    if (!body) continue;
    let parsed;
    try { parsed = JSON.parse(body); } catch { continue; }
    for (const m of parsed.members ?? []) {
      const n = String(m?.name ?? '').trim();
      // Two characters would match half the English language.
      if (n.length >= 3) names.add(n);
    }
  }
  return names;
}

/*
  The addresses and domains above are the leak everyone expects. The one that
  actually happened twice was a person: a teammate's surname used as an
  analyst in a test fixture, and two more as BITS job owners. An address is
  obviously engagement data and a surname reads like a placeholder, which is
  exactly why it slips through.

  Case-sensitive, because the roster is surnames and this codebase always
  writes an actor capitalised. Lowercasing would flag "a fuller explanation".
*/
/**
 * Where a surname counts as named.
 *
 * Returns null for anything that is not plainly a name, so nothing has to be
 * escaped into the pattern.
 */
function nameMatcher(name) {
  if (!/^[A-Za-z][A-Za-z'-]*$/.test(name)) return null;
  return new RegExp(`(?<![A-Za-z])${name}(?![A-Za-z])`);
}

/*
  A guard nobody has watched fail is not a guard. These two cases are what
  decide whether the one below is worth having.
*/
test('the roster matcher catches a name inside a generated label', () => {
  const m = nameMatcher('Okafor');
  assert.ok(m.test('Processes_Baseline_Okafor_20260826083024'), 'an underscore is not a boundary');
  assert.ok(m.test("createdBy: 'Okafor'"));
  assert.equal(m.test('Okaforsson wrote this'), false, 'a longer word is not the name');
  assert.equal(m.test('okafor'), false, 'case-sensitive by design');
  assert.equal(nameMatcher('..'), null);
});

test('no tracked file names anyone on the roster', (t) => {
  const names = [...rosterNames()];
  /*
    Skipped, not passed. CI clones have no mission profile, so there is nobody
    to look for — and a green tick saying the roster is absent from the tree
    would be claiming something this run did not check.
  */
  if (!names.length) { t.skip('no mission profile on this machine'); return; }

  const bodies = tracked()
    .map(f => [f, readable(f)])
    .filter(([, b]) => b !== null);

  const hits = [];
  for (const name of names) {
    const re = nameMatcher(name);
    if (!re) continue;
    for (const [f, body] of bodies) if (re.test(body)) hits.push(`${name} in ${f}`);
  }
  assert.deepEqual(hits, [],
    'use the example roster or an invented name; the team is engagement data');
});

/**
 * What the engagement is called.
 *
 * Read from the profiles on this machine at runtime, exactly like the roster
 * above and for the same reason: this file names no exercise, so it keeps
 * working for whoever uses the repository next and leaks nothing itself.
 *
 * The example profile is excluded — it is a fixture and is meant to be here.
 */
function missionTokens() {
  const found = new Set();
  let dirs = [];
  try {
    dirs = readdirSync('missions', { withFileTypes: true })
      .filter(d => d.isDirectory() && d.name !== 'example')
      .map(d => d.name);
  } catch { /* no profiles on this clone */ }

  for (const d of dirs) {
    found.add(d);                       // the directory name is the code
    const body = readable(join('missions', d, 'mission.json'));
    if (!body) continue;
    let meta;
    try { meta = JSON.parse(body); } catch { continue; }
    for (const v of [meta.code, meta.name]) {
      const s = String(v ?? '').trim();
      if (s.length >= 4) found.add(s);
    }
    /*
      Adjacent word pairs from the name as well as the whole thing. An exercise
      gets shortened in prose long before anybody spells it out, and the short
      form is just as identifying.
    */
    const words = String(meta.name ?? '').split(/[^A-Za-z]+/).filter(w => w.length >= 3);
    for (let i = 0; i + 1 < words.length; i++) found.add(`${words[i]} ${words[i + 1]}`);
  }
  return found;
}

/**
 * Match an identifier however it happens to be punctuated.
 *
 * `XKC 41 9`, `xkc_41_9` and `xkc-41-9` are one leak wearing three hats: the
 * alphanumeric runs carry the meaning and whatever sits between them does not.
 *
 * The example is invented, which is not a stylistic choice. The first draft of
 * this comment spelled out the real one, and the test below failed on its own
 * file — which is the most useful thing it could have done.
 * Returns null for anything too generic to search for, so a mission called
 * `test` does not fail every file in the repository.
 */
function tokenMatcher(token) {
  const parts = String(token).match(/[A-Za-z0-9]+/g);
  if (!parts) return null;
  if (parts.length < 2 && parts[0].length < 6) return null;
  return new RegExp(
    `(?<![A-Za-z0-9])${parts.join('[^A-Za-z0-9]{0,3}')}(?![A-Za-z0-9])`, 'i');
}

test('the mission matcher catches an exercise name however it is punctuated', () => {
  const m = tokenMatcher('xkc-41-9');
  assert.ok(m.test('node terrain/extract.mjs xkc-41-9-assets.html'), 'inside a filename');
  assert.ok(m.test('XKC 41 9'), 'spaces are the same leak as dashes');
  assert.ok(m.test('plans/xkc_41_9.json'));
  assert.equal(m.test('xkc-41-99'), false, 'a longer number is a different thing');
  assert.equal(m.test('prefixkc-41-9'), false, 'has to start on a boundary');
  assert.ok(tokenMatcher('THUNDER RIDGE').test('during the Thunder Ridge rotation'),
    'case-insensitive, because prose shortens and re-cases a name');
  assert.equal(tokenMatcher('hunt'), null, 'one short word is not distinctive enough to search for');
  assert.ok(tokenMatcher('nightfall'), 'one long word is');
});

test('no tracked file names the engagement', (t) => {
  const tokens = [...missionTokens()];
  // Skipped rather than passed, for the same reason as the roster test: a CI
  // clone has no profile, so there is no name to look for and a green tick
  // would claim something this run did not check.
  if (!tokens.length) { t.skip('no mission profile on this machine'); return; }

  const bodies = tracked()
    .map(f => [f, readable(f)])
    .filter(([, b]) => b !== null);

  const hits = [];
  for (const token of tokens) {
    const re = tokenMatcher(token);
    if (!re) continue;
    for (const [f, body] of bodies) if (re.test(body)) hits.push(`${token} in ${f}`);
  }
  assert.deepEqual(hits, [],
    'the exercise name identifies the engagement; use a generic placeholder');
});

/*
  The profile directory is the mechanism the rest of this depends on. If the
  ignore rule is ever relaxed, an engagement's terrain and roster land in the
  next commit silently — the files are already on disk, waiting.
*/
test('only the example mission profile is tracked', () => {
  const profiles = tracked()
    .filter(f => f.startsWith('missions/'))
    .map(f => f.split('/')[1]);
  assert.deepEqual([...new Set(profiles)], ['example'],
    'a real mission profile is tracked and would be pushed');
});

/*
  Every guard above reads text. A binary is invisible to all of them, and the
  binaries are exactly what an engagement leaks as: an exported workbook, a
  capture, a screenshot of the real console with real hostnames in it. So the
  rule is not "scan them" — it cannot be — it is that there is one place they
  are allowed to be, and anything new shows up here as a failure to be looked
  at by a person.

  docs/screenshots is that place. What goes in it comes from tools/demo-data.mjs
  through tools/screenshots.mjs, against a synthetic store on a scratch port,
  and gets read by eye before it is committed.

  The brand assets are the one exception, and they are listed by name rather
  than by a pattern over web/ on purpose. A glob would let the next binary in
  silently, and the property worth keeping is not "these files are allowed" —
  it is that anything not already looked at fails here and gets looked at. They
  are derived from a logo the operator supplied and carry no engagement data.
*/
const BRAND_ASSETS = new Set([
  'web/mark.png', 'web/favicon.png', 'web/apple-touch-icon.png',
  'docs/logo.png',
]);

test('the only tracked binaries are the demo screenshots and the brand assets', () => {
  const binary = tracked().filter((f) => {
    let buf;
    try { buf = readFileSync(f); } catch { return false; }
    return buf.subarray(0, 4096).includes(0);
  });
  const stray = binary.filter(f =>
    !/^docs\/screenshots\/[\w-]+\.png$/.test(f) && !BRAND_ASSETS.has(f));
  assert.deepEqual(stray, [],
    'a binary outside docs/screenshots is unreadable to every check in this file');
});

test('nothing that holds a credential or runtime state is tracked', () => {
  const bad = tracked().filter(f =>
    /(^|\/)\.hunt-token$|(^|\/)\.env$|\.(db|sqlite|sqlite3|log|pem|key|p12|pfx)$|^data\//.test(f));
  assert.deepEqual(bad, []);
});

/*
  One engagement's assertions are that engagement's data: the file names its
  hosts, its addresses and its team, and skips wherever the profile is absent.
*/
test('mission-specific tests are not tracked', () => {
  assert.deepEqual(tracked().filter(f => /^test\/mission-.*\.test\.js$/.test(f)), []);
});
