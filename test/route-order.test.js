import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

/*
  Routes are tested in source order, so a literal path placed after a pattern
  that also matches it is dead code that answers the wrong thing.

  This happened three times in one day. /api/hosts/withdrawn answered "no such
  host" because /api/hosts/:id came first; /api/records/archived did the same;
  /api/notifications/read nearly did. Every one of them looked right in the
  diff and was wrong at runtime, because the pattern that swallows them is two
  hundred lines away.
*/

const SRC = readFileSync('server/http.js', 'utf8');

/** Every route test in the file, in the order the server evaluates them. */
function routes() {
  const out = [];
  SRC.split('\n').forEach((line, idx) => {
    const method = (/method === '(\w+)'/.exec(line) ?? [, null])[1];
    const literal = /pathname === '([^']+)'/.exec(line);
    if (literal) { out.push({ line: idx + 1, kind: 'literal', path: literal[1], method }); return; }
    const pattern = /pathname\.match\((\/\^[^\n]*?\$\/)\)/.exec(line);
    if (pattern) {
      let re = null;
      // eslint-disable-next-line no-eval
      try { re = (0, eval)(pattern[1]); } catch { /* not a literal regex */ }
      if (re) out.push({ line: idx + 1, kind: 'pattern', re, method, src: pattern[1] });
    }
  });
  return out;
}

test('the route table is parseable, so the check below means something', () => {
  const all = routes();
  assert.ok(all.length > 40, `only found ${all.length} routes — the parser has stopped matching`);
  assert.ok(all.some(r => r.kind === 'literal'), 'no literal routes found');
  assert.ok(all.some(r => r.kind === 'pattern'), 'no pattern routes found');
});

test('no literal route is shadowed by a pattern above it', () => {
  const all = routes();
  const shadowed = [];

  for (const lit of all.filter(r => r.kind === 'literal')) {
    for (const pat of all.filter(r => r.kind === 'pattern' && r.line < lit.line)) {
      if (!pat.re.test(lit.path)) continue;
      /*
        Different verbs never collide. A route with no verb of its own handles
        every one of them, so it shadows regardless.
      */
      if (lit.method && pat.method && lit.method !== pat.method) continue;
      shadowed.push(
        `${lit.path} [${lit.method ?? 'any'}] at line ${lit.line} `
        + `is caught first by ${pat.src} [${pat.method ?? 'any'}] at line ${pat.line}`);
    }
  }

  assert.deepEqual(shadowed, [],
    'move the literal path above the pattern that swallows it');
});
