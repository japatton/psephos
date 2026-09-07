import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { state, esc, shortTime, applyDelta, on } from '../web/core.js';

/*
  The browser helpers that everything else is built on, and that nothing
  covered. esc is called about two hundred times across the views and is the
  only thing between the DOM and text that arrives from an analyst's paste, an
  uploaded file, or the model.
*/

// --- escaping ---------------------------------------------------------------------

test('the five characters that matter in HTML are escaped', () => {
  assert.equal(esc('&'), '&amp;');
  assert.equal(esc('<'), '&lt;');
  assert.equal(esc('>'), '&gt;');
  assert.equal(esc('"'), '&quot;');
  assert.equal(esc("'"), '&#39;');
});

test('a script tag cannot survive escaping', () => {
  const out = esc('<script>alert(1)</script>');
  assert.equal(out, '&lt;script&gt;alert(1)&lt;/script&gt;');
  assert.equal(out.includes('<'), false);
});

test('an attribute cannot be broken out of', () => {
  // The shape that matters: values are interpolated inside double quotes.
  const out = esc('" onmouseover="alert(1)');
  assert.equal(out.includes('"'), false, 'the closing quote survived');
  assert.equal(esc("' onfocus='x").includes("'"), false, 'single quotes too');
});

test('ampersands are escaped first, so nothing is double-decoded', () => {
  // Escaping < before & would turn "<" into "&amp;lt;" and render the entity.
  assert.equal(esc('&lt;'), '&amp;lt;');
  assert.equal(esc('a&b<c'), 'a&amp;b&lt;c');
});

test('null, undefined and non-strings do not blow up a render', () => {
  assert.equal(esc(null), '');
  assert.equal(esc(undefined), '');
  assert.equal(esc(0), '0');
  assert.equal(esc(false), 'false');
  assert.equal(esc({ a: 1 }), '[object Object]');
});

test('ordinary text passes through untouched', () => {
  const plain = 'svc_backup ran /usr/bin/curl at 11:59 (pid 4021)';
  assert.equal(esc(plain), plain);
});

/*
  Escaping these five is right for element text and for a quoted attribute.
  It is NOT enough inside href, src or style, where a javascript: value needs
  no angle brackets at all. Asserted as a property of the views rather than of
  esc, because the safety comes from never interpolating into those contexts.
*/
/*
  One justified exception, named rather than hidden. The Markdown renderer has
  to emit links, and it is the only place that may. It does not lean on
  escaping in that position: the target goes through a scheme allowlist first,
  which is the actual defence and is asserted below rather than assumed.
*/
const JUSTIFIED_HREF = new Set(['web/markdown.js: href']);

test('no view interpolates into a URL or style attribute', () => {
  const views = execSync('git ls-files web', { encoding: 'utf8' })
    .trim().split('\n').filter(f => f.endsWith('.js'));
  const bad = [];
  for (const f of views) {
    const src = readFileSync(f, 'utf8');
    for (const m of src.matchAll(/(href|src|action|formaction|style)\s*=\s*"\$\{/g)) {
      const hit = `${f}: ${m[1]}`;
      if (!JUSTIFIED_HREF.has(hit)) bad.push(hit);
    }
  }
  assert.deepEqual(bad, [], 'escaping does not make a value safe in these');
});

/*
  Error text is the interpolation that gets forgotten, because the handler that
  writes it is the one nobody exercises. It also carries content the view did
  not compose: a server message can quote a field name from the request body,
  so it is not automatically the view's own words.

  Narrow on purpose. A general "every interpolation must be escaped" rule fails
  on the many places a view legitimately splices in HTML it just built, so it
  would be turned off within a week. This asserts the one shape that is always
  wrong.
*/
test('no view writes an error message into innerHTML without escaping it', () => {
  const files = execSync('git ls-files web', { encoding: 'utf8' })
    .trim().split('\n').filter(f => f.endsWith('.js'));
  const bad = [];
  for (const f of files) {
    const src = readFileSync(f, 'utf8');
    for (const assign of src.matchAll(/innerHTML\s*=\s*`([^`]*)`/g)) {
      for (const interp of assign[1].matchAll(/\$\{([^}]*)\}/g)) {
        const expr = interp[1];
        if (/\.message\b/.test(expr) && !/\besc\s*\(/.test(expr)) {
          bad.push(`${f}: \${${expr.trim()}}`);
        }
      }
    }
  }
  assert.deepEqual(bad, [], 'these reach the DOM unescaped');
});

/*
  The exemption above is only worth having while the allowlist behind it holds,
  so it is checked here rather than taken on trust. If someone loosens
  safeHref, this fails even though markdown.test.js is a separate file.
*/
test('the one exempted href is gated on a scheme allowlist, not on escaping', async () => {
  const { renderMarkdown } = await import('../web/markdown.js');
  for (const scheme of ['javascript:alert(1)', 'data:text/html,<svg>', 'vbscript:x']) {
    assert.equal(renderMarkdown(`[x](${scheme})`).includes('<a '), false, scheme);
  }
  assert.match(renderMarkdown('[x](https://example.test)'), /<a href="https:\/\/example\.test"/);
});

// --- timestamps ---------------------------------------------------------------------

test('a timestamp is shortened for reading, and absence is visible', () => {
  assert.equal(shortTime('2026-08-19T11:59:02.123Z'), '2026-08-19 11:59:02Z');
  assert.equal(shortTime('2026-08-19T11:59:02Z'), '2026-08-19 11:59:02Z');
  assert.equal(shortTime(null), '—', 'a blank cell would read as zero, not unknown');
  assert.equal(shortTime(''), '—');
});

// --- the delta reducer -----------------------------------------------------------------

const reset = () => {
  state.records = [];
  state.hosts = [];
  state.edges = [];
  state.connections = [];
  state.sessions = [];
};

test('a created record is added and an updated one replaces it in place', () => {
  reset();
  applyDelta({ type: 'record.created', payload: { id: 'r1', description: 'first' } });
  assert.equal(state.records.length, 1);

  applyDelta({ type: 'record.updated', payload: { id: 'r1', description: 'corrected' } });
  assert.equal(state.records.length, 1, 'an update must not duplicate');
  assert.equal(state.records[0].description, 'corrected');
});

test('a wholesale change replaces the list rather than merging into it', () => {
  reset();
  state.records = [{ id: 'stale' }];
  applyDelta({ type: 'records.changed', payload: [{ id: 'r1' }, { id: 'r2' }] });
  assert.deepEqual(state.records.map(r => r.id), ['r1', 'r2'], 'the stale row is gone');
});

test('a verdict updates one host without disturbing the rest', () => {
  reset();
  state.hosts = [{ id: 'h1', verdict: 'unknown' }, { id: 'h2', verdict: 'unknown' }];
  applyDelta({ type: 'host.verdict', payload: { id: 'h2', verdict: 'confirmed' } });
  assert.equal(state.hosts.length, 2);
  assert.equal(state.hosts.find(h => h.id === 'h1').verdict, 'unknown');
  assert.equal(state.hosts.find(h => h.id === 'h2').verdict, 'confirmed');
});

test('an unrecognised event changes nothing but still reaches listeners', () => {
  reset();
  let seen = null;
  const off = on('*', (e) => { seen = e; });
  applyDelta({ type: 'something.new', payload: { a: 1 } });
  if (typeof off === 'function') off();
  assert.deepEqual(state.records, []);
  assert.deepEqual(seen, { type: 'something.new', payload: { a: 1 } },
    'a view that knows about a new event must still get it');
});

/*
  Every type the server broadcasts has to be one the client either applies or
  deliberately ignores. A server-side rename that the reducer never learns
  about shows as a UI that silently stops updating.
*/
test('every event the server broadcasts is one the client has heard of', () => {
  const src = execSync('git ls-files server store claude', { encoding: 'utf8' })
    .trim().split('\n').filter(f => /\.js$/.test(f))
    .map(f => readFileSync(f, 'utf8')).join('\n');
  const broadcast = new Set([...src.matchAll(/broadcast\(\s*'([\w.]+)'/g)].map(m => m[1]));
  assert.ok(broadcast.size > 5, 'found the broadcast calls');

  const client = readFileSync('web/core.js', 'utf8');
  const handled = new Set([...client.matchAll(/case '([\w.]+)'/g)].map(m => m[1]));

  // Views subscribe to the rest by name through on(); those must at least be
  // named somewhere in web/, or nothing is listening.
  const webSrc = execSync('git ls-files web', { encoding: 'utf8' })
    .trim().split('\n').filter(f => f.endsWith('.js'))
    .map(f => readFileSync(f, 'utf8')).join('\n');

  const orphans = [...broadcast].filter(t => !handled.has(t) && !webSrc.includes(`'${t}'`));
  assert.deepEqual(orphans, [], 'the server broadcasts these and nothing listens');
});
