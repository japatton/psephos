import { test } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDb, initSchema } from '../store/db.js';
import { seedMembers, listMembers, memberByToken } from '../store/members.js';
import { loadOrCreateToken, parseCookies, checkAuth, sameToken } from '../server/auth.js';

/*
  The security boundary of a server that binds 0.0.0.0 on purpose, and until
  now the only tests touching it went through HTTP routes. These exercise it
  directly, because the interesting cases — a malformed cookie, a token of the
  wrong length, a member name that needs escaping — are awkward to reach
  through a route and are exactly where it breaks.
*/

const req = (headers = {}) => ({ headers });
const OPERATOR = 'a'.repeat(64);

// --- the token file ------------------------------------------------------------

test('the token is generated once and reused, so a restart does not sign everyone out', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hunt-auth-'));
  const path = join(dir, '.hunt-token');
  try {
    const first = loadOrCreateToken(path);
    assert.equal(first.created, true);
    assert.match(first.token, /^[0-9a-f]{64}$/, '32 bytes of entropy, hex encoded');

    const second = loadOrCreateToken(path);
    assert.equal(second.created, false);
    assert.equal(second.token, first.token);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an empty token file is replaced rather than trusted', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hunt-auth-'));
  const path = join(dir, '.hunt-token');
  try {
    writeFileSync(path, '   \n', 'utf8');
    const out = loadOrCreateToken(path);
    assert.equal(out.created, true);
    assert.equal(out.token.length, 64, 'an empty file must not become an empty token');
    assert.equal(readFileSync(path, 'utf8').trim(), out.token);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the token file is not world-readable', { skip: process.platform === 'win32'
  ? 'POSIX modes do not apply on NTFS' : false }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'hunt-auth-'));
  const path = join(dir, '.hunt-token');
  try {
    loadOrCreateToken(path);
    assert.equal(statSync(path).mode & 0o077, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- cookies --------------------------------------------------------------------

test('cookies are split on the first = only, so a base64 value survives', () => {
  const c = parseCookies('hunt_token=abc==; other=1');
  assert.equal(c.hunt_token, 'abc==');
  assert.equal(c.other, '1');
});

test('percent-encoded values are decoded', () => {
  assert.equal(parseCookies('hunt_analyst=Jos%C3%A9').hunt_analyst, 'José');
});

/*
  decodeURIComponent('%ZZ') throws. Cookies are parsed before anything else on
  every request, so one malformed cookie turned every request into a 500 —
  including the login page, leaving no way back except clearing cookies by
  hand. The server never writes such a value, but a truncated cookie or another
  application on the same host can.
*/
test('a malformed cookie is kept raw rather than taking the request down', () => {
  let c;
  assert.doesNotThrow(() => { c = parseCookies('hunt_token=good; junk=%ZZ'); });
  assert.equal(c.hunt_token, 'good', 'and the good cookie is still read');
  assert.equal(c.junk, '%ZZ');
  assert.doesNotThrow(() => checkAuth(req({ cookie: 'hunt_token=%E0%A4%A' }), OPERATOR));
});

test('junk that is not a cookie at all is ignored', () => {
  assert.deepEqual(parseCookies('novalue; =empty-name; a=1'), { '': 'empty-name', a: '1' });
  assert.deepEqual(parseCookies(''), {});
  assert.deepEqual(parseCookies(undefined), {});
});

// --- who is asking ---------------------------------------------------------------

test('no credential is refused', () => {
  assert.deepEqual(checkAuth(req(), OPERATOR), { ok: false, analyst: null, member: null });
});

test('a bearer header and a cookie are both accepted', () => {
  assert.equal(checkAuth(req({ authorization: `Bearer ${OPERATOR}` }), OPERATOR).ok, true);
  assert.equal(checkAuth(req({ cookie: `hunt_token=${OPERATOR}` }), OPERATOR).ok, true);
});

test('the bearer header wins over a stale cookie', () => {
  const out = checkAuth(req({
    authorization: `Bearer ${OPERATOR}`, cookie: 'hunt_token=wrong',
  }), OPERATOR);
  assert.equal(out.ok, true);
});

test('an empty or malformed Authorization header is not a credential', () => {
  assert.equal(checkAuth(req({ authorization: 'Bearer ' }), OPERATOR).ok, false);
  assert.equal(checkAuth(req({ authorization: OPERATOR }), OPERATOR).ok, false,
    'the scheme is required');
  assert.equal(checkAuth(req({ authorization: 'Basic abc' }), OPERATOR).ok, false);
});

test('a wrong token of the same length is refused', () => {
  assert.equal(checkAuth(req({ authorization: `Bearer ${'b'.repeat(64)}` }), OPERATOR).ok, false);
});

/*
  A near miss, through the route rather than through the comparator.

  sameToken is thoroughly tested on its own, and nothing tested that checkAuth
  actually uses it: replacing the call with token.startsWith(supplied) left all
  751 tests passing, and that is a full API bypass discoverable in about a
  thousand requests — 'a', then 'aa', until the whole token falls out. Every
  existing case differs from the real token in every byte, which a prefix test
  would also reject.
*/
test('a prefix, a truncation or an extension of the token is not the token', () => {
  const near = [
    OPERATOR.slice(0, 1),
    OPERATOR.slice(0, OPERATOR.length - 1),
    OPERATOR.slice(1),
    `${OPERATOR}x`,
    `x${OPERATOR}`,
    OPERATOR.trim().toUpperCase(),
  ];
  for (const supplied of near) {
    if (supplied === OPERATOR) continue;
    assert.equal(checkAuth(req({ authorization: `Bearer ${supplied}` }), OPERATOR).ok, false,
      `"${supplied.slice(0, 12)}…" was accepted as the operator token`);
    assert.equal(checkAuth(req({ cookie: `hunt_token=${supplied}` }), OPERATOR).ok, false,
      `"${supplied.slice(0, 12)}…" was accepted through the cookie`);
  }
  // And the real one still is, so this is not passing by refusing everything.
  assert.equal(checkAuth(req({ authorization: `Bearer ${OPERATOR}` }), OPERATOR).ok, true);
});

/*
  The operator token is nobody's chat window. It grants read and adjudication
  and is deliberately not a member, because honouring a client-supplied name
  here would let anyone holding it post and read DMs as a colleague.
*/
test('the operator token is authenticated but is not a person', () => {
  const out = checkAuth(req({
    authorization: `Bearer ${OPERATOR}`, cookie: 'hunt_analyst=Okafor',
  }), OPERATOR);
  assert.equal(out.ok, true);
  assert.equal(out.analyst, 'operator', 'the cookie must not decide who this is');
  assert.equal(out.member, null);
});

// --- member tokens ----------------------------------------------------------------

function withTeam() {
  const db = openDb(':memory:');
  initSchema(db);
  seedMembers(db);
  return db;
}

test('a member token says who is asking, and the name comes from the store', () => {
  const db = withTeam();
  const m = listMembers(db)[0];
  const out = checkAuth(req({ authorization: `Bearer ${m.token}` }), OPERATOR, db, memberByToken);
  assert.equal(out.ok, true);
  assert.equal(out.analyst, m.name);
  assert.equal(out.member.id, m.id);
});

test('a member token beats a conflicting hunt_analyst cookie', () => {
  const db = withTeam();
  const m = listMembers(db)[0];
  const out = checkAuth(req({
    authorization: `Bearer ${m.token}`, cookie: 'hunt_analyst=SomebodyElse',
  }), OPERATOR, db, memberByToken);
  assert.equal(out.analyst, m.name);
});

test('member tokens are case-insensitive, because people type them off a screen', () => {
  const db = withTeam();
  const m = listMembers(db)[0];
  const out = checkAuth(req({ authorization: `Bearer ${m.token.toLowerCase()}` }),
    OPERATOR, db, memberByToken);
  assert.equal(out.ok, true);
  assert.equal(out.analyst, m.name);
});

test('an unknown token is refused even with the store available', () => {
  const db = withTeam();
  const out = checkAuth(req({ authorization: 'Bearer NOTATOKEN' }), OPERATOR, db, memberByToken);
  assert.equal(out.ok, false);
  assert.equal(out.member, null);
});

test('member tokens avoid characters that are ambiguous on a screen', () => {
  const db = withTeam();
  for (const m of listMembers(db)) {
    assert.match(m.token, /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{8}$/,
      `${m.name}'s token contains a character someone will mistype`);
  }
});

test('every member has a distinct token', () => {
  const db = withTeam();
  const tokens = listMembers(db).map(m => m.token);
  assert.equal(new Set(tokens).size, tokens.length);
});

/*
  The operator token grants the whole case file and the ability to spawn model
  runs. Comparing it with === leaks its bytes to anybody who can time the
  answer, and /api/login is reachable without authenticating, so that is where
  the samples are cheapest to collect.
*/
/*
  Named for what it asserts. Constant-time is a property of the primitive, not
  of any output — replacing the whole body of sameToken with `a === b` is
  behaviour-preserving and no behavioural test can catch it — so the old name
  claimed something none of the five assertions below establish. What they do
  establish is exactness, which is what the near-miss tests above depend on.
  The timing argument lives in the comment over sameToken itself.
*/
test('the operator token comparison is exact', () => {
  assert.equal(sameToken('abcdef', 'abcdef'), true);
  assert.equal(sameToken('abcdef', 'abcdeg'), false);
  assert.equal(sameToken('abcdef', 'abcde'), false, 'length alone is not a match');
  assert.equal(sameToken('', ''), true);
  for (const bad of [null, undefined, 0, {}, ['a']]) {
    assert.equal(sameToken(bad, 'abcdef'), false, String(bad));
    assert.equal(sameToken('abcdef', bad), false, String(bad));
  }
});
