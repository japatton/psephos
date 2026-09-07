import { roster } from '../store/members.js';
import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { seedHosts } from '../store/hosts.js';
import { seedThreads } from '../store/threads.js';
import { createRecord } from '../store/records.js';
import { createServer } from '../server/http.js';
import { seedMembers, listMembers } from '../store/members.js';
import { ensureMemberSessions, sessionForMember } from '../store/sessions.js';

const TOKEN = 'test-token-not-a-real-secret';
let base, server, db, recordId;

const authed = (path, init = {}) => fetch(base + path, {
  ...init,
  headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', ...(init.headers ?? {}) },
});

before(async () => {
  db = openDb(':memory:');
  initSchema(db);
  seedThreads(db);
  seedHosts(db);
  recordId = createRecord(db, {
    description: 'first C2', hostname: 'EX-MAIL.example.test',
    source_ip: '10.20.1.11', destination_ip: '203.0.113.25',
    event_time: '2026-08-13 17:59:02Z',
  }, { analyst: 'seed' }).id;

  seedMembers(db);
  ensureMemberSessions(db, listMembers(db));
  server = createServer({ db, token: TOKEN });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => { server.close(); });

test('unauthenticated api call is 401 with an empty body', async () => {
  const res = await fetch(base + '/api/state');
  assert.equal(res.status, 401);
  assert.equal((await res.text()).length, 0);
});

test('a wrong token is refused', async () => {
  const res = await fetch(base + '/api/state', { headers: { authorization: 'Bearer wrong' } });
  assert.equal(res.status, 401);
});

test('unauthenticated page request gets the login screen, not the app', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /Psephos/);
  assert.doesNotMatch(html, /id="view"/, 'the app shell must not leak before auth');
});

test('the login page can load its stylesheet before sign-in', async () => {
  const res = await fetch(base + '/theme.css');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /text\/css/);
  assert.match(await res.text(), /^\/\* Defender theme/,
    'the login page asks for its own stylesheet, so serving it the login page instead ' +
    'leaves the one screen a new analyst sees rendering unstyled');
});

test('the brand assets the sign-in page needs are served before sign-in', async () => {
  for (const [path, type] of [
    ['/theme.css', /text\/css/],
    ['/mark.png', /image\/png/],
    ['/favicon.png', /image\/png/],
  ]) {
    const res = await fetch(base + path);
    assert.equal(res.status, 200, path);
    assert.match(res.headers.get('content-type') ?? '', type,
      `${path} came back as the wrong type, so the browser will not use it`);
  }
});

/*
  The other half of that rule, and the one worth keeping: a palette, a logo and
  a favicon are already printed on the outside of the box. The shell and the
  views are not, and they stay behind the token.
*/
test('nothing else static is open before sign-in', async () => {
  for (const path of ['/app.js', '/core.js', '/views/map.js', '/vendor/d3.min.js']) {
    const res = await fetch(base + path);
    assert.match(await res.text(), /Enter your team token/,
      `${path} must stay behind the token: the shell reveals structure`);
  }
});

/** From the profile, so adding one to the example does not fail the suite. */
const THREAD_COUNT = 2;

test('/api/state returns the bootstrap shape', async () => {
  const res = await authed('/api/state');
  assert.equal(res.status, 200);
  const body = await res.json();
  for (const k of ['threads', 'hosts', 'edges', 'connections', 'sessions']) {
    assert.ok(k in body, `bootstrap is missing ${k}`);
  }
  assert.equal(body.threads.length, THREAD_COUNT);
  assert.equal(body.connections.length, 1);
  assert.ok(body.hosts.length > 0, 'the profile terrain reached the bootstrap');
});

/*
  The point of the whole exercise, asserted rather than described: what the shell
  is handed is bounded by the estate and the roster. Records are the only
  collection that grows with the engagement and they are fetched by the views
  that draw them, each asking for the part it shows.
*/
test('the bootstrap does not carry the case file', async () => {
  const body = await (await authed('/api/state')).json();
  assert.equal('records' in body, false,
    'records are back in the bootstrap, which is the thing that grew without bound');

  // Everything still there is bounded by something other than the findings.
  for (const k of ['threads', 'hosts', 'edges', 'connections', 'sessions', 'members']) {
    assert.ok(Array.isArray(body[k]), k);
  }
});

test('login sets the cookies EventSource needs', async () => {
  const res = await fetch(base + '/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: TOKEN, analyst: 'Lindqvist' }),
  });
  assert.equal(res.status, 204);
  const cookies = res.headers.getSetCookie();
  assert.ok(cookies.some(c => c.startsWith('hunt_token=')));
  // The server token is always 'operator', whatever name the caller offers.
  // The name gates DM membership and stamps chat authorship, so a
  // caller-supplied one would be an impersonation primitive.
  assert.ok(cookies.some(c => c.includes('hunt_analyst=operator')));
  assert.ok(!cookies.some(c => c.includes('Lindqvist')));
});

test('login with a bad token is refused', async () => {
  const res = await fetch(base + '/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: 'nope', analyst: 'mallory' }),
  });
  assert.equal(res.status, 401);
});

test('promote moves state and the server token cannot claim a name', async () => {
  const res = await fetch(`${base}/api/records/${recordId}/promote`, {
    method: 'POST',
    headers: { cookie: `hunt_token=${TOKEN}; hunt_analyst=Lindqvist` },
  });
  assert.equal(res.status, 200);
  const rec = await res.json();
  assert.equal(rec.state, 'filed');
  // A member token attests its own name; the server token does not, so the
  // hunt_analyst cookie is ignored rather than trusted for attribution.
  assert.equal(rec.adjudicated_by, 'operator');
});

test('host verdict round-trips', async () => {
  const hosts = await (await authed('/api/state')).json();
  const target = hosts.hosts.find(h => h.ip === '10.20.1.11');
  const res = await authed(`/api/hosts/${target.id}/verdict`, {
    method: 'PATCH', body: JSON.stringify({ verdict: 'confirmed' }),
  });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).verdict, 'confirmed');
});

test('CSV export returns the 18 headers and only filed records by default', async () => {
  const res = await authed('/api/export/records.csv');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/csv/);
  const body = await res.text();
  const header = body.replace(/^﻿/, '').split('\r\n')[0];
  assert.equal(header.split(',').length, 18);
  assert.match(header, /^Event ID,Event Time,Hostname/);
  assert.match(body, /first C2/);
});

test('the navigator layer is served as a downloadable layer file', async () => {
  const res = await authed('/api/export/navigator.json');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-disposition') ?? '', /attachment/);
  const layer = await res.json();
  assert.equal(layer.domain, 'enterprise-attack');
  assert.ok(Array.isArray(layer.techniques));
});

test('indicators export as a MISP event by default and STIX on request', async () => {
  const misp = await (await authed('/api/export/iocs.json')).json();
  assert.ok(misp.Event, 'not a MISP event');

  const stix = await (await authed('/api/export/iocs.json?format=stix')).json();
  assert.equal(stix.type, 'bundle');
});

test('usage reports totals, and zero rather than null before any turn', async () => {
  const u = await (await authed('/api/usage')).json();
  assert.equal(u.total.turns, 0);
  assert.equal(u.total.input_tokens, 0, 'null renders as "null tokens" in the header');
  assert.ok(Array.isArray(u.byMember));
});

test('the report assembles from the store as markdown', async () => {
  const res = await authed('/api/export/report.md');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /markdown/);
  const md = await res.text();
  assert.match(md, /hunt report/i);
  assert.match(md, /## Coverage and gaps/);
});

test('the aggregates the views need are served, and route ahead of the id pattern', async () => {
  const ev = await (await authed('/api/records/evidence-by-host')).json();
  assert.equal(typeof ev, 'object');
  assert.ok(!Array.isArray(ev), 'evidence is keyed by host, not a list of findings');

  const counts = await (await authed('/api/records/counts')).json();
  for (const k of ['pending', 'filed', 'unplaceable', 'total']) {
    assert.equal(typeof counts[k], 'number', k);
  }

  const unplaced = await (await authed('/api/records/unplaced')).json();
  assert.ok(Array.isArray(unplaced));

  // Each of these would otherwise be read as a record id by /api/records/:id.
  for (const p of ['evidence-by-host', 'counts', 'unplaced']) {
    const res = await authed(`/api/records/${p}`);
    assert.equal(res.status, 200, `${p} was swallowed by the id route`);
  }
});

test('the bank and coverage are served, and route ahead of the task pattern', async () => {
  const bank = await (await authed('/api/bank?q=scheduled%20task')).json();
  assert.ok(Array.isArray(bank));
  assert.ok(bank.some(e => e.id === 'T1053.005'), 'the bank did not answer a name query');

  const cov = await (await authed('/api/plan/coverage')).json();
  assert.ok(Array.isArray(cov.tactics) && cov.tactics.length > 0);
  assert.ok(cov.version, 'coverage should carry the ATT&CK version it was computed against');

  // No literal GET route answers from-bank (only POST does), so the pattern
  // route is what has to handle it — reading it as an ordinary task key and
  // 404ing like any other unknown one, not swallowing it some other way.
  const asKey = await authed('/api/plan/task/from-bank');
  assert.equal(asKey.status, 404);
  assert.equal((await asKey.json()).error, 'no such task');
});

test('an entry can be drawn into the plan, and a bad id is refused', async () => {
  const res = await authed('/api/plan/task/from-bank', {
    method: 'POST', body: JSON.stringify({ bankId: 'T1053.005', phaseKey: 'P1' }),
  });
  assert.equal(res.status, 201);
  const task = await res.json();
  assert.equal(task.bankId, 'T1053.005');

  const bad = await authed('/api/plan/task/from-bank', {
    method: 'POST', body: JSON.stringify({ bankId: 'T0000-nope' }),
  });
  assert.equal(bad.status, 404);
});

/*
  domain is a raw query parameter on both routes. It used to reach
  readFileSync unchecked: an unknown value 500'd with an absolute filesystem
  path in the body, and '..' in it walked the read straight out of
  plans/attack/ entirely. The static-file route already refuses this shape of
  attack below; the bank and coverage routes need the same line held.
*/
test('an unknown or path-like bank domain is refused, not read off disk', async () => {
  const nope = await authed('/api/bank?domain=nope');
  assert.equal(nope.status, 400);
  assert.match((await nope.json()).error, /unknown domain/);

  const traversal = await authed(`/api/bank?domain=${encodeURIComponent('../../missions/example/plan')}`);
  assert.equal(traversal.status, 400);
  assert.match((await traversal.json()).error, /unknown domain/);

  const covBad = await authed('/api/plan/coverage?domain=nope');
  assert.equal(covBad.status, 400);

  // 'practice' is a real bank domain (it lists fine on /api/bank) but has no
  // ATT&CK matrix behind it, so coverage over it is refused too — just with
  // its own reason, not a crash.
  const covPractice = await authed('/api/plan/coverage?domain=practice');
  assert.equal(covPractice.status, 400);
});

test('static traversal outside the web root is refused', async () => {
  const res = await fetch(base + '/../package.json', {
    headers: { cookie: `hunt_token=${TOKEN}` },
  });
  assert.notEqual(res.status, 200);
});

test('an unknown api route is 404 json, not the login page', async () => {
  const res = await authed('/api/nope');
  assert.equal(res.status, 404);
  assert.equal((await res.json()).error, 'no such route');
});

test('sessions can be created and listed', async () => {
  const created = await authed('/api/sessions', {
    method: 'POST', body: JSON.stringify({ title: 'Thread C sweep', kind: 'chat' }),
  });
  assert.equal(created.status, 201);
  const s = await created.json();
  assert.equal(s.state, 'open');

  const detail = await (await authed(`/api/sessions/${s.id}`)).json();
  assert.deepEqual(detail.messages, []);
});

// --- team members ----------------------------------------------------------

/** Read from the profile, so adding a person to the example does not fail the suite. */
const ROSTER_SIZE = roster().length;

const asMember = (name, path, init = {}) => {
  const m = db.prepare('select * from members where name = ?').get(name);
  if (!m) throw new Error(`no member called ${name} in the example roster`);
  return fetch(base + path, {
    ...init,
    headers: { authorization: `Bearer ${m.token}`, 'content-type': 'application/json', ...(init.headers ?? {}) },
  });
};

test('every member on the roster is seeded, one chat each', () => {
  const members = listMembers(db);
  assert.equal(members.length, ROSTER_SIZE);
  assert.ok(members.every(m => sessionForMember(db, m.id)), 'every member has a session');
  assert.equal(new Set(members.map(m => m.token)).size, ROSTER_SIZE, 'tokens are unique');
});

test('a member token identifies who is asking', async () => {
  const me = await (await asMember('Okafor', '/api/me')).json();
  assert.equal(me.member.name, 'Okafor');
  assert.equal(me.member.role, 'Mission Element Lead');
  assert.equal(me.member.team, 'Bravo');
  assert.ok(me.sessionId, 'and points at their own chat');
});

test('tokens are never sent to the browser', async () => {
  const state = await (await authed('/api/state')).json();
  assert.equal(state.members.length, ROSTER_SIZE);
  assert.ok(state.members.every(m => !('token' in m)), 'a visible token is a usable one');
});

test('a member can post in their own window', async () => {
  const me = await (await asMember('Lindqvist', '/api/me')).json();
  const res = await asMember('Lindqvist', `/api/sessions/${me.sessionId}/message`, {
    method: 'POST', body: JSON.stringify({ text: '   ' }),
  });
  assert.equal(res.status, 400, 'reaches the empty-message check, so ownership passed');
});

test('a member cannot post in a colleague window', async () => {
  const analyst = await (await asMember('Lindqvist', '/api/me')).json();
  const res = await asMember('Baptiste', `/api/sessions/${analyst.sessionId}/message`, {
    method: 'POST', body: JSON.stringify({ text: 'not mine to send' }),
  });
  assert.equal(res.status, 403);
  assert.match((await res.json()).error, /not your chat window/);
});

test('but they can read it, which is the point', async () => {
  const analyst = await (await asMember('Lindqvist', '/api/me')).json();
  const res = await asMember('Baptiste', `/api/sessions/${analyst.sessionId}`);
  assert.equal(res.status, 200);
  assert.ok(Array.isArray((await res.json()).messages));
});

test('a bad member token is refused', async () => {
  const res = await fetch(base + '/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: 'NOTATOKEN' }),
  });
  assert.equal(res.status, 401);
});

test('logging in with a member token sets that identity, not a typed name', async () => {
  const m = db.prepare("select * from members where name = 'Baptiste'").get();
  const res = await fetch(base + '/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: m.token, analyst: 'Somebody Else' }),
  });
  assert.equal(res.status, 204);
  assert.ok(res.headers.getSetCookie().some(c => c.includes('hunt_analyst=Baptiste')),
    'the token decides the name, not the form');
});

/*
  A member token is eight characters and what it gates is posting as that
  person and reading their direct messages. Unlimited guesses also means
  unlimited timing samples against the operator token, which is what makes the
  constant-time comparison in checkAuth worth having in the first place.
*/
test('sign-in attempts are rate limited', async () => {
  const attempt = () => fetch(base + '/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: 'not-a-real-token' }),
  });

  const codes = [];
  for (let i = 0; i < 14; i++) codes.push((await attempt()).status);

  assert.ok(codes.includes(401), 'a wrong token is refused');
  assert.ok(codes.includes(429), `no attempt was throttled: ${codes.join(',')}`);
  // The refusals come first and the throttle after, rather than the reverse.
  assert.equal(codes.indexOf(429) > codes.indexOf(401), true);
  const throttled = await attempt();
  assert.equal(throttled.status, 429);
  assert.equal(throttled.headers.get('retry-after'), '60');
});

test('a throttled caller cannot get in with the right token either', async () => {
  // The limiter is already tripped by the test above, on the same socket
  // address, which is the point: guessing does not stop being expensive
  // because the next guess happens to be correct.
  const res = await fetch(base + '/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: TOKEN }),
  });
  assert.equal(res.status, 429);
});

/*
  Marking a channel read used to mean GETting its messages, because that
  handler marks read as a side effect. Watching a busy channel therefore
  re-downloaded up to three hundred messages for every one that arrived and
  discarded the answer.
*/
test('a channel can be marked read without re-reading it', async () => {
  const [me] = listMembers(db);
  // Its own channel, so the test does not depend on what the store seeds.
  const made = await fetch(base + '/api/chat/channels', {
    method: 'POST',
    headers: { authorization: `Bearer ${me.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ kind: 'group', name: 'read-marker', members: [me.name] }),
  });
  const body = await made.text();
  assert.equal(made.status, 201, body);
  const team = JSON.parse(body);

  const res = await fetch(base + `/api/chat/${team.id}/read`, {
    method: 'POST',
    headers: { authorization: `Bearer ${me.token}`, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(res.status, 204);
  assert.equal((await res.text()).length, 0, 'no body, so nothing is re-sent');
});

/*
  A DM between two people, and a third asking to mark it read.

  Written after finding that this test had never run its assertion: it created
  the DM with `members: [a.name]` where a was also the creator, so
  createChannel's "a direct message needs exactly one other person" threw, the
  route answered 400, and an `if (made.status !== 201) return` above the
  assertion swallowed it. The test was green for the whole of its life and the
  403 was never checked — on the one route where reading is not open.

  So the creation is asserted now rather than tolerated. A fixture that cannot
  build its own precondition is a fixture that tests nothing, and here it was
  hiding the only authorisation check in the file.
*/
test('marking read still refuses a conversation that is not yours', async () => {
  const [a, b, c] = listMembers(db);
  const made = await fetch(base + '/api/chat/channels', {
    method: 'POST',
    headers: { authorization: `Bearer ${a.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ kind: 'dm', members: [b.name] }),
  });
  // Read once: a message that consumes the body leaves nothing for the parse.
  const madeBody = await made.text();
  assert.equal(made.status, 201, `the DM fixture failed: ${madeBody}`);
  const dm = JSON.parse(madeBody);

  // c is on the roster and not in this conversation.
  const outsider = await fetch(base + `/api/chat/${dm.id}/read`, {
    method: 'POST',
    headers: { authorization: `Bearer ${c.token}`, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(outsider.status, 403, 'a non-member marked someone else\'s DM read');

  // And the other participant still can, so the refusal is about membership
  // rather than about the route refusing everyone.
  const member = await fetch(base + `/api/chat/${dm.id}/read`, {
    method: 'POST',
    headers: { authorization: `Bearer ${b.token}`, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(member.status, 204, 'the other participant should be able to mark it read');
});

/*
  A direct message must not reach a browser that cannot open it.

  The route already refuses the read with 403, and the design intent is visible
  two lines below the offending call: `notification.new` deliberately carries a
  null payload so that a mention inside a DM is not delivered to every browser
  on the LAN. The message broadcast did not follow it — it put the full body on
  a stream every authenticated client is listening to, so the 403 protected the
  API and nothing protected the wire.

  Reproduced before it was fixed: an outsider's event stream carried the
  plaintext of a DM they were refused on the API a moment earlier.
*/
test('a direct message body is not broadcast to people outside it', async () => {
  const [a, b, c] = listMembers(db);
  const made = await fetch(base + '/api/chat/channels', {
    method: 'POST',
    headers: { authorization: `Bearer ${a.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ kind: 'dm', members: [b.name] }),
  });
  const madeBody = await made.text();
  assert.equal(made.status, 201, `the DM fixture failed: ${madeBody}`);
  const dm = JSON.parse(madeBody);

  // c is on the roster and outside this conversation.
  const ac = new AbortController();
  const stream = await fetch(base + '/api/events', {
    headers: { authorization: `Bearer ${c.token}` }, signal: ac.signal,
  });
  const reader = stream.body.getReader();
  const dec = new TextDecoder();
  const seen = [];
  const pump = (async () => {
    let buf = '';
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';
        for (const l of lines) {
          if (!l.startsWith('data: ')) continue;
          try { seen.push(JSON.parse(l.slice(6))); } catch { /* keep-alive */ }
        }
      }
    } catch { /* aborted */ }
  })();

  const secret = 'the site lead is under investigation';
  await fetch(base + `/api/chat/${dm.id}/messages`, {
    method: 'POST',
    headers: { authorization: `Bearer ${a.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ body: secret }),
  });
  await new Promise(r => setTimeout(r, 300));
  ac.abort();
  await pump;

  const wire = JSON.stringify(seen);
  assert.ok(!wire.includes(secret), 'a DM body reached a browser outside the conversation');

  // And the API still refuses it, so the two halves agree.
  const read = await fetch(base + `/api/chat/${dm.id}/messages`,
    { headers: { authorization: `Bearer ${c.token}` } });
  assert.equal(read.status, 403);

  /*
    What does still cross the wire: the channel id, with no body. An outsider
    learns that a conversation they cannot open received something. Closing
    that as well means an identity-aware hub — broadcast currently writes to
    every client and knows nothing about who they are — which is a larger change
    than this one and a decision worth taking deliberately rather than in a
    security fix. Pinned here so it is a known shape rather than a surprise.
  */
  assert.ok(seen.some(e => e.type === 'chat.message' && e.payload?.channelId === dm.id),
    'the envelope is still broadcast; only the body was removed');
  assert.ok(seen.every(e => e.type !== 'chat.message' || e.payload?.message === undefined),
    'no chat.message event may carry a message object for a private channel');

  // The participant can still read what was said, which is the half the fix
  // must not have broken.
  const mine = await fetch(base + `/api/chat/${dm.id}/messages`,
    { headers: { authorization: `Bearer ${b.token}` } });
  assert.equal(mine.status, 200);
  assert.ok((await mine.json()).some(msg => msg.body === secret),
    'the intended recipient lost the message');
});

/*
  The route that hands out bytes.

  Every other chat route gates on canSee; this one looked the file up and
  served it. A teammate outside the DM, and the operator token the DM route
  refuses on every other path, both got the contents. Nothing hands an outsider
  the id — it is a UUID — so this was a capability URL rather than an open
  door, which is a reason it went unnoticed rather than a reason it was safe.
*/
test('a DM attachment is refused to everyone outside the conversation', async () => {
  const [a, b, outsider] = roster().map(m => m.name);
  const dm = await (await asMember(a, '/api/chat/channels', {
    method: 'POST', body: JSON.stringify({ kind: 'dm', members: [b] }),
  })).json();

  const up = await (await asMember(a, '/api/files?name=dc-auth.log', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-file-name': 'dc-auth.log' },
    body: '4624 logon from 10.20.20.4',
  })).json();
  const posted = await asMember(a, `/api/chat/${dm.id}/messages`, {
    method: 'POST', body: JSON.stringify({ body: 'this is the one', fileId: up.id }),
  });
  assert.equal(posted.status, 201, await posted.text());

  assert.equal((await asMember(a, `/api/files/${up.id}`)).status, 200, 'the sender');
  assert.equal((await asMember(b, `/api/files/${up.id}`)).status, 200, 'the recipient');

  const out = await asMember(outsider, `/api/files/${up.id}`);
  assert.equal(out.status, 403, 'a teammate outside the DM read a private attachment');
  assert.equal((await authed(`/api/files/${up.id}`)).status, 403,
    'the operator token is refused the conversation; the bytes are the conversation');
});

test('a file you cannot read cannot be laundered into a transcript', async () => {
  const [a, b, outsider] = roster().map(m => m.name);
  const dm = await (await asMember(a, '/api/chat/channels', {
    method: 'POST', body: JSON.stringify({ kind: 'dm', members: [b] }),
  })).json();
  const up = await (await asMember(a, '/api/files?name=secret.log', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-file-name': 'secret.log' },
    body: 'TOP SECRET DM ATTACHMENT BODY',
  })).json();
  await asMember(a, `/api/chat/${dm.id}/messages`, {
    method: 'POST', body: JSON.stringify({ body: 'here', fileId: up.id }),
  });

  const me = await (await asMember(outsider, '/api/me')).json();
  await asMember(outsider, `/api/sessions/${me.sessionId}/message`, {
    method: 'POST', body: JSON.stringify({ text: 'read this for me', fileIds: [up.id] }),
  });
  const sess = await (await asMember(outsider, `/api/sessions/${me.sessionId}`)).json();
  const transcript = JSON.stringify(sess);
  assert.doesNotMatch(transcript, /TOP SECRET DM ATTACHMENT BODY/,
    'inlining a file into a turn is another way of reading it');
});

/*
  The message body was narrowed; the channel row was not.

  createChannel returns the row, and a DM's row carries its title — which is
  both participants' names, sorted. Broadcasting it told every browser on the
  LAN that these two had opened a conversation, and when. The client ignores
  the payload and re-fetches, so nothing rendered; the data was on the wire
  regardless, which is the same standard the body was held to one line up.
*/
test('opening a direct message does not announce who is in it', async () => {
  const [a, b, c] = listMembers(db);
  const ac = new AbortController();
  const stream = await fetch(base + '/api/events', {
    headers: { authorization: `Bearer ${c.token}` }, signal: ac.signal,
  });
  const reader = stream.body.getReader();
  const dec = new TextDecoder();
  const seen = [];
  const pump = (async () => {
    let buf = '';
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';
        for (const l of lines) {
          if (!l.startsWith('data: ')) continue;
          try { seen.push(JSON.parse(l.slice(6))); } catch { /* keep-alive */ }
        }
      }
    } catch { /* aborted */ }
  })();

  await fetch(base + '/api/chat/channels', {
    method: 'POST',
    headers: { authorization: `Bearer ${a.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ kind: 'dm', members: [b.name] }),
  });
  await new Promise(r => setTimeout(r, 300));
  ac.abort();
  await pump;

  const channelEvents = seen.filter(e => e.type === 'chat.channel');
  assert.equal(channelEvents.length, 1, 'the outsider should still be told something changed');
  const wire = JSON.stringify(channelEvents);
  assert.ok(!wire.includes(a.name) && !wire.includes(b.name),
    `a DM's participants were announced to the whole team: ${wire}`);
});

/*
  A filename the header validator will not carry.

  Node rejects any code point above U+00FF in a header value, so a file called
  отчёт-по-хосту.log uploaded fine, posted fine, rendered its card fine — and
  threw on every download, a 500 forever, for evidence sitting in the store.
  The RFC 5987 form is what carries the real name; the ASCII form is a fallback.
*/
test('a file with a non-latin name can actually be downloaded', async () => {
  const [a] = roster().map(m => m.name);
  for (const name of ['отчёт-по-хосту.log', '報告.log', 'spray-📉.csv', 'résumé.csv', 'plain.log']) {
    const up = await (await asMember(a, '/api/files', {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', 'x-file-name': encodeURIComponent(name) },
      body: 'evidence',
    })).json();
    const got = await asMember(a, `/api/files/${up.id}`);
    assert.equal(got.status, 200, `${name} uploaded and then could not be downloaded`);
    assert.equal(await got.text(), 'evidence');
    const cd = got.headers.get('content-disposition');
    assert.match(cd, /filename\*=UTF-8''/, `${name} lost its real name: ${cd}`);
  }
});

/*
  A task key that no per-task route can match.

  addPhase validates its key; addTask took whatever was typed into the板 form's
  free-text Key field. "Sweep DCs" was created (201), rendered on the board with
  status, assign and history controls, and every per-task route answered "no
  such route" — the routes are [\w.:-]+ — including the PATCH that would edit
  it. There is no delete route, so it could only be removed by hand-editing
  data/plan.json.
*/
test('a task key that the per-task routes could never match is refused', async () => {
  for (const key of ['Sweep DCs', 'P1/T2', '50%']) {
    const res = await authed('/api/plan/task', {
      method: 'POST',
      body: JSON.stringify({ phaseKey: 'P1', key, title: 'Hunt for something' }),
    });
    assert.equal(res.status, 400, `"${key}" was accepted and is now unreachable`);
    assert.match((await res.json()).error, /task key may only contain/);
  }
});

/*
  A client's mistake reported as the server breaking. These routes call store
  functions that throw a precise diagnosis and had no catch, so the top-level
  handler answered 500 — and logged a stack trace to the operator's console for
  an ordinary bad id.
*/
test('an id the store does not know is a 404, not a server fault', async () => {
  const cases = [
    ['/api/records/no-such-id/promote', 'POST', {}],
    ['/api/records/no-such-id/deny', 'POST', {}],
    ['/api/records/no-such-id', 'PATCH', { description: 'x' }],
    ['/api/edges/no-such-id/confirm', 'POST', {}],
    ['/api/hosts/no-such-id/verdict', 'PATCH', { verdict: 'confirmed' }],
    ['/api/plan/task/no-such-task/assign', 'PATCH', { assignees: [] }],
  ];
  for (const [path, method, body] of cases) {
    const res = await authed(path, { method, body: JSON.stringify(body) });
    assert.equal(res.status, 404, `${method} ${path} answered ${res.status}`);
    assert.match((await res.json()).error, /no such/);
  }
});

test('a value outside a vocabulary is a 400, not a server fault', async () => {
  const key = (await (await authed('/api/plan')).json()).tasks[0].taskKey;
  const res = await authed(`/api/plan/task/${key}/status`, {
    method: 'PATCH', body: JSON.stringify({ status: 'donezo' }),
  });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /unknown status/);
});

test('a 204 carries no body and does not claim one', async () => {
  const [a] = roster().map(m => m.name);
  const channels = await (await asMember(a, '/api/chat/channels')).json();
  const res = await asMember(a, `/api/chat/${channels[0].id}/read`, { method: 'POST', body: '{}' });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('content-length'), null,
    'a 204 that declares a body length is a framing violation');
  assert.equal((await res.text()).length, 0);
});

/*
  The same near-miss check, at the route.

  /api/login is reachable without authenticating, so it is where the samples
  are cheapest to collect — and it does its own comparison. Substituting a
  prefix test for sameToken at either site left the whole suite passing.
*/
test('a prefix of the operator token does not sign anybody in', async () => {
  /*
    Its own server: the sign-in limiter allows ten attempts a minute per
    address and it is created per server, so borrowing the shared one would
    measure the limiter rather than the comparison.
  */
  const srv = createServer({ db, token: TOKEN });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const at = `http://127.0.0.1:${srv.address().port}`;
  const login = (t) => fetch(at + '/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: t }),
  });
  try {
    for (const supplied of [TOKEN.slice(0, 1), TOKEN.slice(0, TOKEN.length - 1), `${TOKEN}x`]) {
      const res = await login(supplied);
      assert.equal(res.status, 401, `"${supplied.slice(0, 12)}…" was accepted`);
      assert.equal(res.headers.get('set-cookie'), null, 'and it must not hand out a session');
    }
    assert.equal((await login(TOKEN)).status, 204, 'the real token must still work');
  } finally {
    srv.close();
  }
});

/*
  /api/me answers with the caller's own member row, and the row holds their
  token. It is their own token, so this is a smaller thing than the /api/state
  leak beside it — but the rule is "tokens are never sent to the browser", and
  it was pinned in one of the two places that had to keep it.
*/
test('the identity route does not hand back a token either', async () => {
  const [a] = roster().map(m => m.name);
  const me = await (await asMember(a, '/api/me')).json();
  assert.equal(me.member.name, a, 'the fixture must be signed in as somebody');
  assert.ok(!('token' in me.member), 'a visible token is a usable one');
  const token = db.prepare('select token from members where name = ?').get(a).token;
  assert.ok(!JSON.stringify(me).includes(token), 'the token reached the browser by another field');
});
