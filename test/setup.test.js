import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync, existsSync, mkdirSync, cpSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

/*
  A whole server, standing up a mission the way an operator would.

  Everything is redirected into a scratch directory first: missions, the
  mission pointer and the model config all resolve at import, so the paths have
  to be set before anything is loaded. Nothing here touches the real profiles.
*/
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIR = mkdtempSync(join(tmpdir(), 'huntsetup-'));
mkdirSync(join(DIR, 'missions'), { recursive: true });
mkdirSync(join(DIR, 'data'), { recursive: true });
// savePlan can copy the example, so the example has to be reachable.
cpSync(join(ROOT, 'missions', 'example'), join(DIR, 'missions', 'example'), { recursive: true });

process.env.HUNT_MISSIONS = join(DIR, 'missions');
process.env.HUNT_MISSION_FILE = join(DIR, 'data', 'mission');
process.env.HUNT_MODEL_CONFIG = join(DIR, 'data', 'model.json');
process.env.HUNT_PLAN = join(DIR, 'data', 'plan.json');
delete process.env.HUNT_MISSION;   // test/_env.js sets it; setup mode needs it unset

const { readJson } = await import('../store/mission.js');
const { openDb, initSchema } = await import('../store/db.js');
const { createServer } = await import('../server/http.js');
const { activeMissionName, listMissions } = await import('../store/mission.js');
const { listMembers } = await import('../store/members.js');
const { listHosts } = await import('../store/hosts.js');

const TOKEN = 'operator-token-for-the-test';
let base;
let server;
let db;
let runtime;

const call = (path, body) => fetch(base + path, {
  method: body ? 'POST' : 'GET',
  headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
  body: body ? JSON.stringify(body) : undefined,
});

before(async () => {
  db = openDb(':memory:');
  initSchema(db);
  runtime = { setup: true };
  server = createServer({ db, token: TOKEN, runtime });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server?.close();
  rmSync(DIR, { recursive: true, force: true });
});

test('with no mission the server is in setup mode', () => {
  assert.equal(activeMissionName(), null);
  assert.equal(runtime.setup, true);
});

test('setup mode serves the wizard and refuses the application', async () => {
  const page = await call('/');
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Psephos — setup/);

  // A client that asks for real data must be told plainly, not handed an empty
  // estate it would render as a network with nothing in it.
  const state = await call('/api/state');
  assert.equal(state.status, 503);
  assert.equal((await state.json()).setup, true);
});

test('setup mode still needs the operator token', async () => {
  const res = await fetch(base + '/api/setup/state');
  assert.equal(res.status, 401);
});

/*
  A member token is not an operator token, and setup mode is where that matters
  most: /api/setup/model persists a backend every later turn posts the whole
  case-file prompt to.

  The gate was "any valid token", justified by there being no roster yet in
  setup mode. That holds for a fresh install and not for the case that bites: a
  store restored from a backup, or a lost data/mission, opens the wizard over a
  full roster. So the roster is seeded here, which is exactly the state the
  original reasoning assumed away.
*/
test('a team token cannot drive the setup wizard', async () => {
  // Written straight in, because that is how the roster gets here: restored
  // with the store, while the mission pointer that decides setup mode did not
  // come back with it.
  db.prepare(`insert into members (id, name, role, team, token, created_at)
              values ('m1','Okafor','Analyst','Bravo','member-token-8','2026-09-01T00:00:00Z')`).run();
  const m = db.prepare('select * from members limit 1').get();
  const asMember = (path, init = {}) => fetch(base + path, {
    ...init,
    headers: { authorization: `Bearer ${m.token}`, 'content-type': 'application/json' },
  });

  assert.equal((await asMember('/api/setup/state')).status, 403);
  const model = await asMember('/api/setup/model', {
    method: 'POST',
    body: JSON.stringify({ provider: 'openai', baseUrl: 'http://127.0.0.1:1/v1', key: 'k' }),
  });
  assert.equal(model.status, 403, 'an analyst repointed the model backend');
  db.exec('delete from members');
});

test('the wizard reports what is done, so a reopened tab resumes', async () => {
  const s = await (await call('/api/setup/state')).json();
  assert.deepEqual(s.providers, ['cli', 'anthropic', 'openai']);
  assert.equal(s.done.mission, false);
  assert.equal(s.missions.includes('example'), true);
});

// --- walking the steps ----------------------------------------------------------

test('a mission is created from its name', async () => {
  const out = await (await call('/api/setup/mission', {
    name: 'Northern Watch 27-1', week: 'Week 1', briefing: ['4625 is not collected'],
  })).json();
  assert.equal(out.code, 'northern-watch-27-1');
  assert.ok(existsSync(join(DIR, 'missions', 'northern-watch-27-1', 'mission.json')));

  const s = await (await call('/api/setup/state?code=northern-watch-27-1')).json();
  assert.equal(s.done.mission, true);
  assert.equal(s.done.roster, false);
});

/*
  The wizard derives the directory name from the mission name, so two different
  engagements whose names slugify the same land on one profile. Writing
  mission.json over a finished profile renames somebody else's engagement, and
  the next server started against it seeds the wrong terrain — which is the
  failure the whole mission-pointer design exists to prevent.
*/
test('a mission cannot be created on top of a finished profile', async () => {
  const path = join(DIR, 'missions', 'example', 'mission.json');
  const before = readJson(path);

  const res = await call('/api/setup/mission', { name: 'Example', week: 'clobber' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /already/i);

  assert.deepEqual(readJson(path), before, 'the finished profile was overwritten');
});

/*
  The other half of that rule: an unfinished profile is the operator's own
  half-done setup, and going back a step to fix a typo has to keep working.
  Refusing every existing directory would break the resume this file documents.
*/
test('but an unfinished profile can still be re-saved, so going back a step works', async () => {
  const res = await call('/api/setup/mission', {
    name: 'Northern Watch 27-1', week: 'Week 2', briefing: ['corrected'],
  });
  assert.equal(res.status, 200);
  const m = readJson(join(DIR, 'missions', 'northern-watch-27-1', 'mission.json'));
  assert.equal(m.week, 'Week 2', 'the correction did not land');
});

test('a mission code cannot escape the missions directory', async () => {
  const res = await call('/api/setup/roster', {
    code: '../../etc', members: [{ name: 'x' }],
  });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /lower-case letters/);
});

test('the roster refuses two people with the same name', async () => {
  const res = await call('/api/setup/roster', {
    code: 'northern-watch-27-1',
    members: [{ name: 'Reyes', role: 'Lead', team: 'A' }, { name: 'reyes', role: 'Analyst', team: 'A' }],
  });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /names must be distinct/);
});

test('an empty roster is refused rather than producing a server nobody can log into', async () => {
  const res = await call('/api/setup/roster', { code: 'northern-watch-27-1', members: [] });
  assert.equal(res.status, 400);
});

test('the roster is written in the order it was given', async () => {
  const out = await (await call('/api/setup/roster', {
    code: 'northern-watch-27-1',
    members: [
      { name: 'Reyes', role: 'Mission Commander', team: 'Command' },
      { name: 'Okafor', role: 'Host Analyst', team: 'Bravo' },
      { name: '', role: 'ignored', team: 'blank rows are dropped' },
    ],
  })).json();
  assert.equal(out.members, 2);
  const written = JSON.parse(readFileSync(
    join(DIR, 'missions', 'northern-watch-27-1', 'roster.json'), 'utf8'));
  assert.deepEqual(written.members.map(m => m.name), ['Reyes', 'Okafor']);
});

test('terrain that is not terrain is refused', async () => {
  const res = await call('/api/setup/terrain', {
    code: 'northern-watch-27-1', terrain: { hosts: ['a', 'b'] },
  });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /enclaves/);
});

test('terrain is written and counted', async () => {
  const out = await (await call('/api/setup/terrain', {
    code: 'northern-watch-27-1',
    terrain: {
      source: 'test', vantages: [], enclaves: [{
        key: 'corp', name: 'Corp', cidr: '10.0.0.0/8', segments: [{
          name: 'servers', cidr: '10.0.1.0/24', hosts: [
            { name: 'NW-DC', ip: '10.0.1.10', os: 'Windows Server', role: 'DC' },
            { name: 'NW-FILE', ip: '10.0.1.11', os: 'Windows Server', role: 'File' },
          ],
        }],
      }],
    },
  })).json();
  assert.equal(out.hosts, 2);
  assert.equal(out.enclaves, 1);
});

/*
  The doctrinal frame is the reason plans/mission-phases.mjs is tracked code
  rather than mission data: Phase 0 through 4 with tactical objectives and MOEs
  is doctrine, and every engagement should be able to start from it. Before
  this option existed a new mission could only start from four example tasks.
*/
test('a mission can start from the CPT doctrinal frame', async () => {
  const code = 'doctrine-check';
  await call('/api/setup/mission', { name: 'Doctrine Check', week: '' });
  await call('/api/setup/roster', { code, members: [{ name: 'Reyes', role: 'Lead', team: 'A' }] });
  await call('/api/setup/terrain/empty', { code });

  const out = await (await call('/api/setup/plan', { code, from: 'doctrine' })).json();
  assert.ok(out.tasks >= 40, `expected the full frame, got ${out.tasks}`);

  const plan = readJson(join(DIR, 'missions', code, 'plan.json'));
  assert.deepEqual(plan.phases.map(p => p.key), ['M0', 'M1N', 'M1H', 'M1V', 'M2', 'M3', 'M4']);
  assert.ok(plan.phases.every(p => p.intent && p.intent.length > 40),
    'every phase says what it is for');
  const judged = plan.phases.filter(p => /Tactical Objective|MOE/.test(p.intent));
  assert.ok(judged.length >= 4, 'and the doctrinal ones carry how they are judged');

  const tasks = plan.phases.flatMap(p => p.tasks ?? []);
  assert.ok(tasks.every(t => t.key && t.title && (t.steps ?? []).length > 0),
    'every task carries steps, which is the invariant the plan view relies on');
});

/*
  The frame used to name this exercise's hosts in its terrain hints, which made
  it useless anywhere else. A category says more than a hostname anyway.
*/
test('the doctrinal frame names no engagement in particular', async () => {
  const plan = readJson(join(DIR, 'missions', 'doctrine-check', 'plan.json'));
  const blob = JSON.stringify(plan);
  /*
    Checked as shapes rather than as a list of one engagement's values, so the
    guard keeps working for whoever uses this next and names nothing itself.
    APT29 and APT33 are allowed through: they are real, publicly documented
    actors and the tradecraft is reusable. What must not appear is an estate —
    addresses, FQDNs, or a named host.
  */
  assert.doesNotMatch(blob, /\d{1,3}(\.\d{1,3}){3}/, 'the frame names an address');
  assert.doesNotMatch(blob, /[a-z0-9-]+\.(com|mil|local|test|net|org)/i, 'the frame names a domain');
  const hints = plan.phases.flatMap(p => p.tasks ?? []).flatMap(t => t.terrain ?? []);
  assert.ok(hints.includes('domain controllers'), 'and says what kind of host instead');
});

test('finishing before every step is done says which one is missing', async () => {
  const res = await call('/api/setup/finish', { code: 'northern-watch-27-1' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /plan\.json/);
});

/*
  The whole point of the wizard: it ends with a running application, in the
  same process, without asking the operator to remember a restart at the moment
  they know least about the system.
*/
test('finishing seeds the store and takes the server out of setup mode', async () => {
  await call('/api/setup/plan', { code: 'northern-watch-27-1', from: 'example' });

  const out = await (await call('/api/setup/finish', { code: 'northern-watch-27-1' })).json();
  assert.equal(out.code, 'northern-watch-27-1');
  assert.equal(out.members, 2);
  assert.ok(out.tasks > 0);

  assert.equal(runtime.setup, false, 'the application is live');
  assert.equal(activeMissionName(), 'northern-watch-27-1');
  assert.deepEqual(listMembers(db).map(m => m.name).sort(), ['Okafor', 'Reyes']);
  assert.equal(listHosts(db).length, 2);
  assert.ok(listMembers(db).every(m => m.token && m.token.length === 8), 'tokens were generated');
});

test('and the application answers where setup used to', async () => {
  const state = await (await call('/api/state')).json();
  assert.equal(state.hosts.length, 2);
  assert.equal(state.members.length, 2);
  assert.ok(state.members.every(m => !('token' in m)), 'still no tokens to the browser');

  const page = await call('/');
  assert.doesNotMatch(await page.text(), /Psephos — setup/);
});

test('a new profile sits alongside the others, not on top of one', () => {
  assert.deepEqual(listMissions().sort(),
    ['doctrine-check', 'example', 'northern-watch-27-1']);
});

// --- reading an inventory --------------------------------------------------------

test('a model reply wrapped in prose or a fence still parses', async () => {
  const { parseJsonReply } = await import('../server/setup.js');
  assert.deepEqual(parseJsonReply('```json\n{"a":1}\n```'), { a: 1 });
  assert.deepEqual(parseJsonReply('Here you go:\n{"a":1}\nHope that helps.'), { a: 1 });
  assert.equal(parseJsonReply('I could not do that'), null);
  assert.equal(parseJsonReply('{ broken'), null);
});

/*
  The wizard's own upload path is the one the generic advice cannot help.

  /api/setup/terrain re-posts the operator's terrain.json as JSON, and the
  structure step exists to take a pasted inventory dump — so "attach it as a
  file instead" told the operator to do the thing they had just done, and a
  large estate dead-ended there. Four megabytes, the same ceiling a turn has.
*/
test('a large inventory reaches the wizard, and the refusal above that is followable', async () => {
  // About the ceiling, not about terrain's own shape: what mattered was that a
  // real estate's inventory was refused before the handler ever saw it.
  // (Re-entered deliberately — the finish test above takes the server out of
  // setup mode, and these routes only exist inside it.)
  runtime.setup = true;
  const body = (n) => ({ code: 'x', terrain: { enclaves: [], filler: 'h'.repeat(n) } });

  const under = await call('/api/setup/terrain', body(2_000_000));
  assert.notEqual(under.status, 413, 'a two-megabyte inventory was refused as too large');

  const over = await call('/api/setup/terrain', body(5_000_000));
  assert.equal(over.status, 413);
  const { error } = await over.json();
  assert.doesNotMatch(error, /Attach it as a file/,
    'the refusal advises the path the operator is already on');
  assert.match(error, /Split the inventory|after setup/);
  runtime.setup = false;
});
