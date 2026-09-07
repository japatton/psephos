import { test } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/*
  Which engagement the server is running. Everything downstream — terrain, the
  roster, the plan seed, the threads, the prompt — resolves through here, and
  the cost of resolving it wrongly is the map: seeding reconciles, so a server
  pointed at the wrong profile removes every host the wrong terrain does not
  mention, along with the verdicts recorded against them.

  Paths resolve at import, so they are redirected into a scratch directory
  before the module loads. Nothing here touches the real profiles.
*/
const DIR = mkdtempSync(join(tmpdir(), 'hunt-mission-'));
const MISSIONS = join(DIR, 'missions');
mkdirSync(MISSIONS, { recursive: true });
mkdirSync(join(DIR, 'data'), { recursive: true });

process.env.HUNT_MISSIONS = MISSIONS;
process.env.HUNT_MISSION_FILE = join(DIR, 'data', 'mission');
delete process.env.HUNT_MISSION;

const {
  MISSIONS_DIR, POINTER, listMissions, activeMissionName, setActiveMission,
  missionDir, missionPaths, readJson, missionName, readMission,
} = await import('../store/mission.js');

process.on('exit', () => rmSync(DIR, { recursive: true, force: true }));

const makeProfile = (code, meta = {}) => {
  const dir = join(MISSIONS, code);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'mission.json'),
    JSON.stringify({ name: meta.name ?? code, code, ...meta }), 'utf8');
  return dir;
};

const clearActive = () => {
  delete process.env.HUNT_MISSION;
  try { rmSync(POINTER, { force: true }); } catch { /* not there */ }
};

// --- discovery -------------------------------------------------------------------

test('a directory without mission.json is not a profile', () => {
  mkdirSync(join(MISSIONS, 'not-a-profile'), { recursive: true });
  makeProfile('alpha');
  assert.deepEqual(listMissions(), ['alpha']);
});

test('profiles are listed in a stable order', () => {
  makeProfile('zulu');
  makeProfile('bravo');
  assert.deepEqual(listMissions(), ['alpha', 'bravo', 'zulu']);
});

// --- selection --------------------------------------------------------------------

test('with nothing selected there is no active mission', () => {
  clearActive();
  assert.equal(activeMissionName(), null);
});

test('selecting a mission writes the pointer, and it survives a reread', () => {
  clearActive();
  assert.equal(setActiveMission('bravo'), 'bravo');
  assert.equal(readFileSync(POINTER, 'utf8').trim(), 'bravo');
  assert.equal(activeMissionName(), 'bravo');
});

test('a mission that does not exist cannot be selected', () => {
  assert.throws(() => setActiveMission('nonexistent'), /no mission profile called/);
});

test('the environment overrides the pointer, so one run can be redirected', () => {
  clearActive();
  setActiveMission('bravo');
  process.env.HUNT_MISSION = 'alpha';
  try {
    assert.equal(activeMissionName(), 'alpha');
  } finally {
    delete process.env.HUNT_MISSION;
  }
  assert.equal(activeMissionName(), 'bravo', 'and the pointer is untouched by it');
});

test('a blank pointer or a blank override counts as nothing selected', () => {
  clearActive();
  writeFileSync(POINTER, '\n', 'utf8');
  assert.equal(activeMissionName(), null);
  process.env.HUNT_MISSION = '   ';
  try {
    assert.equal(activeMissionName(), null);
  } finally {
    delete process.env.HUNT_MISSION;
  }
});

// --- resolution ----------------------------------------------------------------------

/*
  Refusing beats defaulting. A default would silently pick a profile nobody
  chose, and the server would then re-seed against the wrong terrain.
*/
test('with no mission selected, resolving refuses and says how to choose', () => {
  clearActive();
  assert.throws(() => missionDir(), /No mission selected/);
  assert.throws(() => missionPaths(), /No mission selected/);
});

test('the refusal lists what is actually on disk', () => {
  clearActive();
  assert.throws(() => missionDir(), /alpha, bravo, zulu/);
});

test('a selected profile resolves to its five files', () => {
  clearActive();
  setActiveMission('alpha');
  const p = missionPaths();
  assert.equal(p.dir, join(MISSIONS, 'alpha'));
  for (const k of ['meta', 'terrain', 'plan', 'roster', 'threads']) {
    assert.ok(p[k].startsWith(p.dir), `${k} must live inside the profile`);
  }
  assert.ok(p.meta.endsWith('mission.json'));
  assert.ok(p.threads.endsWith('threads.json'), 'threads are mission data too');
});

test('a name that exists but has no mission.json is refused by name', () => {
  clearActive();
  assert.throws(() => missionDir('not-a-profile'), /has no mission\.json/);
});

/*
  setActiveMission only writes a name that already exists, and the wizard
  validates before creating one — but HUNT_MISSION comes from the environment
  and data/mission is a text file someone can edit.
*/
test('a name that would escape the missions directory is refused', () => {
  for (const bad of ['../../etc', '..', 'a/b', 'a\\b', '', '.hidden', 'x'.repeat(70)]) {
    assert.throws(() => missionDir(bad), /not a usable mission name|No mission selected/,
      `${JSON.stringify(bad)} was allowed`);
  }
});

test('an ordinary name with dots, dashes and underscores is fine', () => {
  makeProfile('xkc-41.9_wk2');
  assert.doesNotThrow(() => missionDir('xkc-41.9_wk2'));
});

// --- reading ---------------------------------------------------------------------------

test('the mission name comes back with the profile it was read from', () => {
  clearActive();
  makeProfile('charlie', { name: 'Charlie Engagement', week: 'Week 3' });
  setActiveMission('charlie');
  const m = readMission();
  assert.equal(m.name, 'Charlie Engagement');
  assert.equal(m.week, 'Week 3');
  assert.equal(m.name_, undefined);
});

/*
  missionName feeds text the model reads. A tool description is not worth
  failing a module load over, so it must never throw — which is exactly what it
  did when it was interpolated into a module-level const before any mission
  existed, making the whole MCP server unloadable during setup.
*/
test('the mission name never throws, however broken the state', () => {
  clearActive();
  assert.equal(missionName(), 'this engagement', 'with nothing selected');

  process.env.HUNT_MISSION = 'nonexistent';
  try {
    assert.equal(missionName(), 'this engagement', 'with a name that resolves to nothing');
  } finally {
    delete process.env.HUNT_MISSION;
  }

  makeProfile('broken');
  writeFileSync(join(MISSIONS, 'broken', 'mission.json'), '{ not json', 'utf8');
  process.env.HUNT_MISSION = 'broken';
  try {
    assert.equal(missionName(), 'this engagement', 'with unparseable metadata');
  } finally {
    delete process.env.HUNT_MISSION;
  }
});

test('a UTF-8 BOM does not stop a profile file being read', () => {
  const dir = makeProfile('bommed');
  writeFileSync(join(dir, 'mission.json'),
    '﻿' + JSON.stringify({ name: 'Bommed', code: 'bommed' }), 'utf8');
  // PowerShell's Set-Content -Encoding UTF8 writes one, and JSON.parse rejects
  // it with a message that never mentions the BOM.
  assert.equal(readJson(join(dir, 'mission.json')).name, 'Bommed');
});

test('MISSIONS_DIR and POINTER are absolute, so cwd cannot move them', () => {
  assert.ok(MISSIONS_DIR.length > 1 && !MISSIONS_DIR.startsWith('.'));
  assert.ok(POINTER.length > 1 && !POINTER.startsWith('.'));
});
