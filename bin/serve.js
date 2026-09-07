#!/usr/bin/env node
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { networkInterfaces } from 'node:os';

import { openDb, initSchema } from '../store/db.js';
import { listMembers } from '../store/members.js';
import { LIVE_PLAN } from '../store/plan-file.js';
import { seedAll } from '../store/seed.js';
import { activeMissionName, readMission } from '../store/mission.js';
import { modelBanner } from '../store/model-config.js';
import { loadOrCreateToken } from '../server/auth.js';
import { createServer } from '../server/http.js';
import { closeAll } from '../server/sse.js';
import { setDbPath, killAllTurns, awaitTurnsExit } from '../claude/runner.js';
import { backupIfChanged } from '../store/backup.js';

const PORT = Number(process.env.HUNT_PORT || 8787);
const HOST = process.env.HUNT_HOST || '0.0.0.0';
const DB_PATH = resolve(process.env.HUNT_DB || 'data/hunt.db');
// 0 disables. The plan has kept rolling backups since it was written; the store
// holds the entire engagement and kept none.
const BACKUP_MINUTES = Number(process.env.HUNT_BACKUP_MINUTES ?? 30);
const BACKUP_KEEP = Number(process.env.HUNT_BACKUP_KEEP ?? 20);

mkdirSync(dirname(DB_PATH), { recursive: true });

/*
  No mission means no terrain, and seeding an empty estate would take every
  host off the map along with the verdicts recorded against them. So rather
  than guess a profile, the server comes up in setup mode: it serves the wizard
  and nothing else until the wizard names one.

  runtime is mutable because the wizard flips it when it finishes, so the same
  process starts serving the application without a restart.
*/
const runtime = { setup: !activeMissionName() };
const mission = runtime.setup ? null : readMission();

const db = openDb(DB_PATH);
initSchema(db);
setDbPath(DB_PATH);

// The team edits the plan through the UI, so the live copy lives in data/
// (gitignored) and the profile's plan.json is only ever the seed.
const boot = runtime.setup ? null : seedAll(db);
if (boot?.stale) {
  console.log(`\n  recovered   ${boot.stale} session(s) left mid-turn by the last run`);
}

const { token, created } = loadOrCreateToken();
const server = createServer({ db, token, runtime });

server.listen(PORT, HOST, () => {
  const lan = Object.values(networkInterfaces()).flat()
    .filter(i => i && i.family === 'IPv4' && !i.internal).map(i => i.address);

  console.log('');
  console.log('  Psephos');
  if (runtime.setup) {
    console.log('  setup      no mission yet — open the address below and follow the wizard');
  } else {
    console.log(`  mission    ${mission.name}${mission.week ? `  ·  ${mission.week}` : ''}`);
  }
  console.log(`  local      http://127.0.0.1:${PORT}`);
  for (const a of lan) console.log(`  lan        http://${a}:${PORT}`);
  console.log(`  store      ${DB_PATH}`);
  console.log(`  model      ${modelBanner()}`);
  console.log('');
  console.log(`  operator   ${token}`);
  console.log(`             ${created ? 'generated now, saved to .hunt-token' : 'from .hunt-token'}`);
  console.log('');

  if (runtime.setup) {
    console.log('  Sign in with the operator token above. There is no team yet, so it is the');
    console.log('  only way in — which is the point: the console proves who is at the keyboard.');
    console.log('');
  } else {
    if (boot.plan.imported) {
      console.log(`  plan       ${boot.plan.imported} tasks (${boot.plan.period || boot.plan.version})`);
      console.log(`             ${LIVE_PLAN}${boot.seeded.seeded
        ? `  (seeded from ${mission.name})` : '  (live, edited in the UI)'}\n`);
    }
    console.log('  Team tokens — each person logs in with their own:');
    let team = null;
    for (const m of listMembers(db)) {
      if (m.team !== team) { team = m.team; console.log(`    ${team}`); }
      console.log(`      ${m.token}   ${m.name.padEnd(9)} ${m.role}`);
    }
    if (boot.newMembers) {
      console.log(`\n  ${boot.newMembers} member(s) and ${boot.newSessions} chat(s) created this start.`);
    }
    console.log('');
  }

  if (HOST !== '127.0.0.1' && lan.length) {
    console.log('  This server is reachable from the LAN. Anyone with the token can read');
    console.log('  every unreviewed finding and spend your Claude quota. Bind to loopback');
    console.log('  with HUNT_HOST=127.0.0.1 if you did not mean to share it.');
    console.log('');
  }
});

/*
  Snapshot on a timer and again on the way out.

  backupIfChanged rather than a bare interval: a timer that fires regardless
  fills the directory with identical copies and prunes the one interesting
  snapshot out the back of the retention window. unref so a quiet server still
  exits when asked.
*/
const backupState = {};
const snapshot = (label) => {
  try {
    return backupIfChanged(db, { dbPath: DB_PATH, label, keep: BACKUP_KEEP }, backupState);
  } catch (e) {
    // Never take the server down over a backup. A hunt in progress matters
    // more than the snapshot, and the console is where the operator will see
    // that the safety net is not there.
    console.error(`  backup failed: ${e.message}`);
    return null;
  }
};

if (BACKUP_MINUTES > 0) {
  setInterval(() => snapshot('auto'), BACKUP_MINUTES * 60_000).unref();
}

let leaving = false;
const shutdown = async () => {
  if (leaving) return;          // a second ^C must not race the first one out
  leaving = true;
  /*
    Turns first, and before the snapshot.

    A turn's subprocess holds its own connection to the case file through the
    MCP server it spawns, so one still running while the process exits is a
    model writing findings into a store the operator believes is closed — and a
    snapshot taken around it captures a half-written moment. Stopping them first
    makes the backup a picture of a settled store.

    And WAITING for them is what makes that true. killAllTurns sends SIGTERM
    and escalates to SIGKILL after a grace period, but this used to exit from
    server.close()'s callback — about a millisecond later — so the escalation
    never ran and the snapshot was taken while the children were still alive.
    A CLI that traps SIGTERM outlived the server every time.
  */
  const stopped = killAllTurns();
  if (stopped) {
    console.log(`  stopped ${stopped} turn${stopped === 1 ? '' : 's'} still running`);
    const left = await awaitTurnsExit();
    if (left) console.error(`  ${left} did not stop; exiting anyway`);
  }
  if (BACKUP_MINUTES > 0) snapshot('shutdown');
  closeAll();
  server.close(() => { try { db.close(); } catch { /* already closed */ } process.exit(0); });
  setTimeout(() => process.exit(0), 2000).unref();
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
