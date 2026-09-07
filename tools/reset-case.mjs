/**
 * Clear the case file for a fresh start, keeping the terrain and the plan.
 *
 *   node tools/reset-case.mjs --dry-run     show what would go, change nothing
 *   node tools/reset-case.mjs               back up, then clear
 *   node tools/reset-case.mjs --keep-progress   leave hunt plan progress alone
 *
 * WIPED   findings and their links, hunt session transcripts, team chat,
 *         uploaded files, the adjudication audit log, and (unless
 *         --keep-progress) hunt plan completion state and history.
 *
 * KEPT    the network map and every host on it, activity threads, the team
 *         roster and their tokens, and the hunt plan itself.
 *
 * A timestamped copy of the database is written before anything is deleted.
 * This is irreversible otherwise, and "we meant the other week's data" is a
 * sentence somebody says eventually.
 */
import { copyFileSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { openDb, initSchema } from '../store/db.js';
import { listMembers } from '../store/members.js';
import { ensureMemberSessions } from '../store/sessions.js';
import { ensureTeamChannel } from '../store/chat.js';

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const keepProgress = args.includes('--keep-progress');
const dbPath = resolve(process.env.HUNT_DB || 'data/hunt.db');

if (!existsSync(dbPath)) {
  console.error(`no store at ${dbPath}`);
  process.exit(1);
}

const WIPE = [
  ['edges', 'links between findings'],
  ['records', 'findings'],
  ['messages', 'hunt session transcripts'],
  ['sessions', 'hunt sessions'],
  ['chat_messages', 'team chat messages'],
  ['channel_members', 'channel membership'],
  ['channel_reads', 'read markers'],
  ['channels', 'chat channels'],
  ['files', 'uploaded files'],
  ['audit', 'adjudication audit log'],
];
const PROGRESS = [
  ['task_events', 'hunt plan history'],
  ['task_state', 'hunt plan completion state'],
  ['task_assignees', 'hunt plan assignments'],
];
const KEEP = [
  ['hosts', 'network map'],
  ['threads', 'activity threads'],
  ['members', 'roster and tokens'],
  ['plan_tasks', 'hunt plan'],
];

const db = openDb(dbPath);
initSchema(db);
const count = (t) => db.prepare(`select count(*) n from ${t}`).get().n;

const targets = keepProgress ? WIPE : [...WIPE, ...PROGRESS];

console.log(`\nstore  ${dbPath}  (${(statSync(dbPath).size / 1048576).toFixed(1)} MB)\n`);
console.log('  WIPE');
for (const [t, label] of targets) console.log(`    ${String(count(t)).padStart(5)}  ${label}`);
console.log('\n  KEEP');
for (const [t, label] of KEEP) console.log(`    ${String(count(t)).padStart(5)}  ${label}`);
if (keepProgress) {
  console.log('\n  KEEP (--keep-progress)');
  for (const [t, label] of PROGRESS) console.log(`    ${String(count(t)).padStart(5)}  ${label}`);
}

if (dryRun) {
  console.log('\n  --dry-run: nothing was changed.\n');
  process.exit(0);
}

// Back up before the first delete, not after.
const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const backupDir = join(dirname(dbPath), 'backups');
mkdirSync(backupDir, { recursive: true });
const backup = join(backupDir, `hunt-${stamp}.db`);
// WAL mode keeps recent writes outside the main file, so checkpoint first or
// the copy can be missing the very rows somebody wants back.
db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
copyFileSync(dbPath, backup);
console.log(`\n  backup   ${backup}`);

// Children before parents: edges reference records, messages reference
// sessions, chat_messages reference channels and files.
db.exec('PRAGMA foreign_keys = OFF');
for (const [t] of targets) db.exec(`delete from ${t}`);
db.exec('PRAGMA foreign_keys = ON');

// Anything the team needs on day one comes straight back.
const members = listMembers(db);
const sessions = ensureMemberSessions(db, members);
ensureTeamChannel(db);
db.exec('VACUUM');

console.log(`  restored ${sessions} member chats and the team channel`);
console.log(`  store is now ${(statSync(dbPath).size / 1048576).toFixed(1)} MB\n`);
for (const [t, label] of KEEP) console.log(`  kept  ${String(count(t)).padStart(5)}  ${label}`);
console.log('');
