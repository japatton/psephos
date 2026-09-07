/**
 * Take a consistent copy of the case file before doing something to it.
 *
 *   node tools/backup-db.mjs <label> [--keep 20]
 *
 * Uses VACUUM INTO rather than copying the file, which matters more than it
 * sounds. SQLite in WAL mode keeps recent writes in a sidecar, so `cp hunt.db`
 * captures whatever had been checkpointed and silently leaves the rest behind
 * — three of the backups already on disk have stray -wal and -shm files beside
 * them, which is what that looks like afterwards. VACUUM INTO writes a single
 * self-contained database with everything committed at the moment it runs.
 *
 * Prunes oldest-first, because a directory that grows without limit is a
 * backup strategy that eventually fills the disk during an exercise.
 */
import { DatabaseSync } from 'node:sqlite';
import { takeBackup } from '../store/backup.js';

const args = process.argv.slice(2);
const label = args.find(a => !a.startsWith('--')) ?? 'manual';
const keep = args.includes('--keep') ? Number(args[args.indexOf('--keep') + 1]) : 20;

const dbPath = process.env.HUNT_DB || 'data/hunt.db';
const db = new DatabaseSync(dbPath);
let out;
try {
  out = takeBackup(db, { dbPath, label, keep });
} catch (e) {
  console.error(`  ${e.message}`);
  process.exit(1);
} finally {
  db.close();
}
console.log(`  ${out.path}  (${(out.size / 1048576).toFixed(1)} MB)`);
console.log(`  ${out.kept} backup(s) from this tool kept, ${out.pruned} pruned`);
