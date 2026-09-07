/**
 * Snapshots of the case file, taken while the server runs.
 *
 * The plan has been protected since it was written — plan-file.js keeps a
 * rolling backup on every write — and the store, which holds every record,
 * verdict, message and audit row, was not. The asymmetry is the argument: a few
 * kilobytes of task state had a safety net and the engagement did not.
 *
 * VACUUM INTO rather than copying the file, for the reason tools/backup-db.mjs
 * gives at length: WAL keeps recent writes in a sidecar, so copying hunt.db
 * captures whatever had been checkpointed and silently leaves the rest. What
 * this writes is one file with everything committed at the moment it ran.
 */
import { readdirSync, statSync, unlinkSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
import { join, dirname } from 'node:path';

export const backupDir = (dbPath) => join(dirname(dbPath), 'backups');

/** Only what this tool writes: <label>-<ISO seconds>.db */
const MINE = /^[\w.-]+-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.db$/;

const LABEL = /^[\w.-]+$/;

/**
 * Take one snapshot and prune the directory back to `keep`.
 *
 * @returns {{path:string,size:number,kept:number,pruned:number}}
 */
export function takeBackup(db, { dbPath, label = 'auto', keep = 20 } = {}) {
  if (!LABEL.test(label)) throw new Error('a backup label goes in a filename');
  if (!Number.isInteger(keep) || keep < 1) throw new Error('keep needs a whole number');

  const dir = backupDir(dbPath);
  mkdirSync(dir, { recursive: true });

  // Seconds, not milliseconds: two backups inside one second is a mistake worth
  // overwriting rather than two files nobody can tell apart.
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const path = join(dir, `${label}-${stamp}.db`);
  /*
    VACUUM INTO refuses an existing target, so a second snapshot inside the same
    second fails with "output file already exists" rather than doing the
    overwrite the seconds-resolution stamp implies. Two backups one second apart
    are the same backup; the later one wins.
  */
  if (existsSync(path)) unlinkSync(path);
  db.exec(`vacuum into '${path.replace(/'/g, "''")}'`);
  // A copy of the store is the store: same tokens, same DMs, same bytes.
  try { chmodSync(path, 0o600); } catch { /* not ours to tighten */ }

  /*
    Prune only what this tool wrote. A file somebody put here by hand, or an
    older tool's copy under its own naming, is a deliberate safety copy — and
    in this repository's own history one of those was the only surviving record
    of ten findings.
  */
  const mine = readdirSync(dir)
    .filter(f => MINE.test(f))
    .map(f => ({ f, at: statSync(join(dir, f)).mtimeMs }))
    .sort((a, b) => b.at - a.at);

  const doomed = mine.slice(keep);
  for (const d of doomed) unlinkSync(join(dir, d.f));

  return {
    path,
    size: statSync(path).size,
    kept: Math.min(mine.length, keep),
    pruned: doomed.length,
  };
}

/**
 * Take one only if something has been written since the last.
 *
 * A timer that fires regardless fills the directory with identical copies and
 * prunes the one interesting snapshot out the back of the window. The question
 * worth asking on a schedule is not whether time has passed but whether
 * anything happened.
 *
 * `total_changes` counts rows written on this connection since it opened, which
 * is exactly the span a running server cares about. `state` is the caller's to
 * hold, so this stays a function rather than a module with a memory.
 */
export function backupIfChanged(db, opts, state = {}) {
  const changes = db.prepare('select total_changes() as n').get().n;
  if (state.lastChanges === changes) return null;
  const out = takeBackup(db, opts);
  state.lastChanges = changes;
  return out;
}
