import { chmodSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { snapshotLabel, uniqueLabel } from '../lib/snapshot-name.js';

/**
 * Open the store. WAL because the access pattern is many readers (browsers
 * polling state, SSE clients) against a single writer (this process).
 *
 * Owner-only, because of what is in it. The operator token file is created
 * 0600 and the model config is chmodded again after its atomic rename, and
 * this — every member's token in plaintext, every DM body, every uploaded
 * file's bytes, the whole case file — was left at whatever the umask said, and
 * on a shared host that is world-readable. Any other local account could read
 * the tokens and sign in as any analyst.
 *
 * Done before the first write, so the WAL and shared-memory files SQLite
 * creates alongside it take their permissions from this one.
 */
export function openDb(path = 'data/hunt.db') {
  const db = new DatabaseSync(path);
  if (path !== ':memory:') {
    try { chmodSync(path, 0o600); } catch { /* not ours to tighten */ }
  }
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA busy_timeout = 5000');
  return db;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS threads (
  id            TEXT PRIMARY KEY,
  key           TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  assessed_cell TEXT,
  status        TEXT,
  color         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  ip         TEXT,
  enclave    TEXT,
  segment    TEXT,
  cidr       TEXT,
  os         TEXT,
  role       TEXT,
  source     TEXT NOT NULL CHECK (source IN ('seeded','discovered')),
  verdict    TEXT NOT NULL DEFAULT 'unknown'
             CHECK (verdict IN ('unknown','suspected','confirmed','cleared')),
  verdict_by TEXT,
  verdict_at TEXT,
  presence      TEXT NOT NULL DEFAULT 'unsurveyed',
  presence_note TEXT,
  domain_joined INTEGER,
  name_conflict TEXT,
  observed_from TEXT
);
CREATE INDEX IF NOT EXISTS hosts_ip ON hosts(ip);

CREATE TABLE IF NOT EXISTS members (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  role       TEXT NOT NULL,
  team       TEXT NOT NULL,
  token      TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id                TEXT PRIMARY KEY,
  title             TEXT NOT NULL,
  kind              TEXT NOT NULL CHECK (kind IN ('chat','intake')),
  analyst           TEXT,
  claude_session_id TEXT,
  state             TEXT NOT NULL DEFAULT 'open'
                    CHECK (state IN ('open','running','closed','error')),
  created_at        TEXT NOT NULL,
  member_id         TEXT REFERENCES members(id)
);

CREATE TABLE IF NOT EXISTS records (
  id              TEXT PRIMARY KEY,
  session_id      TEXT REFERENCES sessions(id),
  thread_id       TEXT REFERENCES threads(id),
  event_id        TEXT,
  event_time      TEXT,
  hostname        TEXT,
  source_ip       TEXT,
  destination_ip  TEXT,
  user            TEXT,
  indicator       TEXT,
  command         TEXT,
  pid             TEXT,
  sha256          TEXT,
  description     TEXT,
  misp            TEXT,
  evidence_source TEXT,
  confidence      TEXT,
  triage_status   TEXT,
  analyst_notes   TEXT,
  mitre           TEXT,
  reference       TEXT,
  state           TEXT NOT NULL DEFAULT 'pending'
                  CHECK (state IN ('pending','filed','denied')),
  time_parsed     TEXT,
  time_tier       TEXT NOT NULL DEFAULT 'unplaceable'
                  CHECK (time_tier IN ('exact','approximate','unplaceable')),
  created_by      TEXT,
  created_at      TEXT NOT NULL,
  adjudicated_by  TEXT,
  adjudicated_at  TEXT
);
CREATE INDEX IF NOT EXISTS records_state  ON records(state);
CREATE INDEX IF NOT EXISTS records_host   ON records(hostname);
CREATE INDEX IF NOT EXISTS records_time   ON records(time_parsed);
CREATE INDEX IF NOT EXISTS records_thread ON records(thread_id);

CREATE TABLE IF NOT EXISTS edges (
  id             TEXT PRIMARY KEY,
  src_record_id  TEXT NOT NULL REFERENCES records(id),
  dst_record_id  TEXT NOT NULL REFERENCES records(id),
  kind           TEXT NOT NULL CHECK (kind IN ('caused','preceded','same_actor')),
  status         TEXT NOT NULL DEFAULT 'proposed'
                 CHECK (status IN ('proposed','confirmed','denied')),
  rationale      TEXT,
  created_by     TEXT,
  created_at     TEXT NOT NULL,
  adjudicated_by TEXT,
  adjudicated_at TEXT
);

CREATE TABLE IF NOT EXISTS messages (
  id         TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  role       TEXT NOT NULL CHECK (role IN ('user','assistant','system','tool')),
  content    TEXT NOT NULL,
  ts         TEXT NOT NULL,
  -- Which button produced this turn. Evidence turns carry the case file and
  -- may file records; research turns do neither.
  mode       TEXT
);
CREATE INDEX IF NOT EXISTS messages_session ON messages(session_id, ts);

-- Static plan content. Re-imported wholesale when a revised plan is uploaded.
CREATE TABLE IF NOT EXISTS plan_tasks (
  id                TEXT PRIMARY KEY,
  plan_version      TEXT NOT NULL,
  phase_key         TEXT NOT NULL,
  phase_name        TEXT NOT NULL,
  phase_intent      TEXT,
  phase_source      TEXT,
  task_key          TEXT NOT NULL UNIQUE,
  title             TEXT NOT NULL,
  intent            TEXT,
  source            TEXT NOT NULL,
  steps_source      TEXT,
  priority          TEXT,
  team              TEXT,
  mitre             TEXT,
  tools             TEXT,
  data_sources      TEXT,
  commands          TEXT,
  terrain           TEXT,
  refs              TEXT,
  evidence_expected TEXT,
  analysis          TEXT,
  do_next           TEXT,
  steps             TEXT,
  original          TEXT,
  ord               INTEGER NOT NULL
);

-- Progress. Deliberately a separate table so re-importing a revised plan
-- never wipes what the team has already done.
CREATE TABLE IF NOT EXISTS task_state (
  task_key     TEXT PRIMARY KEY,
  status       TEXT NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending','in-progress','complete','blocked')),
  changed_by   TEXT,
  changed_at   TEXT,
  note         TEXT
);

CREATE TABLE IF NOT EXISTS task_assignees (
  task_key TEXT NOT NULL,
  member   TEXT NOT NULL,
  PRIMARY KEY (task_key, member)
);

-- Append-only. Anyone may complete or reset; every one of those is kept, so
-- "we reattacked this three times on Tuesday" is an answerable question.
CREATE TABLE IF NOT EXISTS task_events (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       TEXT NOT NULL,
  task_key TEXT NOT NULL,
  actor    TEXT,
  action   TEXT NOT NULL,
  detail   TEXT
);
CREATE INDEX IF NOT EXISTS task_events_task ON task_events(task_key, id);

-- Team communication. Separate from hunt sessions on purpose: a session is a
-- conversation with Claude that can produce records, a channel is people
-- talking to each other and produces nothing but its own history.
CREATE TABLE IF NOT EXISTS channels (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL CHECK (kind IN ('team','dm','group')),
  name       TEXT NOT NULL,
  created_by TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS channel_members (
  channel_id TEXT NOT NULL REFERENCES channels(id),
  member     TEXT NOT NULL,
  PRIMARY KEY (channel_id, member)
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id         TEXT PRIMARY KEY,
  channel_id TEXT NOT NULL REFERENCES channels(id),
  author     TEXT NOT NULL,
  body       TEXT NOT NULL,
  mentions   TEXT,
  file_id    TEXT REFERENCES files(id),
  ts         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chat_channel ON chat_messages(channel_id, ts);

CREATE TABLE IF NOT EXISTS channel_reads (
  channel_id TEXT NOT NULL,
  member     TEXT NOT NULL,
  last_read  TEXT NOT NULL,
  PRIMARY KEY (channel_id, member)
);

-- Uploaded files live in the store rather than on disk: one file to back up,
-- no path handling, and nothing on the filesystem for a LAN visitor to reach
-- by any route other than the API.
CREATE TABLE IF NOT EXISTS files (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  mime        TEXT,
  size        INTEGER NOT NULL,
  sha256      TEXT NOT NULL,
  body        BLOB NOT NULL,
  is_text     INTEGER NOT NULL DEFAULT 0,
  uploaded_by TEXT,
  uploaded_at TEXT NOT NULL
);

-- Characterization, in two levels.
--
-- A SNAPSHOT is a named collection run the analyst picks in the composer:
-- "Baseline · 24 Aug". An UPLOAD is one contribution to it — one host, one
-- paste. A paged collection is many uploads in one snapshot, which is the
-- whole point: treating each page as its own point in time reported rows as
-- appearing when they had only ever been on page two.
CREATE TABLE IF NOT EXISTS char_snapshots (
  id         TEXT PRIMARY KEY,
  label      TEXT NOT NULL,
  note       TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS char_uploads (
  id             TEXT PRIMARY KEY,
  snapshot_id    TEXT REFERENCES char_snapshots(id),
  repo           TEXT NOT NULL,
  host           TEXT,                      -- null means unattributed
  source_format  TEXT,                      -- what the model recognised
  file_id        TEXT,
  session_id     TEXT,
  analyst        TEXT,
  claimed_rows   INTEGER,                   -- what the model said the source had
  counted_rows   INTEGER,
  extracted_rows INTEGER,                   -- what actually reached char_entities
  status         TEXT NOT NULL DEFAULT 'ok'
                 CHECK (status IN ('ok','incomplete')),
  note           TEXT,
  ts             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS char_entities (
  id        TEXT PRIMARY KEY,
  upload_id TEXT NOT NULL REFERENCES char_uploads(id),
  repo      TEXT NOT NULL,
  host      TEXT,
  ident     TEXT NOT NULL,  -- normalised identity; a PID would churn on reboot
  label     TEXT NOT NULL,
  attrs     TEXT,           -- JSON
  ts        TEXT NOT NULL
);
-- Why a host is absent from a completed collection. The analyst's call, not
-- something the store can infer: missed, powered off, or unreachable because
-- somebody disabled the collection path are the same silence.
CREATE TABLE IF NOT EXISTS char_host_status (
  repo     TEXT NOT NULL,
  host     TEXT NOT NULL,
  reason   TEXT NOT NULL,
  note     TEXT,
  set_by   TEXT,
  set_at   TEXT NOT NULL,
  PRIMARY KEY (repo, host)
);

-- Fields a collection did not gather, acknowledged by the operator.
--
-- Different operators run different commands: one Get-ADUser returns
-- whenCreated and Enabled, the next does not. Comparing those two snapshots
-- reported 90 accounts as "changed" when nothing about them had changed at
-- all. A gap is a property of the RUN, not of each row, so it is acknowledged
-- once here and every row in that run is read through it.
CREATE TABLE IF NOT EXISTS char_field_gaps (
  snapshot_id TEXT NOT NULL REFERENCES char_snapshots(id),
  field       TEXT NOT NULL,
  note        TEXT,
  ack_by      TEXT,
  ack_at      TEXT NOT NULL,
  PRIMARY KEY (snapshot_id, field)
);

-- Somebody needs to know something: they were put on a task, or tagged in a
-- channel. Held per person rather than derived on read, because "assigned to
-- you since you last looked" cannot be recovered from the assignment table —
-- it only records who is on the task now, not when they were put there.
CREATE TABLE IF NOT EXISTS notifications (
  id      TEXT PRIMARY KEY,
  member  TEXT NOT NULL,          -- roster name it is for
  kind    TEXT NOT NULL,          -- 'assigned' | 'mention'
  title   TEXT NOT NULL,
  body    TEXT,
  link    TEXT,                   -- route to open
  actor   TEXT,                   -- who caused it
  ts      TEXT NOT NULL,
  read_at TEXT
);
CREATE INDEX IF NOT EXISTS notifications_inbox ON notifications(member, read_at, ts);

CREATE INDEX IF NOT EXISTS char_entities_lookup ON char_entities(repo, host, ident);
CREATE INDEX IF NOT EXISTS char_entities_upload ON char_entities(upload_id);

-- Fields corrected by hand, re-applied after every terrain re-seed. Only the
-- pinned field is held: correcting an enclave must not stop a later survey
-- correcting the OS.
CREATE TABLE IF NOT EXISTS host_overrides (
  host_id TEXT NOT NULL,
  field   TEXT NOT NULL,
  value   TEXT,
  was     TEXT,           -- what terrain said, so reverting has something to go back to
  set_by  TEXT,
  set_at  TEXT NOT NULL,
  PRIMARY KEY (host_id, field)
);

CREATE TABLE IF NOT EXISTS audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  analyst     TEXT,
  action      TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id   TEXT NOT NULL,
  before      TEXT,
  after       TEXT
);
`;

/**
 * Add a column to an existing table. CREATE TABLE IF NOT EXISTS does nothing
 * for a store that already holds data, so new columns need this or an
 * upgraded server reads a schema its database does not have.
 */
/** @returns true when it added the column, so a one-time backfill can key on it. */
function ensureColumn(db, table, name, decl) {
  const cols = db.prepare(`pragma table_info(${table})`).all().map(c => c.name);
  if (cols.includes(name)) return false;
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${decl}`);
  return true;
}

/**
 * Characterization used to call one upload a "snapshot". It is now one
 * contribution to a snapshot, because a paged collection arrives across
 * several uploads and treating each as its own point in time invented deltas
 * that never happened. Rename before the schema runs, or CREATE TABLE IF NOT
 * EXISTS sees the old table and silently leaves the wrong shape in place.
 */
function migrateCharSnapshotsToUploads(db) {
  const tables = db.prepare("select name from sqlite_master where type='table'").all().map(t => t.name);
  if (tables.includes('char_uploads') || !tables.includes('char_snapshots')) return;
  const cols = db.prepare('pragma table_info(char_snapshots)').all().map(c => c.name);
  if (!cols.includes('repo')) return;   // already the new shape

  db.exec('ALTER TABLE char_snapshots RENAME TO char_uploads');
  const ecols = db.prepare('pragma table_info(char_entities)').all().map(c => c.name);
  if (ecols.includes('snapshot_id') && !ecols.includes('upload_id')) {
    db.exec('ALTER TABLE char_entities RENAME COLUMN snapshot_id TO upload_id');
  }
}

/**
 * Give every collection run a repository, splitting the ones that spanned more
 * than one.
 *
 * Lossless, and it changes no comparison: a diff chain was already keyed on
 * (repo, host) and already skipped runs holding no data for that repository,
 * so one run covering accounts and scheduled-tasks was ALREADY behaving as two
 * where it mattered. This makes the storage say what the reads were doing.
 *
 * The operator's own label carried real meaning ("Nmap Scan - ICS Network")
 * and is kept as the note rather than thrown away. Runs holding nothing at all
 * have no repository to infer and are left alone; they are invisible to a
 * per-repository picker anyway, and guessing one from the label would invent a
 * baseline nobody collected.
 *
 * Idempotent: it only looks at runs whose repo is still null.
 */
function migrateSnapshotsToRepoScope(db) {
  const pending = db.prepare('select * from char_snapshots where repo is null').all();
  if (!pending.length) return;

  const reposOf = db.prepare('select distinct repo from char_uploads where snapshot_id = ? order by repo');
  const clone = db.prepare(`insert into char_snapshots
    (id, repo, label, note, created_by, created_at, completed_at, completed_by)
    values (?,?,?,?,?,?,?,?)`);
  const claim = db.prepare('update char_snapshots set repo = ?, label = ?, note = ? where id = ?');
  const move = db.prepare('update char_uploads set snapshot_id = ? where snapshot_id = ? and repo = ?');
  const taken = db.prepare('select 1 from char_snapshots where label = ? limit 1');
  const free = (l) => uniqueLabel(l, (c) => Boolean(taken.get(c)));

  db.exec('begin');
  try {
    for (const s of pending) {
      const repos = reposOf.all(s.id).map(r => r.repo).filter(Boolean);
      if (!repos.length) continue;             // an empty run; nothing to infer from
      const keep = repos[0];
      const note = s.note ? `${s.label} · ${s.note}` : s.label;
      claim.run(keep, free(snapshotLabel(keep, s.created_by, s.created_at)), note, s.id);
      for (const repo of repos.slice(1)) {
        const id = `${s.id}-${repo}`.slice(0, 64);
        clone.run(id, repo, free(snapshotLabel(repo, s.created_by, s.created_at)), note,
          s.created_by, s.created_at, s.completed_at ?? null, s.completed_by ?? null);
        move.run(id, s.id, repo);
      }
    }
    db.exec('commit');
  } catch (e) { db.exec('rollback'); throw e; }
}

export function initSchema(db) {
  migrateCharSnapshotsToUploads(db);
  db.exec(SCHEMA);
  // After ensureColumn, never inside SCHEMA: an index over a column the
  // migration has not added yet fails the whole schema apply. Same trap the
  // sessions_member index fell into.
  /*
    Which host a finding belongs to, stored rather than re-derived. The
    association used to be recomputed by string matching on every render, and
    with two seeded hosts both named "Web" one rootkit finding rendered on
    both of them.
  */
  ensureColumn(db, 'records', 'host_id', 'TEXT');
  /*
    What a turn cost, beside what it said. Nullable on purpose: a user message
    costs nothing to store and a turn whose provider reported no usage has an
    unknown cost, which is not the same as zero and must not average like it.
  */
  ensureColumn(db, 'messages', 'input_tokens', 'INTEGER');
  ensureColumn(db, 'messages', 'output_tokens', 'INTEGER');
  ensureColumn(db, 'messages', 'cost_usd', 'REAL');
  ensureColumn(db, 'messages', 'duration_ms', 'INTEGER');
  ensureColumn(db, 'messages', 'model', 'TEXT');
  /*
    Retired from the working views without being destroyed. Denying a finding
    is the adjudication — it was not what we thought. Archiving is the
    housekeeping that follows: the team is done with it, and it should stop
    occupying the map, the timeline and the case file the model is shown.
  */
  ensureColumn(db, 'records', 'archived_at', 'TEXT');
  ensureColumn(db, 'records', 'archived_by', 'TEXT');
  ensureColumn(db, 'records', 'host_bound_by', 'TEXT');
  ensureColumn(db, 'hosts', 'created_by', 'TEXT');
  /*
    Taken off the map without being destroyed. A host that exists only because
    a finding named it, where the analyst has since investigated and denied
    that finding, cannot be removed — the denied record still points at it —
    but it must stop appearing as though something is known about it.
  */
  ensureColumn(db, 'hosts', 'archived_at', 'TEXT');
  ensureColumn(db, 'hosts', 'archived_by', 'TEXT');
  // Reverting a pinned field has to put something back. The row itself no
  // longer holds the terrain value — the override overwrote it — so the value
  // displaced at pin time is kept alongside.
  ensureColumn(db, 'host_overrides', 'was', 'TEXT');
  ensureColumn(db, 'char_uploads', 'snapshot_id', 'TEXT');
  // Coverage is only meaningful once a collection has finished: five hosts
  // uploaded of ten planned is indistinguishable from five that did not answer.
  /*
    A collection run belongs to ONE repository. It used to span all of them,
    so every repository's picker listed all twenty runs whether or not they
    held a single row of its data — processes had data in two. Operators
    compensated by typing the repository into the label by hand, differently
    each time.
  */
  ensureColumn(db, 'char_snapshots', 'repo', 'TEXT');
  ensureColumn(db, 'char_snapshots', 'completed_at', 'TEXT');
  ensureColumn(db, 'char_snapshots', 'completed_by', 'TEXT');
  // A manual correction carries rows but must never make a host count as
  // having reported, or moving one row would strand the other forty-six.
  ensureColumn(db, 'char_uploads', 'kind', "TEXT NOT NULL DEFAULT 'collection'");
  /*
    Staged imports are invisible to every baseline read until committed.

    The backfill runs ONLY on the migration that adds the column, which is what
    "everything that already exists predates staging" actually means. Written
    unguarded it ran at every boot, and every import an analyst had staged for
    review was committed into the live baseline by the next restart — the
    review queue emptied, discardStaged unable to reach the rows, and no audit
    row to say a commit had happened. Staging decides what "normal" means for
    the whole estate; it cannot be undone by starting the server.
  */
  if (ensureColumn(db, 'char_uploads', 'committed_at', 'TEXT')) {
    db.exec('UPDATE char_uploads SET committed_at = ts WHERE committed_at IS NULL');
  }
  ensureColumn(db, 'char_entities', 'edited_by', 'TEXT');
  ensureColumn(db, 'char_entities', 'edited_at', 'TEXT');
  ensureColumn(db, 'char_entities', 'collected_attrs', 'TEXT');
  // How many rows the model handed over, as against how many survived
  // deduplication. Without both, a fold cannot be told from a loss.
  ensureColumn(db, 'char_uploads', 'returned_rows', 'INTEGER');
  db.exec('CREATE INDEX IF NOT EXISTS char_uploads_scope ON char_uploads(repo, host, snapshot_id)');
  migrateSnapshotsToRepoScope(db);

  // Migrations for stores created before a column existed.
  ensureColumn(db, 'hosts', 'presence', "TEXT NOT NULL DEFAULT 'unsurveyed'");
  ensureColumn(db, 'hosts', 'presence_note', 'TEXT');
  ensureColumn(db, 'hosts', 'domain_joined', 'INTEGER');
  ensureColumn(db, 'hosts', 'name_conflict', 'TEXT');
  ensureColumn(db, 'hosts', 'observed_from', 'TEXT');
  ensureColumn(db, 'sessions', 'member_id', 'TEXT');
  ensureColumn(db, 'messages', 'mode', 'TEXT');
  // Provenance for plan tasks written through the UI rather than imported.
  // Carried from the plan file on every re-import, like every other column.
  ensureColumn(db, 'plan_tasks', 'created_by', 'TEXT');
  ensureColumn(db, 'plan_tasks', 'created_at', 'TEXT');
  ensureColumn(db, 'plan_tasks', 'edited_by', 'TEXT');
  ensureColumn(db, 'plan_tasks', 'edited_at', 'TEXT');
  /*
    Which bank entry a task was drawn from. Null for a task somebody wrote
    here. plan_tasks is re-derived from the plan file at every startup, so this
    exists only to carry the file's bankId across that rebuild.
  */
  ensureColumn(db, 'plan_tasks', 'bank_id', 'TEXT');

  /*
    Whether the depth this task was drawn with was authored by somebody on the
    engagement or drafted from general practice. Null for a task nobody drew
    from the bank, and for a drawn stub, which has no depth to stand behind.
  */
  ensureColumn(db, 'plan_tasks', 'bank_provenance', 'TEXT');
  /*
    MITRE's own description, carried alongside a drawn stub's bankId. Set only
    when the task has no authored intent, so the two never occupy the same
    field — a stub's intent must read as empty, not as MITRE's prose wearing
    an analyst's byline.
  */
  ensureColumn(db, 'plan_tasks', 'bank_desc', 'TEXT');
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS sessions_member ON sessions(member_id)');

  // Rows that predate the column would otherwise read 'unsurveyed', which
  // understates what is known: a discovered host was named in evidence.
  // Only touches rows still carrying the default, so a survey result is
  // never overwritten.
  db.exec(`UPDATE hosts SET presence = 'evidence-only',
             presence_note = 'Named in evidence, not surveyed'
           WHERE source = 'discovered' AND presence = 'unsurveyed'`);
}
