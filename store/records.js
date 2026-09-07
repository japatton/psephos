import { newId, nowIso } from '../lib/ids.js';
import { parseEventTime } from '../lib/time.js';
import { resolveHost, normalizeIp } from './hosts.js';
import { writeAudit } from './audit.js';

/**
 * The 18 columns, in the order they appear in the analyst workbooks. Kept
 * verbatim so CSV export round-trips with what the team already maintains.
 */
export const COLUMNS = [
  'event_id', 'event_time', 'hostname', 'source_ip', 'destination_ip', 'user',
  'indicator', 'command', 'pid', 'sha256', 'description', 'misp',
  'evidence_source', 'confidence', 'triage_status', 'analyst_notes', 'mitre', 'reference',
];

/** Human-facing headers, positionally aligned with COLUMNS. */
export const HEADERS = [
  'Event ID', 'Event Time', 'Hostname', 'Source IP', 'Destination IP', 'User',
  'Indicator (Process Name/Executable)', 'Command', 'PID', 'SHA256 / Hash',
  'Description/Justification', 'MISP (When applicable) or File Contents',
  'Evidence Source', 'Confidence', 'Triage Status', 'Analyst Notes',
  'MITRE ATT&CK', 'Reference',
];

const blankToNull = (v) => {
  if (v == null) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
};

export function getRecord(db, id) {
  return db.prepare('select * from records where id = ?').get(id);
}

/**
 * File an observation. Time is parsed into a tier, and every address it
 * mentions is resolved against terrain — creating discovered hosts as needed —
 * so the map and timeline never need a separate ingest step.
 */
export function createRecord(db, fields = {}, { sessionId = null, analyst = null, state = 'pending', threadId = null } = {}) {
  const id = newId();
  const values = COLUMNS.map(c => blankToNull(fields[c]));
  // One clock reading, used both as the row's timestamp and as the fallback
  // position for an event the analyst dated but did not time.
  const recordedAt = nowIso();
  const { iso, tier } = parseEventTime(fields.event_time, { recordedAt });

  db.prepare(`insert into records
    (id, session_id, thread_id, ${COLUMNS.join(', ')},
     state, time_parsed, time_tier, created_by, created_at)
    values (?,?,?,${COLUMNS.map(() => '?').join(',')},?,?,?,?,?)`)
    .run(id, sessionId, threadId, ...values, state, iso, tier, analyst, recordedAt);

  /*
    Attach the record to terrain and REMEMBER which host it landed on.
    Discarding this was the root cause of a rootkit finding rendering on two
    different servers: with nothing stored, the association was re-derived by
    string matching on every render, and two hosts are legitimately named "Web".
    resolveHost returns null when the name is ambiguous, which leaves the
    record visibly unbound rather than confidently wrong.
  */
  const hostId = resolveHost(db, { hostname: fields.hostname, ip: fields.source_ip });
  if (hostId) db.prepare('update records set host_id = ? where id = ?').run(hostId, id);
  resolveHost(db, { ip: fields.destination_ip });

  return getRecord(db, id);
}

/** Bind a record to a host by hand, when the name could not decide. */
export function bindRecordHost(db, id, hostId, { reason = null, analyst = null } = {}) {
  const before = getRecord(db, id);
  if (!before) throw new Error(`no such record: ${id}`);
  if (hostId && !db.prepare('select 1 from hosts where id = ?').get(hostId)) {
    throw new Error('no such host');
  }
  db.prepare('update records set host_id = ?, host_bound_by = ? where id = ?')
    .run(hostId ?? null, hostId ? analyst : null, id);
  writeAudit(db, {
    analyst, action: 'record.bind', targetType: 'record', targetId: id,
    before: { host_id: before.host_id },
    after: { host_id: hostId ?? null, reason },
  });
  return getRecord(db, id);
}

/**
 * Findings, minus the ones the team has retired.
 *
 * Archived rows are excluded by default rather than by each reader
 * remembering to. Everything downstream — the map, the timeline, the exports,
 * the case file the model is shown — reads through here, and a filter that has
 * to be opted into is one somebody forgets.
 */
export function listRecords(db, { state, hostname, threadId, from, to, includeArchived = false } = {}) {
  const where = [];
  const args = [];
  if (!includeArchived) where.push('archived_at is null');
  if (state) { where.push('state = ?'); args.push(state); }
  if (hostname) { where.push('hostname = ?'); args.push(hostname); }
  if (threadId) { where.push('thread_id = ?'); args.push(threadId); }
  if (from) { where.push('time_parsed >= ?'); args.push(from); }
  if (to) { where.push('time_parsed <= ?'); args.push(to); }
  const sql = `select * from records${where.length ? ' where ' + where.join(' and ') : ''}
               order by (time_parsed is null), time_parsed, created_at`;
  return db.prepare(sql).all(...args);
}

/*
  The columns the browser searched, kept in the same order it concatenated them.

  One deliberate difference: the client joined these into a single string and
  matched a substring across the whole of it, so a query could span a field
  boundary. That is matched here per field instead. The only queries that change
  behaviour are ones that straddle two fields, which nobody means to type.
*/
const SEARCHABLE = [
  'description', 'hostname', 'indicator', 'command', 'analyst_notes',
  'mitre', 'source_ip', 'destination_ip', 'user',
];

/*
  LIKE reads % and _ as wildcards, so a literal "95%" would match every row and
  a pipe named a_b would match a-b. A search that quietly over-matches is worse
  than one that finds nothing: it looks like it worked.
*/
const likeLiteral = (q) => `%${String(q).replace(/[\\%_]/g, c => `\\${c}`)}%`;

/**
 * Records matching a query, as one page plus the size of the whole match.
 *
 * The total is separate from the page on purpose. "Showing 50 of 3,412" is the
 * number an analyst needs to know whether to narrow the query; a page length
 * alone cannot say whether anything was left out.
 */
export function searchRecords(db, {
  q = '', state = null, threadId = null, hostname = null, confidence = null,
  from = null, to = null, includeArchived = false,
  limit = null, offset = 0,
} = {}) {
  const where = [];
  const args = [];
  if (!includeArchived) where.push('archived_at is null');
  if (state) { where.push('state = ?'); args.push(state); }
  if (threadId) { where.push('thread_id = ?'); args.push(threadId); }
  if (hostname) { where.push('hostname = ?'); args.push(hostname); }
  if (confidence) { where.push('confidence = ?'); args.push(confidence); }
  if (from) { where.push('time_parsed >= ?'); args.push(from); }
  if (to) { where.push('time_parsed <= ?'); args.push(to); }

  const needle = String(q ?? '').trim();
  if (needle) {
    where.push(`(${SEARCHABLE.map(c => `${c} like ? escape '\\'`).join(' or ')})`);
    for (let i = 0; i < SEARCHABLE.length; i++) args.push(likeLiteral(needle));
  }

  const clause = where.length ? ` where ${where.join(' and ')}` : '';
  const total = db.prepare(`select count(*) n from records${clause}`).get(...args).n;

  // The same ordering listRecords uses, so a page and the full list agree about
  // what comes first.
  let sql = `select * from records${clause}
             order by (time_parsed is null), time_parsed, created_at`;
  const pageArgs = [...args];
  if (limit != null) {
    sql += ' limit ? offset ?';
    pageArgs.push(Number(limit), Number(offset) || 0);
  }
  return { rows: db.prepare(sql).all(...pageArgs), total };
}

/**
 * The fields the browser needs before it opens anything.
 *
 * bootstrap() hands every record to every client on load, and — since a client
 * now re-fetches on reconnect — on every recovered connection too. Half of a
 * record by weight is prose no view renders until somebody opens the drawer:
 * the analyst's notes, the command line, the hash. Measured at 2,000 findings,
 * sending the whole row costs 2.24 MB and this projection costs 1.11 MB.
 *
 * Derived from what the views read, not from what looks unimportant. The
 * pending rail and the host drawer both render `description`, which is why the
 * largest text column stays: dropping it would have been the obvious saving and
 * would have emptied two panels. `record-search.test.js` pins the list against
 * the views so a newly rendered field fails there rather than rendering blank.
 *
 * The drawer fetches the whole row from GET /api/records/:id when it opens one,
 * which is the only place the rest is wanted.
 */
export const SUMMARY_FIELDS = [
  'id', 'state', 'thread_id', 'host_id', 'hostname', 'source_ip', 'destination_ip',
  'time_parsed', 'time_tier', 'event_time', 'archived_at',
  'description', 'indicator', 'mitre', 'confidence', 'created_by',
];

/** The same records listRecords returns, projected to SUMMARY_FIELDS. */
export const listRecordSummaries = (db, opts = {}) =>
  listRecords(db, opts).map(r => Object.fromEntries(SUMMARY_FIELDS.map(f => [f, r[f] ?? null])));

/*
  How many findings touch each host.

  This is the only thing the Network Map wanted the whole records array for, and
  therefore the only reason the bootstrap payload grew with the case file rather
  than with the estate. Computed here instead, and what goes back is one number
  per host that carries evidence.

  Reading every record to do it is fine and deliberate: the cost being removed is
  the payload, not the arithmetic. At ten thousand findings the whole pass is
  tens of milliseconds in process, against megabytes over the wire to every
  browser on every load and every reconnect.

  The rule is transcribed from the browser rather than reinvented, including the
  part that looks like an omission: a bare hostname counts only when the record
  is not already bound, and only on an exact match. Short names were deliberately
  excluded after two hosts called "Web" each showed a finding belonging to one of
  them. test/evidence-index.test.js pins this against that same algorithm.
*/
export function evidenceByHost(db, hosts = [], filters = {}) {
  const byIp = new Map();
  const byName = new Map();
  const push = (m, k, id) => { if (k) m.set(k, [...(m.get(k) ?? []), id]); };
  for (const h of hosts) {
    push(byIp, h.ip, h.id);
    push(byName, String(h.name ?? '').toLowerCase(), h.id);
  }

  const counts = new Map();
  for (const r of searchRecords(db, filters).rows) {
    // Denied findings are off the map; denying is what takes them off it.
    if (r.state === 'denied') continue;
    const touched = new Set();
    if (r.host_id) touched.add(r.host_id);
    for (const ip of [ipIn(r.source_ip), ipIn(r.destination_ip)]) {
      for (const id of byIp.get(ip) ?? []) touched.add(id);
    }
    if (!r.host_id) {
      for (const id of byName.get(String(r.hostname ?? '').toLowerCase()) ?? []) touched.add(id);
    }
    for (const id of touched) counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  return Object.fromEntries(counts);
}

/**
 * The findings that touch one host, by the same rule evidenceByHost counts by.
 *
 * The host drawer used to filter the whole records array for this. Doing it here
 * is what lets that array stop being shipped, and keeping the rule in one place
 * is what stops the badge on a node and the list inside its drawer disagreeing —
 * which they did once, for exactly that reason.
 */
export function recordsForHost(db, hosts, host, filters = {}) {
  if (!host) return [];
  const name = String(host.name ?? '').toLowerCase();
  return searchRecords(db, filters).rows.filter((r) => {
    if (r.state === 'denied') return false;
    if (r.host_id === host.id) return true;
    if (host.ip && (ipIn(r.source_ip) === host.ip || ipIn(r.destination_ip) === host.ip)) return true;
    // Placed elsewhere; a bare name must not claim it back.
    if (r.host_id) return false;
    const hn = String(r.hostname ?? '').toLowerCase();
    return Boolean(name) && Boolean(hn) && hn === name;
  });
}

/**
 * Findings nothing can place, so the map can offer to bind them by hand.
 *
 * Bounded in practice by how many the team has not yet dealt with rather than by
 * the size of the case file, but capped anyway: a thousand unplaceable findings
 * is a collection problem, and shipping all of them to draw a list nobody can
 * read would be the same mistake in a smaller place.
 */
export function unplacedRecords(db, hosts, { limit = 200 } = {}) {
  const byIp = new Set(hosts.map(h => h.ip).filter(Boolean));
  const byName = new Set(hosts.map(h => String(h.name ?? '').toLowerCase()).filter(Boolean));
  const out = [];
  for (const r of searchRecords(db, {}).rows) {
    if (r.host_id || r.state === 'denied') continue;
    if (byIp.has(ipIn(r.source_ip)) || byIp.has(ipIn(r.destination_ip))) continue;
    if (byName.has(String(r.hostname ?? '').toLowerCase())) continue;
    out.push(r);
    if (out.length >= limit) break;
  }
  return out;
}

/** Counts the shell needs without the rows behind them. */
export const recordCounts = (db) => db.prepare(`
  select
    count(*) filter (where state = 'pending')                     as pending,
    count(*) filter (where state = 'filed')                       as filed,
    count(*) filter (where time_parsed is null and state <> 'denied') as unplaceable,
    count(*)                                                      as total
  from records where archived_at is null`).get();

/** An address embedded in a field that may also carry a port. */
const ipIn = (v) => {
  if (!v) return null;
  const m = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(String(v));
  return m ? m[1] : null;
};

const EDITABLE = new Set([...COLUMNS, 'thread_id']);

export function updateRecord(db, id, patch = {}, analyst = null) {
  const before = getRecord(db, id);
  if (!before) throw new Error(`no such record: ${id}`);

  const keys = Object.keys(patch).filter(k => EDITABLE.has(k));
  if (keys.length === 0) return before;

  db.prepare(`update records set ${keys.map(k => `${k} = ?`).join(', ')} where id = ?`)
    .run(...keys.map(k => blankToNull(patch[k])), id);

  // Re-derive position if the analyst corrected the time.
  if (keys.includes('event_time')) {
    // Against when the record was written, not now — a correction made days
    // later must not drag the event onto today.
    const { iso, tier } = parseEventTime(patch.event_time, { recordedAt: before.created_at });
    db.prepare('update records set time_parsed = ?, time_tier = ? where id = ?').run(iso, tier, id);
  }
  /*
    Re-bind when the analyst corrects what the binding was derived from.

    resolveHost was already called here, for its side effect of discovering the
    host, and its answer was thrown away — so a finding corrected from
    ControlThings to EX-WS-1 stayed bound to ControlThings. host_id says which
    host a finding is ABOUT, and the correction is the analyst saying it is
    about a different one; leaving the old binding put the same finding on two
    servers, which is the failure host_id was introduced to end.

    A hand-binding is left alone. bindRecordHost exists for the cases a name
    could not settle, and re-deriving would overrule the person who settled it.

    A correction that resolves to nothing — a name now ambiguous across two
    hosts — clears the binding rather than keeping the stale one. The record
    surfaces in the bind-by-hand list, which is true, where "still about the
    host you just corrected away from" is not.
  */
  if (keys.includes('hostname') || keys.includes('source_ip')) {
    const hostId = resolveHost(db,
      { hostname: patch.hostname ?? before.hostname, ip: patch.source_ip ?? before.source_ip });
    if (!before.host_bound_by) {
      db.prepare('update records set host_id = ? where id = ?').run(hostId ?? null, id);
    }
  }
  if (keys.includes('destination_ip')) resolveHost(db, { ip: patch.destination_ip });

  const after = getRecord(db, id);
  writeAudit(db, {
    analyst, action: 'record.update', targetType: 'record', targetId: id,
    before: Object.fromEntries(keys.map(k => [k, before[k]])),
    after: Object.fromEntries(keys.map(k => [k, after[k]])),
  });
  return after;
}

function setState(db, id, state, analyst, action) {
  const before = getRecord(db, id);
  if (!before) throw new Error(`no such record: ${id}`);
  db.prepare('update records set state = ?, adjudicated_by = ?, adjudicated_at = ? where id = ?')
    .run(state, analyst ?? null, nowIso(), id);
  const after = getRecord(db, id);
  writeAudit(db, {
    analyst, action, targetType: 'record', targetId: id,
    before: { state: before.state }, after: { state: after.state },
  });
  return after;
}

export const promoteRecord = (db, id, analyst) => setState(db, id, 'filed', analyst, 'record.promote');
export const denyRecord = (db, id, analyst) => setState(db, id, 'denied', analyst, 'record.deny');

export const listArchivedRecords = (db) => db.prepare(
  'select * from records where archived_at is not null order by archived_at desc').all();

/**
 * Retire a finding from the working views.
 *
 * Deliberately separate from denying. Denying says the evidence did not show
 * what it appeared to; archiving says the team is finished with it either way.
 * A confirmed finding can be archived once it is written up, and a denied one
 * can stay visible as long as somebody still wants to see it — this does not
 * decide that for them.
 */
export function archiveRecord(db, id, { actor = null, reason = null } = {}) {
  const before = getRecord(db, id);
  if (!before) throw new Error(`no such record: ${id}`);
  if (before.archived_at) return before;
  db.prepare('update records set archived_at = ?, archived_by = ? where id = ?')
    .run(nowIso(), actor, id);
  writeAudit(db, {
    analyst: actor, action: 'record.archive', targetType: 'record', targetId: id,
    before: { state: before.state, hostname: before.hostname },
    after: { archived: true, reason },
  });
  return getRecord(db, id);
}

export function restoreRecord(db, id, { actor = null } = {}) {
  const before = getRecord(db, id);
  if (!before) throw new Error(`no such record: ${id}`);
  if (!before.archived_at) return before;
  db.prepare('update records set archived_at = null, archived_by = null where id = ?').run(id);
  writeAudit(db, {
    analyst: actor, action: 'record.restore', targetType: 'record', targetId: id,
    before: { archived_at: before.archived_at }, after: { archived: false },
  });
  return getRecord(db, id);
}

/**
 * Host-to-host connections implied by the evidence. Deliberately computed on
 * read rather than stored, so the graph can never drift from the records that
 * justify it. Denied records are excluded — a denial should remove its edge.
 */
export function derivedConnections(db) {
  const rows = db.prepare(`select source_ip, destination_ip from records
    where source_ip is not null and destination_ip is not null
      and state <> 'denied' and archived_at is null`).all();

  const counts = new Map();
  for (const r of rows) {
    const src = normalizeIp(r.source_ip);
    const dst = normalizeIp(r.destination_ip);
    if (!src || !dst || src === dst) continue;
    const key = `${src}\u0000${dst}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts].map(([key, count]) => {
    const [src, dst] = key.split('\u0000');
    return { src, dst, count };
  });
}
