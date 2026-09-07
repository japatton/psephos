import { newId, nowIso } from '../lib/ids.js';
import { terrainHosts } from '../terrain/load.js';
import { writeAudit } from './audit.js';

const IPV4 = /(\d{1,3}(?:\.\d{1,3}){3})/;

/** Analysts write "N/A", "Not collected", "-" and blanks. None of those identify a host. */
function clean(v) {
  if (v == null) return null;
  const s = String(v).trim();
  if (s === '' || s === '-' || /^n\s*\/\s*a\b/i.test(s) || /^not\s+(collected|recorded)/i.test(s)) return null;
  return s;
}

/** Pull the address out of "198.51.100.25:443" or "198.51.100.53 (web)". */
export function normalizeIp(v) {
  const s = clean(v);
  if (!s) return null;
  const m = IPV4.exec(s);
  if (!m) return null;
  return m[1].split('.').every(o => +o <= 255) ? m[1] : null;
}

/**
 * Load the terrain baseline.
 *
 * Keyed on name+address rather than address alone, because the source
 * inventory genuinely lists two hosts at one address (ControlThings and Sift
 * both at one address in a tooling segment). Deduplicating on address
 * would silently discard one of them; a hosts table that quietly loses an
 * entry is worse than one that reflects the inventory's own ambiguity.
 */
/**
 * The first label of a hostname — but an address has no labels to take.
 *
 * "10.20.10.2".split('.')[0] is "10", and seventeen terrain hosts are named
 * after addresses that begin 10. So an analyst filing evidence against a bare
 * address in that range hit ambiguous(), resolveHost refused to bind or create
 * anything, and the finding landed on nothing with no explanation. Seventeen
 * more collide on 100 and nine on 150.
 */
const shortName = (n) => {
  const s = String(n ?? '').trim();
  if (normalizeIp(s) === s) return s.toLowerCase();
  return s.split(/[.\s]/)[0].trim().toLowerCase();
};
/** "SITE-DC.example.test" -> ["site","dc"], so a role label can be found inside it. */
const tokensOf = (n) => shortName(n).split(/[-_]/).filter(Boolean);

/**
 * Load the terrain baseline, reconciling rather than appending.
 *
 * A survey rewrites the map: a DC moves from one address to another and gains
 * an FQDN. Matching only on exact name+address would treat that as a brand new
 * host and leave the stale one behind, so the table would grow a duplicate on
 * every survey and any verdict recorded against the old row would be stranded.
 *
 * So each terrain host claims an existing seeded row — by address, then by
 * short name — and is updated in place. The row keeps its id, which keeps its
 * audit history resolvable, and keeps its verdict, which is the analyst's call
 * and never the survey's. Seeded rows the terrain no longer mentions are
 * removed; anything an analyst judged is reported rather than silently
 * dropped.
 */
export function seedHosts(db, hosts = terrainHosts()) {
  const before = db.prepare("select * from hosts where source = 'seeded'").all();
  assertNotAShrink(before, hosts);
  const claimed = new Set();
  const orphanedVerdicts = [];

  /*
    One unit of work, the way mergeHosts already is.

    This runs on every start and rewrites the whole seeded estate: inserts,
    updates, a delete of absorbed rows with their records reassigned first, then
    the hand corrections laid back over the top. A throw anywhere in that —
    terrain naming a host the schema refuses, a row the driver cannot bind —
    used to leave the estate half-rebuilt, with records pointing at a host that
    had been deleted and overrides never reapplied. And it happens at boot, so
    the operator's first sight of it is a map that is wrong.
  */
  db.exec('begin');
  try {

    const ins = db.prepare(`insert into hosts
      (id, name, ip, enclave, segment, cidr, os, role, source,
       presence, presence_note, domain_joined, name_conflict, observed_from)
      values (?,?,?,?,?,?,?,?,'seeded',?,?,?,?,?)`);
    const upd = db.prepare(`update hosts set name = ?, ip = ?, enclave = ?, segment = ?,
      cidr = ?, os = ?, role = ?, presence = ?, presence_note = ?,
      domain_joined = ?, name_conflict = ?, observed_from = ? where id = ?`);

    for (const h of hosts) {
      const ip = normalizeIp(h.ip);
      const name = h.name || ip || 'unnamed';
      const cols = [
        name, ip, h.enclave || null, h.segment || null, h.cidr || null,
        h.os || null, h.role || null,
        h.presence || 'unsurveyed', h.presenceNote || '',
        h.domainJoined === null || h.domainJoined === undefined ? null : (h.domainJoined ? 1 : 0),
        h.nameConflict || null,
        h.observedFrom && h.observedFrom.length ? JSON.stringify(h.observedFrom) : null,
      ];

      // Address, then exact short name, then a token match inside the same
      // segment. The last one is what recognises a relocation that also gained
      // an FQDN: the inventory said "DC" at .2, the survey says
      // "SITE-DC.example.test" at a new one, and those share neither address
      // nor short name. Scoped to the segment so one enclave's DC cannot
      // claim another's.
      const free = (r) => !claimed.has(r.id);
      const sameSegment = (r) =>
        (h.cidr && r.cidr === h.cidr) || (h.segment && r.segment === h.segment && r.enclave === h.enclave);
      const short = shortName(name);
      const match =
        (ip && before.find(r => r.ip === ip && free(r))) ||
        before.find(r => shortName(r.name) && shortName(r.name) === short && free(r)) ||
        before.find(r => free(r) && sameSegment(r) && short && shortName(r.name) &&
          (tokensOf(name).includes(shortName(r.name)) || tokensOf(r.name).includes(short)));

      if (match) {
        claimed.add(match.id);
        upd.run(...cols, match.id);
      } else {
        ins.run(newId(), ...cols);
      }
    }

    for (const r of before) {
      if (claimed.has(r.id)) continue;
      if (r.verdict && r.verdict !== 'unknown') {
        orphanedVerdicts.push({ name: r.name, ip: r.ip, verdict: r.verdict, by: r.verdict_by });
      }
      db.prepare('delete from hosts where id = ?').run(r.id);
    }

    // A host the evidence found before the survey did is the same host. Fold it
    // into the seeded row rather than leaving one address on the map twice,
    // once as an anonymous discovery and once under its surveyed name.
    const absorbed = [];
    for (const d of db.prepare("select * from hosts where source = 'discovered'").all()) {
      if (!d.ip) continue;
      const seeded = db.prepare(
        "select * from hosts where ip = ? and source = 'seeded' limit 1").get(d.ip);
      if (!seeded) continue;
      if (d.verdict && d.verdict !== 'unknown' && seeded.verdict === 'unknown') {
        db.prepare('update hosts set verdict = ?, verdict_by = ?, verdict_at = ? where id = ?')
          .run(d.verdict, d.verdict_by, d.verdict_at, seeded.id);
      }
      // Anything bound to the discovered row follows it, exactly as a merge
      // would. Deleting the host out from under a binding would leave the
      // finding pointing at a row that no longer exists, so it would render on
      // no host at all.
      db.prepare('update records set host_id = ? where host_id = ?').run(seeded.id, d.id);
      db.prepare('delete from host_overrides where host_id = ?').run(d.id);
      db.prepare('delete from hosts where id = ?').run(d.id);
      absorbed.push({ ip: d.ip, was: d.name, now: seeded.name });
    }

    // Terrain has just rewritten every matched row, so lay the hand corrections
    // back over the top. Doing it here means no caller can forget.
    applyHostOverrides(db);
    const bound = bindUnplacedRecords(db);

    db.exec('commit');
    return { orphanedVerdicts, absorbed, bound };
  } catch (err) {
    // Leaving the transaction open would take every later write down with
    // it, and this runs at boot — the server would come up unable to store
    // anything, which is a worse failure than the one being rolled back.
    db.exec('rollback');
    throw err;
  }
}

/**
 * Refuse a re-seed that would empty the map.
 *
 * Seeding reconciles: a host terrain no longer mentions is removed, along with
 * any verdict recorded against it. That is right when a survey genuinely drops
 * a host, and catastrophic when the server was pointed at the wrong mission
 * profile — the whole estate disappears mid-exercise and there is nothing in
 * the UI to say why.
 *
 * So a re-seed that would take out most of an established estate stops and
 * says so. A real survey that really did lose half the network can still be
 * applied with HUNT_ALLOW_TERRAIN_SHRINK=1.
 */
const SHRINK_FLOOR = 10;      // below this the estate is too small to judge
const SHRINK_RATIO = 0.5;

function assertNotAShrink(before, hosts) {
  if (process.env.HUNT_ALLOW_TERRAIN_SHRINK === '1') return;
  if (before.length < SHRINK_FLOOR) return;
  if (hosts.length >= before.length * SHRINK_RATIO) return;
  throw new Error(
    `terrain lists ${hosts.length} host(s) but the map holds ${before.length}. ` +
    'Seeding would remove the difference and every verdict recorded against them. ' +
    'Check HUNT_MISSION points at the right profile. ' +
    'If the survey really did lose them, re-run with HUNT_ALLOW_TERRAIN_SHRINK=1.');
}

/**
 * Fields corrected by hand, laid back over the terrain after every re-seed.
 *
 * Only the pinned field is held. Correcting an enclave should not stop a later
 * survey correcting the OS, so this is per field rather than per host.
 */
export const OVERRIDABLE = ['name', 'ip', 'enclave', 'segment', 'cidr', 'os', 'role'];

export function setHostOverride(db, hostId, field, value, actor = null) {
  if (!OVERRIDABLE.includes(field)) throw new Error(`${field} cannot be overridden by hand`);
  const before = getHost(db, hostId);
  if (!before) throw new Error(`no such host: ${hostId}`);

  const existing = db.prepare(
    'select was from host_overrides where host_id = ? and field = ?').get(hostId, field);

  if (value == null || String(value).trim() === '') {
    /*
      Put the displaced value back. Clearing the row alone would leave the hand
      correction sitting in the hosts table until the next re-seed, so a revert
      appeared to do nothing — the pin chip vanished and the wrong value stayed.
      A discovered host has no terrain value, so `was` is null and the field
      simply empties, which is the truth for a host terrain never knew.
    */
    db.prepare('delete from host_overrides where host_id = ? and field = ?').run(hostId, field);
    if (existing) db.prepare(`update hosts set ${field} = ? where id = ?`).run(existing.was, hostId);
  } else {
    // Only the first pin records what terrain said. Re-pinning would otherwise
    // save the previous hand value and revert to that instead of to terrain.
    const was = existing ? existing.was : before[field];
    db.prepare(`insert into host_overrides (host_id, field, value, was, set_by, set_at) values (?,?,?,?,?,?)
      on conflict(host_id, field) do update set value = excluded.value,
        set_by = excluded.set_by, set_at = excluded.set_at`)
      .run(hostId, field, String(value).trim(), was, actor, nowIso());
  }
  applyHostOverrides(db);
  writeAudit(db, {
    analyst: actor, action: value == null ? 'host.override.clear' : 'host.override',
    targetType: 'host', targetId: hostId,
    before: { [field]: before[field] }, after: { [field]: value ?? '(back to terrain)' },
  });
  return getHost(db, hostId);
}

export const hostOverrides = (db, hostId) =>
  db.prepare('select * from host_overrides where host_id = ?').all(hostId);

/** Re-apply every pinned field. Called after any seed, which rewrites from terrain. */
export function applyHostOverrides(db) {
  let n = 0;
  for (const o of db.prepare('select * from host_overrides').all()) {
    if (!getHost(db, o.host_id)) continue;   // host is gone; the override is inert
    db.prepare(`update hosts set ${o.field} = ? where id = ?`).run(o.value, o.host_id);
    n++;
  }
  return n;
}

/**
 * The hosts every view works from.
 *
 * Archived ones are excluded by default rather than by each caller
 * remembering to: the whole point of archiving is that it stops appearing, and
 * a filter every reader has to opt into is one somebody will forget.
 */
export function listHosts(db, { includeArchived = false } = {}) {
  return db.prepare(`select * from hosts
    ${includeArchived ? '' : 'where archived_at is null'}
    order by enclave, segment, ip`).all();
}

export const listArchivedHosts = (db) => db.prepare(
  'select * from hosts where archived_at is not null order by archived_at desc').all();

/**
 * Hosts that exist only because of evidence nobody stands behind any more.
 *
 * Discovered rather than seeded, because a terrain host is real whatever its
 * findings turned out to be. No surviving record and no baseline row, because
 * either would mean the host is still carrying something. Denied records are
 * deliberately not counted: they are the reason this set exists.
 */
export function withdrawnHosts(db) {
  return db.prepare(`select h.* from hosts h
    where h.archived_at is null
      and h.source = 'discovered'
      and not exists (
        select 1 from records r where r.state <> 'denied' and r.archived_at is null and (
          r.host_id = h.id
          or (r.host_id is null and lower(r.hostname) = lower(h.name))
          or (h.ip is not null and (r.source_ip = h.ip or r.source_ip like h.ip || ':%'))
          or (h.ip is not null and (r.destination_ip = h.ip or r.destination_ip like h.ip || ':%'))))
      and not exists (select 1 from char_entities e where e.host = h.name)
    order by h.name`).all();
}

/**
 * Take a host off the map without destroying it.
 *
 * removeHost refuses these, correctly: the denied record still points at the
 * host and deleting it would orphan the record that explains why it was ever
 * there. Archiving keeps both, keeps the audit trail, and is reversible.
 */
export function archiveHost(db, hostId, { actor = null, reason = null } = {}) {
  const h = getHost(db, hostId);
  if (!h) throw new Error('no such host');
  if (h.archived_at) return h;
  db.prepare('update hosts set archived_at = ?, archived_by = ? where id = ?')
    .run(nowIso(), actor, hostId);
  writeAudit(db, {
    analyst: actor, action: 'host.archive', targetType: 'host', targetId: hostId,
    before: { name: h.name, ip: h.ip, verdict: h.verdict, presence: h.presence },
    after: { archived: true, reason },
  });
  return getHost(db, hostId);
}

/** Put it back, for when archiving turns out to have been the wrong call. */
export function restoreHost(db, hostId, { actor = null } = {}) {
  const h = getHost(db, hostId);
  if (!h) throw new Error('no such host');
  if (!h.archived_at) return h;
  db.prepare('update hosts set archived_at = null, archived_by = null where id = ?').run(hostId);
  writeAudit(db, {
    analyst: actor, action: 'host.restore', targetType: 'host', targetId: hostId,
    before: { archived_at: h.archived_at }, after: { archived: false },
  });
  return getHost(db, hostId);
}

export function getHost(db, id) {
  return db.prepare('select * from hosts where id = ?').get(id);
}

/**
 * Map an observation onto a host, inventing one when the terrain does not know
 * it. This is how an unmapped address — an internal exfil destination nobody
 * had in a reference table — becomes a visible node without anyone adding it
 * by hand.
 *
 * @returns {string|null} host id, or null when the input identifies nothing
 */
export function resolveHost(db, { hostname, ip } = {}) {
  /*
    An analyst filing against a bare address types it into the hostname field,
    because that is the field the form offers and the characterization row is
    keyed on it. It is still an address: treated as a name it would produce a
    host with no ip, which can never receive a connection on the map.
  */
  if (!normalizeIp(ip) && normalizeIp(clean(hostname))) ip = clean(hostname);

  const found = matchHost(db, { hostname, ip });
  if (found !== null) return found;

  const addr = normalizeIp(ip);
  const name = clean(hostname);
  if (!addr && !name) return null;
  if (ambiguous(db, name)) return null;

  // "Referenced in evidence" is a weaker claim than "answered on the wire",
  // so this deliberately does not say alive. Only the survey can say that.
  const id = newId();
  db.prepare(`insert into hosts (id, name, ip, source, presence, presence_note)
              values (?,?,?,'discovered','evidence-only',?)`)
    .run(id, name || addr, addr, 'Named in evidence, not surveyed');
  return id;
}

/** True when a short name answers for more than one host, so nothing may claim it. */
function ambiguous(db, name) {
  if (!name) return false;
  const short = shortName(name);
  const rows = db.prepare('select name from hosts').all();
  if (rows.some(r => r.name.toLowerCase() === name.toLowerCase())) return false;
  return rows.filter(r => shortName(r.name) === short).length > 1;
}

/**
 * Match an observation onto a host that already exists. Never invents one.
 *
 * This is the half of resolveHost the backfill needs: placing a record that
 * predates binding must not conjure the host it failed to find, which is
 * exactly how a sentence of prose became a host named after itself.
 *
 * @returns {string|null} host id, or null when nothing here identifies a host
 */
export function matchHost(db, { hostname, ip } = {}) {
  const addr = normalizeIp(ip);
  const name = clean(hostname);
  if (!addr && !name) return null;

  if (addr) {
    const row = db.prepare('select id from hosts where ip = ?').get(addr);
    if (row) return row.id;
  }
  if (name) {
    /*
      Compare short form to short form. Logs say "SITE-DC"; terrain stores
      "SITE-DC.example.test".

      But refuse to guess when the short form is ambiguous. Two seeded hosts
      are both called "Web", and picking whichever the table returned first put
      a rootkit finding on one of them when the record named the other. An
      unresolved host is recoverable; a confidently wrong one is not.
    */
    const short = shortName(name);
    const rows = db.prepare('select id, name, source from hosts').all();
    const exact = rows.filter(r => r.name.toLowerCase() === name.toLowerCase());
    if (exact.length === 1) return exact[0].id;

    const byShort = rows.filter(r => shortName(r.name) === short);
    if (byShort.length === 1) return byShort[0].id;
    if (byShort.length > 1) return null;   // ambiguous: bind it by hand
  }

  return null;
}

/**
 * Bind records that predate binding, or that a later survey has made placeable.
 *
 * Only the unambiguous: an address, or a name exactly one host answers to.
 * Anything else stays unbound and is shown as unbound, because guessing is the
 * behaviour that put one rootkit finding on two servers. A host arriving in a
 * later survey can place a record nothing could place before, so this runs
 * after every seed rather than once at migration time.
 *
 * @returns {number} records bound by this pass
 */
export function bindUnplacedRecords(db) {
  const rows = db.prepare(
    'select id, hostname, source_ip from records where host_id is null and archived_at is null').all();
  const upd = db.prepare('update records set host_id = ? where id = ?');
  let n = 0;
  for (const r of rows) {
    const id = matchHost(db, { hostname: r.hostname, ip: r.source_ip });
    if (!id) continue;
    upd.run(id, r.id);
    n++;
  }
  return n;
}

/** The only four values the map can render and the drawer can clear. */
export const VERDICTS = new Set(['confirmed', 'suspected', 'cleared', 'unknown']);

/**
 * Fold one host into another: its evidence follows, then it disappears.
 *
 * Refuses to merge AWAY a seeded host. Terrain would recreate it at the next
 * re-seed and the duplicate would be back, only now with its evidence pointing
 * somewhere else — worse than the state we started in.
 */
export function mergeHosts(db, fromId, intoId, { reason = null, actor = null } = {}) {
  const from = getHost(db, fromId);
  const into = getHost(db, intoId);
  if (!from) throw new Error('no such source host');
  if (!into) throw new Error('no such target host');
  if (fromId === intoId) throw new Error('a host cannot be merged into itself');
  if (from.source === 'seeded') {
    throw new Error(
      `${from.name} comes from terrain, so the next survey re-seed would recreate it and the ` +
      'evidence would be pointing elsewhere. Merge the other way, or correct terrain.');
  }

  db.exec('begin');
  let moved = 0;
  let charRows = 0;
  try {
    moved = db.prepare('update records set host_id = ? where host_id = ?').run(intoId, fromId).changes;
    // Records that only ever matched by the old name follow too.
    if (from.name) {
      moved += db.prepare(
        'update records set host_id = ? where host_id is null and lower(hostname) = lower(?)')
        .run(intoId, from.name).changes;
    }
    // Characterization keys on the host name string rather than an id.
    if (from.name && into.name) {
      charRows = db.prepare('update char_entities set host = ? where host = ?')
        .run(into.name, from.name).changes;
      db.prepare('update char_uploads set host = ? where host = ?').run(into.name, from.name);
      db.prepare('update char_host_status set host = ? where host = ?').run(into.name, from.name);
    }
    db.prepare('delete from host_overrides where host_id = ?').run(fromId);
    db.prepare('delete from hosts where id = ?').run(fromId);
    db.exec('commit');
  } catch (e) { db.exec('rollback'); throw e; }

  writeAudit(db, {
    analyst: actor, action: 'host.merge', targetType: 'host', targetId: intoId,
    before: { name: from.name, ip: from.ip, source: from.source },
    after: { into: into.name, records: moved, characterizationRows: charRows, reason },
  });
  return { into: getHost(db, intoId), records: moved, characterizationRows: charRows };
}

/** A box that exists but terrain does not know. Marked discovered, so seeding leaves it alone. */
export function createHost(db, { name, ip, enclave, segment, cidr, os, role, actor = null } = {}) {
  const n = clean(name) || normalizeIp(ip);
  if (!n) throw new Error('a host needs a name or an address');
  const addr = normalizeIp(ip);
  if (addr && db.prepare('select 1 from hosts where ip = ?').get(addr)) {
    throw new Error(`${addr} is already on the map`);
  }
  const id = newId();
  db.prepare(`insert into hosts
    (id, name, ip, enclave, segment, cidr, os, role, source, presence, presence_note, created_by)
    values (?,?,?,?,?,?,?,?,'discovered','unsurveyed',?,?)`)
    .run(id, n, addr, clean(enclave), clean(segment), clean(cidr), clean(os), clean(role),
      'Added by hand, not surveyed', actor);
  writeAudit(db, {
    analyst: actor, action: 'host.create', targetType: 'host', targetId: id,
    before: {}, after: { name: n, ip: addr },
  });
  return getHost(db, id);
}

/** How much evidence a host carries, which decides whether it can be removed. */
/**
 * What a host is carrying, archived rows included.
 *
 * Deliberately counts them: archiving retires a finding from the views, it
 * does not delete it, and removeHost must still refuse to orphan one. Archive
 * the host instead — that is what it is for.
 */
export function hostEvidence(db, hostId) {
  const h = getHost(db, hostId);
  if (!h) return { records: 0, characterization: 0 };
  /*
    Counted by the rule every reader of the same question uses — the binding,
    either address, or an exact name where nothing else placed it.

    The addresses were missing, and they are the common case rather than the
    exotic one: a finding naming an external destination_ip discovers a host
    for it and binds no host_id, because only source_ip binds. So the map drew
    a badge on the exfil destination, the drawer listed the finding, and this
    guard reported zero and deleted the host — leaving derivedConnections
    drawing an edge to a node that no longer exists, and the guard's own
    message about orphaning records unable to fire for the way records most
    often reach a host.

    Scanned rather than queried because the address may be recorded with a port
    on it, which is a regex the query cannot do. Removing a host is a rare,
    deliberate act; the scan costs nothing anybody will notice.
  */
  const name = String(h.name ?? '').toLowerCase();
  const ip = normalizeIp(h.ip);
  const records = db.prepare('select host_id, hostname, source_ip, destination_ip from records')
    .all()
    .filter((r) => {
      if (r.host_id === hostId) return true;
      if (ip && (normalizeIp(r.source_ip) === ip || normalizeIp(r.destination_ip) === ip)) return true;
      return !r.host_id && Boolean(name) && String(r.hostname ?? '').toLowerCase() === name;
    }).length;
  const characterization = h.name
    ? db.prepare('select count(*) n from char_entities where host = ?').get(h.name).n : 0;
  return { records, characterization };
}

export function removeHost(db, hostId, { actor = null, reason = null } = {}) {
  const h = getHost(db, hostId);
  if (!h) throw new Error('no such host');
  const ev = hostEvidence(db, hostId);
  if (ev.records || ev.characterization) {
    throw new Error(
      `${h.name} still carries ${ev.records} record(s) and ${ev.characterization} baseline row(s). ` +
      'Removing it would orphan them — merge it into the right host instead.');
  }
  if (h.source === 'seeded') {
    throw new Error(`${h.name} comes from terrain and would return at the next re-seed.`);
  }
  db.prepare('delete from host_overrides where host_id = ?').run(hostId);
  db.prepare('delete from hosts where id = ?').run(hostId);
  writeAudit(db, {
    analyst: actor, action: 'host.remove', targetType: 'host', targetId: hostId,
    before: { name: h.name, ip: h.ip }, after: { removed: true, reason },
  });
  return { removed: h.name };
}

export function setVerdict(db, hostId, verdict, analyst) {
  if (!VERDICTS.has(verdict)) throw new Error(`unknown verdict: ${verdict}`);
  const before = getHost(db, hostId);
  if (!before) throw new Error(`no such host: ${hostId}`);
  db.prepare('update hosts set verdict = ?, verdict_by = ?, verdict_at = ? where id = ?')
    .run(verdict, analyst ?? null, nowIso(), hostId);
  const after = getHost(db, hostId);
  writeAudit(db, {
    analyst, action: 'host.verdict', targetType: 'host', targetId: hostId,
    before: { verdict: before.verdict }, after: { verdict: after.verdict },
  });
  return after;
}
