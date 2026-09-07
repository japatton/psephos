import { newId, nowIso } from '../lib/ids.js';
import { writeAudit } from './audit.js';

/**
 * Causality between two observations. Unlike host connections — which are
 * derived from the evidence and therefore not a judgement — an assertion that
 * one event caused another is a human call, so it is stored and adjudicated.
 */
export function proposeEdge(db, { srcRecordId, dstRecordId, kind, rationale = null }, analyst = null) {
  const exists = db.prepare('select 1 from records where id = ?');
  if (!exists.get(srcRecordId)) throw new Error(`no such record: ${srcRecordId}`);
  if (!exists.get(dstRecordId)) throw new Error(`no such record: ${dstRecordId}`);
  if (srcRecordId === dstRecordId) throw new Error('an event cannot cause itself');

  const id = newId();
  db.prepare(`insert into edges
    (id, src_record_id, dst_record_id, kind, rationale, status, created_by, created_at)
    values (?,?,?,?,?,'proposed',?,?)`)
    .run(id, srcRecordId, dstRecordId, kind, rationale, analyst, nowIso());
  return getEdge(db, id);
}

export function getEdge(db, id) {
  return db.prepare('select * from edges where id = ?').get(id);
}

export function listEdges(db, { status } = {}) {
  return status
    ? db.prepare('select * from edges where status = ? order by created_at').all(status)
    : db.prepare('select * from edges order by created_at').all();
}

function adjudicate(db, id, status, analyst, action) {
  const before = getEdge(db, id);
  if (!before) throw new Error(`no such edge: ${id}`);
  db.prepare('update edges set status = ?, adjudicated_by = ?, adjudicated_at = ? where id = ?')
    .run(status, analyst ?? null, nowIso(), id);
  const after = getEdge(db, id);
  writeAudit(db, {
    analyst, action, targetType: 'edge', targetId: id,
    before: { status: before.status }, after: { status: after.status },
  });
  return after;
}

export const confirmEdge = (db, id, analyst) => adjudicate(db, id, 'confirmed', analyst, 'edge.confirm');
export const denyEdge = (db, id, analyst) => adjudicate(db, id, 'denied', analyst, 'edge.deny');
