import { nowIso } from '../lib/ids.js';

/**
 * Append-only record of who decided what. Every verdict writes exactly one
 * row — that invariant is asserted in the store tests, because an adjudication
 * trail with gaps is worse than none at all.
 */
export function writeAudit(db, { analyst, action, targetType, targetId, before, after }) {
  db.prepare(`insert into audit (ts, analyst, action, target_type, target_id, before, after)
              values (?,?,?,?,?,?,?)`)
    .run(nowIso(), analyst ?? null, action, targetType, targetId,
      before == null ? null : JSON.stringify(before),
      after == null ? null : JSON.stringify(after));
}

export function listAudit(db, { targetId, limit = 200 } = {}) {
  return targetId
    ? db.prepare('select * from audit where target_id = ? order by id desc limit ?').all(targetId, limit)
    : db.prepare('select * from audit order by id desc limit ?').all(limit);
}
