/**
 * Telling one person that something happened to them.
 *
 * Two events matter enough to interrupt somebody: they were put on a task, and
 * they were tagged in a channel. Everything else on this server is a shared
 * picture that anybody can go and look at, and turning all of it into alerts
 * is how a team learns to ignore the alerts.
 *
 * Rows rather than a derived query, because the interesting question is "since
 * you last looked", and the assignment table cannot answer it — it records who
 * is on a task now, never when they were put there.
 */
import { newId, nowIso } from '../lib/ids.js';

export const KINDS = new Set(['assigned', 'mention']);

/**
 * @returns {object|null} the row, or null when there is nobody to tell —
 *   an unknown member, or the person who caused it in the first place.
 */
export function notify(db, { member, kind, title, body = null, link = null, actor = null }) {
  const to = String(member ?? '').trim();
  if (!to || !KINDS.has(kind)) return null;
  // Nobody needs telling about their own doing.
  if (actor && to.toLowerCase() === String(actor).toLowerCase()) return null;

  const id = newId();
  db.prepare(`insert into notifications (id, member, kind, title, body, link, actor, ts)
              values (?,?,?,?,?,?,?,?)`)
    .run(id, to, kind, String(title), body, link, actor, nowIso());
  return db.prepare('select * from notifications where id = ?').get(id);
}

export const listNotifications = (db, member, { limit = 50, unreadOnly = false } = {}) =>
  db.prepare(`select * from notifications
    where member = ? ${unreadOnly ? 'and read_at is null' : ''}
    order by ts desc, rowid desc limit ?`).all(String(member ?? ''), limit);

export const unreadCount = (db, member) => db.prepare(
  'select count(*) n from notifications where member = ? and read_at is null')
  .get(String(member ?? '')).n;

/** Scoped to the member on purpose: an id is not authority to read it. */
export function markRead(db, id, member) {
  db.prepare('update notifications set read_at = ? where id = ? and member = ? and read_at is null')
    .run(nowIso(), id, String(member ?? ''));
  return unreadCount(db, member);
}

export function markAllRead(db, member) {
  const at = nowIso();
  const n = db.prepare('update notifications set read_at = ? where member = ? and read_at is null')
    .run(at, String(member ?? '')).changes;
  return n;
}
