import { newId, nowIso } from '../lib/ids.js';

export function createSession(db, { title, kind = 'chat', analyst = null, memberId = null }) {
  const id = newId();
  db.prepare(`insert into sessions (id, title, kind, analyst, state, created_at, member_id)
              values (?,?,?,?,'open',?,?)`)
    .run(id, title, kind, analyst, nowIso(), memberId);
  return getSession(db, id);
}

/**
 * One persistent chat per team member, created on demand and never replaced.
 * The roster is the session list, so there is no "new session" step and no
 * question about which window is whose.
 */
export function ensureMemberSessions(db, members) {
  let created = 0;
  for (const m of members) {
    const have = db.prepare('select id from sessions where member_id = ?').get(m.id);
    if (have) continue;
    createSession(db, { title: `${m.name} — ${m.role}`, kind: 'chat', analyst: m.name, memberId: m.id });
    created++;
  }
  return created;
}

export const sessionForMember = (db, memberId) =>
  db.prepare('select * from sessions where member_id = ?').get(memberId) ?? null;

export function getSession(db, id) {
  return db.prepare('select * from sessions where id = ?').get(id);
}

export function listSessions(db) {
  return db.prepare('select * from sessions order by created_at desc').all();
}

/**
 * @param usage  what the turn cost, when the provider reported it. Absent for
 *               anything a person typed, and absent rather than zeroed when a
 *               provider says nothing — an unmeasured turn is not a free one.
 */
export function appendMessage(db, sessionId, role, content, mode = null, usage = null) {
  const id = newId();
  db.prepare(`insert into messages
      (id, session_id, role, content, ts, mode,
       input_tokens, output_tokens, cost_usd, duration_ms, model)
      values (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, sessionId, role, content, nowIso(), mode,
      usage?.inputTokens ?? null, usage?.outputTokens ?? null,
      usage?.costUsd ?? null, usage?.durationMs ?? null, usage?.model ?? null);
  return db.prepare('select * from messages where id = ?').get(id);
}

export function listMessages(db, sessionId) {
  return db.prepare('select * from messages where session_id = ? order by ts, rowid').all(sessionId);
}

/** Stored on the first turn so later turns can --resume the same conversation. */
export function setClaudeSessionId(db, id, claudeSessionId) {
  db.prepare('update sessions set claude_session_id = ? where id = ?').run(claudeSessionId, id);
  return getSession(db, id);
}

export function setState(db, id, state) {
  db.prepare('update sessions set state = ? where id = ?').run(state, id);
  return getSession(db, id);
}
