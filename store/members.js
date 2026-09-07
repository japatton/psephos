import { randomInt } from 'node:crypto';
import { newId, nowIso } from '../lib/ids.js';
import { missionPaths, readJson } from './mission.js';
import { writeAudit } from './audit.js';

/**
 * The team. One persistent chat each, one token each.
 *
 * The token is not authentication. It stops someone typing into a colleague's
 * chat window by accident, and it makes attribution automatic so nobody has to
 * remember to say who they are. Anyone holding any token can still read every
 * chat, which is deliberate: review and insight across the team is the point.
 *
 * Who is on the team is mission data, not source, so it comes from the active
 * profile's roster.json.
 */
export function roster() {
  const { members } = readJson(missionPaths().roster);
  if (!Array.isArray(members) || members.length === 0) {
    throw new Error('the mission roster lists nobody');
  }
  return members.map(m => ({ name: m.name, role: m.role ?? '', team: m.team ?? '' }));
}

// No 0/O or 1/I/L: twelve people are going to read these off a screen and type
// them, and a token that is ambiguous in a font is a support call.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

export function newMemberToken(len = 8) {
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[randomInt(ALPHABET.length)];
  return s;
}

/** Idempotent: existing members keep their token so a restart does not lock anyone out. */
export function seedMembers(db, members = roster()) {
  const existing = new Set(db.prepare('select name from members').all().map(r => r.name.toLowerCase()));
  const ins = db.prepare(`insert into members (id, name, role, team, token, created_at)
                          values (?,?,?,?,?,?)`);
  let created = 0;
  for (const m of members) {
    if (existing.has(m.name.toLowerCase())) continue;
    let token = newMemberToken();
    while (db.prepare('select 1 from members where token = ?').get(token)) token = newMemberToken();
    ins.run(newId(), m.name, m.role, m.team, token, nowIso());
    created++;
  }
  return created;
}

/**
 * Display order follows the roster's own order, so a team writes its chain of
 * command down once and the UI reflects it. Hard-coding Command/Bravo/Alpha
 * and a CPT's role names only ever ordered one mission correctly.
 */
function rosterOrder() {
  const teams = new Map();
  const roles = new Map();
  let list = [];
  try { list = roster(); } catch { /* profile gone; fall back to alphabetical */ }
  for (const m of list) {
    if (!teams.has(m.team)) teams.set(m.team, teams.size);
    if (!roles.has(m.role)) roles.set(m.role, roles.size);
  }
  return { teams, roles };
}

export function listMembers(db) {
  const { teams, roles } = rosterOrder();
  return db.prepare('select * from members').all().sort((a, b) =>
    (teams.get(a.team) ?? 99) - (teams.get(b.team) ?? 99) ||
    (roles.get(a.role) ?? 99) - (roles.get(b.role) ?? 99) ||
    a.name.localeCompare(b.name));
}

export const getMember = (db, id) => db.prepare('select * from members where id = ?').get(id);

/** Case-insensitive: nobody is going to get the capitalisation right every time. */
export const memberByToken = (db, token) => {
  if (!token) return null;
  return db.prepare('select * from members where upper(token) = upper(?)').get(String(token).trim()) ?? null;
};


/**
 * Rotate one token without disturbing anyone else's.
 *
 * Audited without the token itself: who was rotated and by whom is the part
 * worth keeping, and writing either the old or the new value into a table
 * every holder of any token can read would defeat the rotation.
 */
export function resetToken(db, memberId, { actor = null } = {}) {
  const before = getMember(db, memberId);
  if (!before) throw new Error(`no such member: ${memberId}`);

  let token = newMemberToken();
  while (db.prepare('select 1 from members where token = ?').get(token)) token = newMemberToken();
  db.prepare('update members set token = ? where id = ?').run(token, memberId);

  writeAudit(db, {
    analyst: actor, action: 'member.token.reset',
    targetType: 'member', targetId: memberId, after: { name: before.name },
  });
  return getMember(db, memberId);
}
