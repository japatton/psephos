import { newId, nowIso } from '../lib/ids.js';
import { getFileMeta } from './files.js';
import { notify } from './notifications.js';

export const TEAM_CHANNEL = 'team';

/** The all-hands channel exists from first start; nobody has to create it. */
export function ensureTeamChannel(db) {
  const have = db.prepare("select * from channels where kind = 'team'").get();
  if (have) return have;
  db.prepare(`insert into channels (id, kind, name, created_by, created_at)
              values (?, 'team', ?, ?, ?)`)
    .run(TEAM_CHANNEL, 'Whole team', 'system', nowIso());
  return db.prepare('select * from channels where id = ?').get(TEAM_CHANNEL);
}

/**
 * A DM is a group of two, so both are the same table. The one thing DMs need
 * that groups do not is a stable identity: opening a DM with the same person
 * twice must land in the same conversation, not create a second one.
 */
export function findDm(db, a, b) {
  const pair = [a, b].sort();
  const rows = db.prepare("select id from channels where kind = 'dm'").all();
  for (const { id } of rows) {
    const mem = db.prepare('select member from channel_members where channel_id = ? order by member')
      .all(id).map(m => m.member);
    if (mem.length === 2 && mem[0] === pair[0] && mem[1] === pair[1]) {
      return db.prepare('select * from channels where id = ?').get(id);
    }
  }
  return null;
}

export function createChannel(db, { kind, name, members, createdBy }) {
  if (kind === 'dm') {
    const others = members.filter(m => m !== createdBy);
    if (others.length !== 1) throw new Error('a direct message needs exactly one other person');
    const existing = findDm(db, createdBy, others[0]);
    if (existing) return existing;
  }
  if (kind === 'group' && !String(name ?? '').trim()) throw new Error('a group needs a name');

  const id = newId();
  const title = kind === 'dm' ? [createdBy, ...members.filter(m => m !== createdBy)].sort().join(' · ') : name.trim();
  db.prepare('insert into channels (id, kind, name, created_by, created_at) values (?,?,?,?,?)')
    .run(id, kind, title, createdBy, nowIso());
  for (const m of new Set([...members, createdBy])) {
    db.prepare('insert or ignore into channel_members (channel_id, member) values (?,?)').run(id, m);
  }
  return db.prepare('select * from channels where id = ?').get(id);
}

/** Channels this person can see: the team channel, plus any they belong to. */
export function listChannels(db, member) {
  const rows = db.prepare(`
    select c.* from channels c
    where c.kind = 'team'
       or exists (select 1 from channel_members m where m.channel_id = c.id and m.member = ?)
    order by case c.kind when 'team' then 0 when 'group' then 1 else 2 end, c.name`).all(member ?? '');

  return rows.map(c => {
    const members = db.prepare('select member from channel_members where channel_id = ? order by member')
      .all(c.id).map(m => m.member);
    const last = db.prepare('select ts, author, body from chat_messages where channel_id = ? order by ts desc, rowid desc limit 1')
      .get(c.id);
    const read = db.prepare('select last_read from channel_reads where channel_id = ? and member = ?')
      .get(c.id, member ?? '');
    const unread = db.prepare(`select count(*) n from chat_messages
      where channel_id = ? and author <> ? and ts > ?`)
      .get(c.id, member ?? '', read?.last_read ?? '').n;
    return { ...c, members, lastTs: last?.ts ?? null, lastAuthor: last?.author ?? null, unread };
  });
}

/*
  Whether a channel is readable by everyone.

  The team channel is; a DM or a group is not. Used by the broadcast path,
  which must not put a private body on a wire every browser on the LAN is
  listening to.
*/
export const isOpenChannel = (db, channelId) =>
  db.prepare('select kind from channels where id = ?').get(channelId)?.kind === 'team';

export const canSee = (db, channelId, member) => {
  const c = db.prepare('select * from channels where id = ?').get(channelId);
  if (!c) return false;
  if (c.kind === 'team') return true;
  return Boolean(db.prepare('select 1 from channel_members where channel_id = ? and member = ?')
    .get(channelId, member));
};

/*
  Whether this person may read this file's bytes.

  GET /api/files/:id checked nothing at all: every other chat route gates on
  canSee, and the one route that hands out the bytes served them to anyone
  holding any token — including the operator token, which the DM routes
  deliberately refuse. A DM attachment was readable by the whole roster and by
  the operator, and could be laundered into a session transcript the whole team
  reads by posting its id as an attachment.

  Readable when you uploaded it, when it is attached to a message in a channel
  you can see, or when it is a characterization import — those are estate
  material the whole team works from, which is what the panel is for.
*/
export function canReadFile(db, fileId, member) {
  const f = db.prepare('select uploaded_by from files where id = ?').get(fileId);
  if (!f) return false;
  if (member && f.uploaded_by === member) return true;
  if (db.prepare('select 1 from char_uploads where file_id = ? limit 1').get(fileId)) return true;
  return db.prepare('select distinct channel_id from chat_messages where file_id = ?')
    .all(fileId)
    .some(r => canSee(db, r.channel_id, member));
}

/**
 * @Name against the roster. Longest name first so "@Lin" cannot swallow a
 * hypothetical "@Lindqvist", and matching is case-insensitive because nobody
 * capitalises consistently while typing fast.
 */
export function parseMentions(body, roster) {
  const found = new Set();
  const names = [...roster].sort((a, b) => b.length - a.length);
  for (const name of names) {
    const re = new RegExp(`@${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    if (re.test(body)) found.add(name);
  }
  return [...found];
}

export function postMessage(db, { channelId, author, body, roster = [], fileId = null }) {
  if (!db.prepare('select 1 from channels where id = ?').get(channelId)) {
    throw new Error('no such channel');
  }
  if (!String(body ?? '').trim() && !fileId) throw new Error('empty message');
  const id = newId();
  /*
    Who can be tagged here, which is not the same as who is on the roster.

    A mention writes a durable notification carrying the first 240 characters of
    the message. In the team channel that is right — everyone can already read
    it. In a DM or a group it handed the body, and the conversation's title, to
    somebody the route refuses on every other path, and it did so through the
    inbox rather than the channel, so no membership check ever saw it.

    Scoping the roster rather than filtering the notifications afterwards also
    keeps the mentions stored on the message honest: a tag that reaches nobody
    should not be recorded as one.
  */
  const eligible = isOpenChannel(db, channelId)
    ? roster
    : roster.filter(name => canSee(db, channelId, name));
  const mentions = parseMentions(body ?? '', eligible);
  db.prepare(`insert into chat_messages (id, channel_id, author, body, mentions, file_id, ts)
              values (?,?,?,?,?,?,?)`)
    .run(id, channelId, author, String(body ?? ''), JSON.stringify(mentions), fileId, nowIso());

  // Being tagged is the one thing in a channel somebody has to be told about;
  // everything else is a room they can walk into.
  const channel = db.prepare('select name from channels where id = ?').get(channelId);
  for (const m of mentions) {
    notify(db, {
      member: m, kind: 'mention', actor: author,
      title: `${author} tagged you in ${channel?.name ?? 'a channel'}`,
      body: String(body ?? '').slice(0, 240),
      link: '#/comms',
    });
  }
  return hydrate(db, db.prepare('select * from chat_messages where id = ?').get(id));
}

const hydrate = (db, r) => ({
  ...r,
  mentions: (() => { try { return JSON.parse(r.mentions ?? '[]'); } catch { return []; } })(),
  file: r.file_id ? getFileMeta(db, r.file_id) : null,
});

/*
  The NEWEST messages, returned oldest-first.

  Written `order by ts limit 300` it returned the oldest 300, so a channel that
  passed three hundred messages froze: SSE kept appending for a browser that
  stayed open, but every reload, channel switch and reconnect refetch put the
  transcript back to the first 300 and left it there, while the unread count
  went on climbing against messages nobody could reach. Take the newest, then
  put them back in reading order.
*/
export const listMessages = (db, channelId, limit = 300) =>
  db.prepare('select * from chat_messages where channel_id = ? order by ts desc, rowid desc limit ?')
    .all(channelId, limit).reverse().map(r => hydrate(db, r));

export const markRead = (db, channelId, member) =>
  db.prepare(`insert into channel_reads (channel_id, member, last_read) values (?,?,?)
              on conflict(channel_id, member) do update set last_read = excluded.last_read`)
    .run(channelId, member, nowIso());

/*
  Everywhere this person has been tagged, newest first.

  The LIKE is a prefilter over the JSON column, not the answer: it narrows the
  scan to rows that mention SOMEBODY of this name, and the parsed check below
  decides. Scanning the newest 500 messages estate-wide and filtering afterwards
  meant a busy day on the team channel aged a mention out of somebody's list
  while it was still the only thing addressed to them.
*/
export const listMentions = (db, member, limit = 50) =>
  db.prepare(`select * from chat_messages where mentions like ? escape '\\'
              order by ts desc, rowid desc limit ?`)
    .all(`%${JSON.stringify(String(member)).replace(/[\\%_]/g, c => `\\${c}`)}%`, limit)
    .map(r => hydrate(db, r))
    .filter(m => m.mentions.includes(member));
