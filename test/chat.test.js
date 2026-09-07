import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import {
  ensureTeamChannel, createChannel, listChannels, canSee, parseMentions,
  postMessage, listMessages, markRead, listMentions, findDm, canReadFile,
} from '../store/chat.js';
import { saveFile, fileAsPromptText, looksTextual, MAX_FILE_BYTES } from '../store/files.js';
import { roster } from '../store/members.js';
import { listNotifications } from '../store/notifications.js';

// Chat keys on analyst names rather than member ids, so these tests need real
// ones. Read from the profile: a copied list drifts the moment it changes, and
// the names are mission data now. No test needs more than three at once.
const ROSTER = roster().map(m => m.name);
const [P1, P2, P3] = ROSTER;
const fresh = () => { const db = openDb(':memory:'); initSchema(db); ensureTeamChannel(db); return db; };

test('the team channel exists from first start and is not duplicated', () => {
  const db = fresh();
  ensureTeamChannel(db);
  assert.equal(db.prepare("select count(*) n from channels where kind='team'").get().n, 1);
  assert.ok(listChannels(db, P1).some(c => c.kind === 'team'));
});

test('everyone can see the team channel without being a member of it', () => {
  const db = fresh();
  assert.ok(canSee(db, 'team', P3));
  assert.equal(db.prepare("select count(*) n from channel_members where channel_id='team'").get().n, 0);
});

test('opening a DM twice lands in the same conversation', () => {
  const db = fresh();
  const a = createChannel(db, { kind: 'dm', members: [P2], createdBy: P1 });
  const b = createChannel(db, { kind: 'dm', members: [P1], createdBy: P2 });
  assert.equal(a.id, b.id, 'a second DM must not be created from the other side');
  assert.ok(findDm(db, P1, P2));
});

test('a DM is private to its two people', () => {
  const db = fresh();
  const dm = createChannel(db, { kind: 'dm', members: [P2], createdBy: P1 });
  assert.ok(canSee(db, dm.id, P1));
  assert.ok(canSee(db, dm.id, P2));
  assert.ok(!canSee(db, dm.id, P3), 'a DM is the one place reading is not open');
  assert.ok(!listChannels(db, P3).some(c => c.id === dm.id));
});

test('a group needs a name and includes its creator', () => {
  const db = fresh();
  assert.throws(() => createChannel(db, { kind: 'group', name: '  ', members: [P2], createdBy: P1 }));
  const g = createChannel(db, { kind: 'group', name: 'OT cell', members: [P2, P3], createdBy: P1 });
  assert.equal(g.name, 'OT cell');
  assert.deepEqual(listChannels(db, P1).find(c => c.id === g.id).members.sort(),
    [P3, P2, P1]);
});

test('a DM needs exactly one other person', () => {
  const db = fresh();
  assert.throws(() => createChannel(db, { kind: 'dm', members: [P2, P3], createdBy: P1 }));
});

test('mentions are matched against the roster, case-insensitively', () => {
  assert.deepEqual(parseMentions(`@${P1} can you take this`, ROSTER), [P1]);
  // The case people actually type in, which is whatever came to hand.
  assert.deepEqual(
    parseMentions(`@${P1.toLowerCase()} and @${P2.toUpperCase()}`, ROSTER).sort(),
    [P1, P2].sort());
  assert.deepEqual(parseMentions('no tags here', ROSTER), []);
});

test('a mention of someone not on the roster is not a mention', () => {
  assert.deepEqual(parseMentions('@Mallory look at this', ROSTER), []);
});

test('messages persist with their mentions and can be found later', () => {
  const db = fresh();
  postMessage(db, { channelId: 'team', author: P1, body: `@${P2} start the OT baseline`, roster: ROSTER });
  const msgs = listMessages(db, 'team');
  assert.equal(msgs.length, 1);
  assert.deepEqual(msgs[0].mentions, [P2]);
  assert.equal(listMentions(db, P2).length, 1);
  assert.equal(listMentions(db, P3).length, 0);
});

test('unread counts ignore your own messages and clear on read', () => {
  const db = fresh();
  postMessage(db, { channelId: 'team', author: P1, body: 'one', roster: ROSTER });
  postMessage(db, { channelId: 'team', author: P2, body: 'two', roster: ROSTER });
  assert.equal(listChannels(db, P3).find(c => c.id === 'team').unread, 2);
  assert.equal(listChannels(db, P1).find(c => c.id === 'team').unread, 1, 'not your own');
  markRead(db, 'team', P3);
  assert.equal(listChannels(db, P3).find(c => c.id === 'team').unread, 0);
});

test('an empty message is refused unless it carries a file', () => {
  const db = fresh();
  assert.throws(() => postMessage(db, { channelId: 'team', author: P1, body: '   ', roster: ROSTER }));
  const f = saveFile(db, { name: 'a.log', buffer: Buffer.from('x'), uploadedBy: P1 });
  assert.doesNotThrow(() => postMessage(db,
    { channelId: 'team', author: P1, body: '', fileId: f.id, roster: ROSTER }));
});

// --- files -----------------------------------------------------------------

test('a text file is stored, hashed and readable back as prompt text', () => {
  const db = fresh();
  const body = Buffer.from('Aug 19 11:59:01 web CRON[123]: (root) CMD (/opt/scripts/sync_logs.sh)\n');
  const f = saveFile(db, { name: 'auth.log', mime: 'text/plain', buffer: body, uploadedBy: P1 });
  assert.equal(f.size, body.length);
  assert.match(f.sha256, /^[0-9a-f]{64}$/);
  assert.equal(f.is_text, 1);
  const text = fileAsPromptText(db, f.id);
  assert.match(text, /sync_logs\.sh/);
  assert.match(text, /auth\.log/);
});

test('binary content is described, never decoded into the prompt', () => {
  const db = fresh();
  // A PNG header carries NUL bytes; pasting it into a prompt would be mojibake.
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]);
  const f = saveFile(db, { name: 'screenshot.png', mime: 'image/png', buffer: png, uploadedBy: P3 });
  assert.equal(f.is_text, 0);
  const text = fileAsPromptText(db, f.id);
  assert.match(text, /binary; not decoded/);
  assert.ok(text.includes(f.sha256));
});

test('content decides text or binary, not the extension', () => {
  // Analysts rename things; a .log that is really gzip must not be pasted in.
  assert.equal(looksTextual(Buffer.from([0x1f, 0x8b, 0x08, 0, 0, 0]), 'capture.log'), false);
  assert.equal(looksTextual(Buffer.from('plain text here'), 'evidence.bin'), true);
});

test('prompt text is truncated visibly rather than silently', () => {
  const db = fresh();
  const f = saveFile(db, { name: 'big.log', buffer: Buffer.from('A'.repeat(5000)), uploadedBy: P1 });
  assert.match(fileAsPromptText(db, f.id, { limit: 1000 }), /truncated at 1000 of 5000 characters/);
});

test('an oversized or empty upload is refused', () => {
  const db = fresh();
  assert.throws(() => saveFile(db, { name: 'x', buffer: Buffer.alloc(0), uploadedBy: P1 }));
  assert.throws(() => saveFile(db, { name: 'x', buffer: Buffer.alloc(MAX_FILE_BYTES + 1), uploadedBy: P1 }),
    /limit/);
});

/*
  A mention cannot carry a private message to somebody outside it.

  Tagging is the one thing a channel has to tell somebody about, so the mention
  path writes a durable notification carrying the first 240 characters of the
  message. In the team channel that is right — everybody can already read it.
  In a DM it handed the body, and the conversation's title, to a person the
  route refuses on every other path.

  Reproduced before the fix: Lindqvist, not a party to a DM between Reyes and
  Okafor, received "the box at 10.20.20.4 is compromised, do not tell the client
  yet" in their inbox, titled with both participants' names.

  The fix is to compute mentions against who can actually be tagged here rather
  than the whole roster, which also stops the message storing a mention that
  was never delivered.
*/
test('tagging someone outside a private channel notifies nobody', () => {
  const db = fresh();
  const [a, b, c] = [P1, P2, P3];
  const dm = createChannel(db, { kind: 'dm', name: null, members: [b], createdBy: a });

  const secret = `@${c} the box at 10.20.20.4 is compromised, do not tell the client yet`;
  const msg = postMessage(db, {
    channelId: dm.id, author: a, body: secret,
    roster: ROSTER,
  });

  assert.equal(canSee(db, dm.id, c), false, 'the fixture must have a real outsider');
  assert.deepEqual(listNotifications(db, c), [],
    'a private message reached somebody who cannot open the conversation');
  assert.deepEqual(msg.mentions, [],
    'the message stored a mention that was never delivered');

  // The participants still see the text itself; only the tag is dropped.
  assert.match(listMessages(db, dm.id)[0].body, /10\.20\.20\.4/);
});

test('tagging a participant of a private channel still works', () => {
  const db = fresh();
  const [a, b] = [P1, P2];
  const dm = createChannel(db, { kind: 'dm', name: null, members: [b], createdBy: a });

  const msg = postMessage(db, {
    channelId: dm.id, author: a, body: `@${b} can you look at this?`,
    roster: ROSTER,
  });
  assert.deepEqual(msg.mentions, [b]);
  assert.equal(listNotifications(db, b).length, 1);
});

test('the team channel can still tag anyone on the roster', () => {
  const db = fresh();
  const team = ensureTeamChannel(db);
  const [a, , c] = [P1, P2, P3];
  const msg = postMessage(db, {
    channelId: team.id, author: a, body: `@${c} take a look`,
    roster: ROSTER,
  });
  assert.deepEqual(msg.mentions, [c], 'the open channel must keep tagging the whole roster');
  assert.equal(listNotifications(db, c).length, 1);
});

/*
  A channel does not stop at three hundred messages.

  `order by ts limit 300` returned the OLDEST three hundred, so a long-running
  engagement froze its own transcript: a browser that stayed open kept
  receiving over SSE, but every reload, channel switch and reconnect refetch
  put the window back to the first three hundred and left it there. The unread
  count is computed straight off the table and went on climbing against
  messages the reader had no way to reach.
*/
test('a channel past the limit shows the newest messages, in reading order', () => {
  const db = fresh();
  for (let i = 1; i <= 305; i++) postMessage(db, { channelId: 'team', author: P1, body: `m${i}` });

  const msgs = listMessages(db, 'team');
  assert.equal(msgs.length, 300);
  assert.equal(msgs.at(-1).body, 'm305', 'the newest message must be reachable');
  assert.equal(msgs[0].body, 'm6', 'and the window is the newest 300, not the oldest');
  assert.deepEqual(msgs.map(m => m.body), msgs.map(m => m.body).sort(
    (a, b) => Number(a.slice(1)) - Number(b.slice(1))), 'oldest first, as a transcript reads');
});

/*
  A mention is addressed to one person; scanning the newest 500 messages
  estate-wide and filtering afterwards meant a busy afternoon on the team
  channel aged somebody's only mention out of their own list.
*/
test('a mention survives a busy channel burying it', () => {
  const db = fresh();
  postMessage(db, { channelId: 'team', author: P1, body: `@${P2} start with the DC`, roster: ROSTER });
  for (let i = 0; i < 600; i++) postMessage(db, { channelId: 'team', author: P1, body: `noise ${i}` });

  const mine = listMentions(db, P2);
  assert.equal(mine.length, 1, 'the mention should still be findable under 600 later messages');
  assert.match(mine[0].body, /start with the DC/);
  assert.equal(listMentions(db, P3).length, 0, 'and it belongs to one person, not the roster');
});

/*
  The bytes, as against the message that carries them.

  Every chat route gates on canSee. GET /api/files/:id gated on nothing: it
  looked the file up and served it to anyone holding any token — a teammate who
  is not in the DM, and the operator token, which the DM routes refuse by
  design. The id is a UUID and nothing hands it to an outsider, so this is a
  capability URL rather than an open door; it is still the one route that gives
  out the contents, and it is the one that asked no question.
*/
test('a DM attachment is readable by its participants and nobody else', () => {
  const db = fresh();
  const [a, b, outsider] = [P1, P2, P3];
  const dm = createChannel(db, { kind: 'dm', members: [b], createdBy: a });
  const f = saveFile(db, {
    name: 'dc-auth.log', mime: 'text/plain', uploadedBy: a,
    buffer: Buffer.from('4624 logon from 10.20.20.4'),
  });
  postMessage(db, { channelId: dm.id, author: a, body: 'this is the one', fileId: f.id, roster: ROSTER });

  assert.equal(canReadFile(db, f.id, a), true, 'the person who sent it');
  assert.equal(canReadFile(db, f.id, b), true, 'the person it was sent to');
  assert.equal(canReadFile(db, f.id, outsider), false,
    'a teammate outside the conversation read a private attachment');
  assert.equal(canReadFile(db, f.id, 'operator'), false,
    'the operator token is refused the DM itself; the bytes are the DM');
});

test('an attachment in the team channel is readable by the team', () => {
  const db = fresh();
  const f = saveFile(db, {
    name: 'spray.csv', mime: 'text/csv', uploadedBy: P1,
    buffer: Buffer.from('user,count\nsvc-backup,412'),
  });
  postMessage(db, { channelId: 'team', author: P1, body: 'the spray counts', fileId: f.id, roster: ROSTER });
  assert.equal(canReadFile(db, f.id, P3), true);
});

test('a file attached to nothing is readable only by whoever uploaded it', () => {
  const db = fresh();
  const f = saveFile(db, {
    name: 'draft.txt', mime: 'text/plain', uploadedBy: P1, buffer: Buffer.from('not sent yet'),
  });
  assert.equal(canReadFile(db, f.id, P1), true);
  assert.equal(canReadFile(db, f.id, P2), false);
  assert.equal(canReadFile(db, 'no-such-file', P1), false);
});
