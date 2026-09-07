import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import {
  notify, listNotifications, unreadCount, markRead, markAllRead,
} from '../store/notifications.js';
import { setAssignees, importPlan, listPlan } from '../store/plan.js';
import { ensureTeamChannel, postMessage } from '../store/chat.js';

const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };

/*
  Two events are worth interrupting somebody for: being put on a task, and
  being tagged. Everything else here is a shared picture anybody can walk up to,
  and alerting on all of it is how a team learns to ignore the alerts.
*/

test('being put on a task tells the person, once', () => {
  const db = fresh();
  importPlan(db);
  const task = listPlan(db)[0];

  setAssignees(db, task.taskKey, ['Lindqvist'], 'Okafor');
  const [note] = listNotifications(db, 'Lindqvist');
  assert.equal(note.kind, 'assigned');
  assert.ok(note.title.includes(task.taskKey), note.title);
  assert.equal(note.body, task.title);
  assert.equal(note.actor, 'Okafor');
  assert.equal(note.link, '#/plan');

  // Re-saving the task with the same person on it is how somebody changes
  // something else about it, and must not tell them again.
  setAssignees(db, task.taskKey, ['Lindqvist'], 'Okafor');
  assert.equal(listNotifications(db, 'Lindqvist').length, 1);
});

test('only the people newly added are told', () => {
  const db = fresh();
  importPlan(db);
  const key = listPlan(db)[0].taskKey;
  setAssignees(db, key, ['Lindqvist'], 'Okafor');
  setAssignees(db, key, ['Lindqvist', 'Baptiste'], 'Okafor');

  assert.equal(listNotifications(db, 'Lindqvist').length, 1, 'already on it');
  assert.equal(listNotifications(db, 'Baptiste').length, 1, 'newly on it');
});

test('assigning yourself is not news', () => {
  const db = fresh();
  importPlan(db);
  setAssignees(db, listPlan(db)[0].taskKey, ['Okafor'], 'Okafor');
  assert.deepEqual(listNotifications(db, 'Okafor'), []);
});

test('being tagged in a channel tells the person, and never the author', () => {
  const db = fresh();
  const roster = ['Okafor', 'Lindqvist', 'Reyes'];
  const ch = ensureTeamChannel(db, 'Bravo');

  postMessage(db, {
    channelId: ch.id, author: 'Okafor', roster,
    body: '@Lindqvist can you take the DC, and @Okafor is already on the FS',
  });

  const [note] = listNotifications(db, 'Lindqvist');
  assert.equal(note.kind, 'mention');
  assert.match(note.title, /Okafor tagged you/);
  assert.match(note.body, /take the DC/);
  assert.equal(note.link, '#/comms');
  assert.deepEqual(listNotifications(db, 'Okafor'), [], 'tagging yourself is not news');
  assert.deepEqual(listNotifications(db, 'Reyes'), [], 'nobody else is told');
});

// --- the inbox ------------------------------------------------------------------

test('unread counts, and reading one leaves the rest alone', () => {
  const db = fresh();
  for (const t of ['a', 'b', 'c']) notify(db, { member: 'Reyes', kind: 'mention', title: t });
  assert.equal(unreadCount(db, 'Reyes'), 3);

  const [newest] = listNotifications(db, 'Reyes');
  assert.equal(markRead(db, newest.id, 'Reyes'), 2);
  assert.equal(listNotifications(db, 'Reyes', { unreadOnly: true }).length, 2);
  assert.ok(listNotifications(db, 'Reyes')[0].read_at, 'still listed, just read');
});

/*
  An id is not authority to read somebody else's mail. The route scopes every
  call to the caller's own roster identity and this is the half that enforces
  it, so a guessed id from another browser does nothing.
*/
test('one person cannot read or clear another persons inbox', () => {
  const db = fresh();
  const note = notify(db, { member: 'Reyes', kind: 'mention', title: 'private' });

  assert.equal(markRead(db, note.id, 'Baptiste'), 0, 'no effect, and reports Baptiste own count');
  assert.equal(unreadCount(db, 'Reyes'), 1, 'still unread for the person it is for');
  assert.equal(markAllRead(db, 'Baptiste'), 0);
  assert.equal(unreadCount(db, 'Reyes'), 1);
});

test('mark all read clears only that person', () => {
  const db = fresh();
  notify(db, { member: 'Reyes', kind: 'mention', title: 'x' });
  notify(db, { member: 'Baptiste', kind: 'assigned', title: 'y' });

  assert.equal(markAllRead(db, 'Reyes'), 1);
  assert.equal(unreadCount(db, 'Reyes'), 0);
  assert.equal(unreadCount(db, 'Baptiste'), 1);
});

test('a notification for nobody, or of an unknown kind, is not written', () => {
  const db = fresh();
  assert.equal(notify(db, { member: '', kind: 'mention', title: 'x' }), null);
  assert.equal(notify(db, { member: '   ', kind: 'mention', title: 'x' }), null);
  assert.equal(notify(db, { member: 'Reyes', kind: 'nonsense', title: 'x' }), null);
  assert.equal(unreadCount(db, 'Reyes'), 0);
});
