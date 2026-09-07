import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { writeAudit, listAudit } from '../store/audit.js';
import { seedHosts, setVerdict, listHosts } from '../store/hosts.js';
import { seedMembers, listMembers, resetToken, memberByToken } from '../store/members.js';
import {
  createCharSnapshot, stageSnapshot, stagedPreview, commitStaged, discardStaged,
} from '../store/characterization.js';

/*
  The accountability record. An adjudication trail with gaps is worse than
  none, because it invites the reader to trust what is there.
*/
const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };

test('a row records who, what, and both sides of the change', () => {
  const db = fresh();
  writeAudit(db, {
    analyst: 'Okafor', action: 'host.verdict', targetType: 'host', targetId: 'h1',
    before: { verdict: 'unknown' }, after: { verdict: 'confirmed' },
  });
  const [row] = listAudit(db);
  assert.equal(row.analyst, 'Okafor');
  assert.equal(row.action, 'host.verdict');
  assert.equal(row.target_type, 'host');
  assert.equal(row.target_id, 'h1');
  assert.deepEqual(JSON.parse(row.before), { verdict: 'unknown' });
  assert.deepEqual(JSON.parse(row.after), { verdict: 'confirmed' });
  assert.match(row.ts, /^\d{4}-\d{2}-\d{2}T/);
});

test('an unattributed action is recorded as unattributed, not dropped', () => {
  const db = fresh();
  writeAudit(db, { analyst: null, action: 'x', targetType: 't', targetId: 'i' });
  const [row] = listAudit(db);
  assert.equal(row.analyst, null);
  assert.equal(row.before, null);
  assert.equal(row.after, null);
});

test('the log reads newest first, and filters to one target', () => {
  const db = fresh();
  for (const id of ['a', 'b', 'a']) {
    writeAudit(db, { analyst: 'x', action: 'touch', targetType: 't', targetId: id });
  }
  assert.deepEqual(listAudit(db).map(r => r.target_id), ['a', 'b', 'a']
    .reverse().slice(0, 3), 'newest first');
  assert.equal(listAudit(db, { targetId: 'a' }).length, 2);
  assert.equal(listAudit(db, { limit: 1 }).length, 1);
});

test('the log is append-only in practice: nothing here updates a row', () => {
  const db = fresh();
  writeAudit(db, { analyst: 'x', action: 'one', targetType: 't', targetId: 'i' });
  writeAudit(db, { analyst: 'y', action: 'two', targetType: 't', targetId: 'i' });
  assert.deepEqual(listAudit(db, { targetId: 'i' }).map(r => r.action), ['two', 'one']);
});

// --- what actually gets audited -------------------------------------------------

const TERRAIN = [{ name: 'EX-DC', ip: '10.20.1.10', enclave: 'Corp', segment: 'servers' }];

test('a verdict writes exactly one row', () => {
  const db = fresh();
  seedHosts(db, TERRAIN);
  const h = listHosts(db)[0];
  setVerdict(db, h.id, 'confirmed', 'Reyes');
  const rows = listAudit(db, { targetId: h.id });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].analyst, 'Reyes');
});

/*
  Committing a baseline is the most consequential thing anyone does to
  characterization — it changes what "normal" means estate-wide, and every
  later delta is measured against it. Correcting one row already demanded a
  reason and left a trail; committing a whole upload left none at all.
*/
test('committing a staged upload is recorded, with who did it', () => {
  const db = fresh();
  const snap = createCharSnapshot(db, { repo: 'accounts' });
  stageSnapshot(db, {
    repo: 'accounts', host: 'EX-DC', snapshotId: snap.id, staged: true,
    entities: [{ UserName: 'svc_backup' }],
  });
  const ids = stagedPreview(db).map(u => u.id);
  assert.ok(ids.length, 'something was staged');

  assert.equal(commitStaged(db, ids, { actor: 'Okafor' }), ids.length);
  const rows = listAudit(db).filter(r => r.action === 'characterization.commit');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].analyst, 'Okafor');
  assert.equal(JSON.parse(rows[0].after).uploads, ids.length);
});

test('discarding a staged upload is recorded too', () => {
  const db = fresh();
  const snap = createCharSnapshot(db, { repo: 'accounts' });
  stageSnapshot(db, {
    repo: 'accounts', host: 'EX-DC', snapshotId: snap.id, staged: true,
    entities: [{ UserName: 'root' }],
  });
  const ids = stagedPreview(db).map(u => u.id);
  assert.equal(discardStaged(db, ids, { actor: 'Reyes' }), ids.length);
  const rows = listAudit(db).filter(r => r.action === 'characterization.discard');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].analyst, 'Reyes');
});

test('committing nothing writes nothing', () => {
  const db = fresh();
  assert.equal(commitStaged(db, [], { actor: 'Okafor' }), 0);
  assert.equal(discardStaged(db, ['no-such-id'], { actor: 'Okafor' }), 0);
  assert.equal(listAudit(db).length, 0, 'a no-op must not leave a trail suggesting otherwise');
});

/*
  Rotating a login token is an administrative act on someone else's access.
  The trail records who and whom — and deliberately neither token, because a
  table every token-holder can read is the wrong place for either.
*/
test('a token reset is recorded, and neither token is written down', () => {
  const db = fresh();
  seedMembers(db);
  const m = listMembers(db)[0];
  const oldToken = m.token;

  const after = resetToken(db, m.id, { actor: 'Reyes' });
  assert.notEqual(after.token, oldToken, 'the token actually changed');
  assert.equal(memberByToken(db, oldToken), null, 'and the old one stops working');

  const [row] = listAudit(db, { targetId: m.id });
  assert.equal(row.action, 'member.token.reset');
  assert.equal(row.analyst, 'Reyes');
  const serialised = JSON.stringify(row);
  assert.equal(serialised.includes(oldToken), false, 'the old token leaked into the log');
  assert.equal(serialised.includes(after.token), false, 'the new token leaked into the log');
  assert.equal(JSON.parse(row.after).name, m.name, 'but who it was is recorded');
});

test('resetting a member who does not exist is refused rather than silently ignored', () => {
  const db = fresh();
  seedMembers(db);
  assert.throws(() => resetToken(db, 'nobody', { actor: 'Reyes' }), /no such member/);
  assert.equal(listAudit(db).length, 0);
});
