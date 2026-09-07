import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import {
  createCharSnapshot, listCharSnapshots, stageSnapshot, repoView,
  setFieldGaps, fieldGapsFor, colValue,
} from '../store/characterization.js';
import { snapshotLabel, uniqueLabel } from '../lib/snapshot-name.js';

const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };
const run = (db, repo, who = null) => createCharSnapshot(db, { repo, createdBy: who }).id;
const put = (db, snapshotId, repo, host, entities) =>
  stageSnapshot(db, { repo, host, snapshotId, entities });

/*
  Every picker used to list all twenty collection runs whatever repository you
  were looking at, and processes held data in two of them. Operators
  compensated by typing the repository into the label by hand, four different
  ways in two days.
*/

// --- scope --------------------------------------------------------------------

test('a baseline belongs to one repository and no other picker offers it', () => {
  const db = fresh();
  run(db, 'processes', 'Okafor');
  run(db, 'accounts', 'Lindqvist');

  assert.equal(listCharSnapshots(db, 'processes').length, 1);
  assert.equal(listCharSnapshots(db, 'accounts').length, 1);
  assert.equal(listCharSnapshots(db, 'services').length, 0);
  assert.equal(listCharSnapshots(db).length, 2, 'unscoped still sees both');
});

test('an upload cannot land in another repository baseline', () => {
  const db = fresh();
  const procs = run(db, 'processes', 'Okafor');
  assert.throws(
    () => put(db, procs, 'accounts', 'H', [{ UserName: 'root' }]),
    /is a processes baseline; this upload is accounts/);
});

test('a run with no baseline chosen gets one for that repository, not the last one made', () => {
  const db = fresh();
  run(db, 'accounts', 'Lindqvist');
  stageSnapshot(db, { repo: 'processes', host: 'H', entities: [{ name: 'a.exe', path: 'C:/' }] });

  assert.equal(listCharSnapshots(db, 'accounts').length, 1);
  assert.equal(listCharSnapshots(db, 'processes').length, 1, 'processes got its own');
});

// --- naming -------------------------------------------------------------------

test('the name is generated in the fixed format, never typed', () => {
  assert.equal(
    snapshotLabel('processes', 'Okafor', new Date('2026-08-26T08:30:24Z')),
    'Processes_Baseline_Okafor_20260826083024');
  assert.equal(
    snapshotLabel('domain-accounts', 'Reyes', new Date('2026-08-26T08:30:24Z')),
    'DomainAccounts_Baseline_Reyes_20260826083024');
});

test('an operator name cannot break the separator, and a missing one is honest', () => {
  const at = new Date('2026-08-26T08:30:24Z');
  assert.equal(snapshotLabel('processes', 'de Vries_x', at), 'Processes_Baseline_DeVriesx_20260826083024');
  assert.equal(snapshotLabel('processes', null, at), 'Processes_Baseline_Unknown_20260826083024');
});

test('two runs in the same second are told apart rather than colliding', () => {
  const taken = new Set(['Processes_Baseline_Okafor_20260826083024']);
  assert.equal(
    uniqueLabel('Processes_Baseline_Okafor_20260826083024', (l) => taken.has(l)),
    'Processes_Baseline_Okafor_20260826083024_2');
});

test('the operator note survives even though the label does not', () => {
  const db = fresh();
  const id = createCharSnapshot(db, { repo: 'processes', createdBy: 'Baptiste', note: 'ICS network only' }).id;
  const [only] = listCharSnapshots(db, 'processes');
  assert.equal(only.id, id);
  assert.match(only.label, /^Processes_Baseline_Baptiste_\d{14}$/);
  assert.equal(only.note, 'ICS network only');
});

// --- aliases ------------------------------------------------------------------

/*
  A declared column used to resolve only against its own spelling, so 470
  accounts rendered a blank uid beside a UserId they were carrying, and two
  spellings of one field read as a change rather than as the same value.
*/
test('a declared column reads the spellings its sources actually use', () => {
  assert.equal(colValue('accounts', { UserId: '1001' }, 'uid'), '1001');
  assert.equal(colValue('accounts', { GroupNames: ['wheel', 'adm'] }, 'groups'), 'wheel, adm');
  assert.equal(colValue('services', { 'service.path': 'C:/svc.exe' }, 'binary'), 'C:/svc.exe');
  assert.equal(colValue('domain-accounts', { SamAccountName: 'jdoe' }, 'username'), 'jdoe');
});

test('collection plumbing is not a difference', () => {
  const db = fresh();
  const a = run(db, 'accounts', 'Baptiste');
  put(db, a, 'accounts', 'H', [{ _id: 'abc123', host: 'H', UserName: 'root', UserId: '0' }]);
  const b = run(db, 'accounts', 'Baptiste');
  put(db, b, 'accounts', 'H', [{ _id: 'zzz999', host: 'H', UserName: 'root', UserId: '0' }]);

  const v = repoView(db, 'accounts');
  assert.equal(v.counts.changed, 0, 'a Velociraptor row id is not a change to the account');
  assert.equal(v.rows[0].change, 'same');
});

// --- acknowledged gaps ---------------------------------------------------------

/*
  The case this exists for. One operator runs Get-ADUser with -Properties and
  the next does not; comparing the two reported 90 accounts as changed when
  nothing about any of them had changed.
*/
const twoRuns = (db) => {
  const thin = run(db, 'domain-accounts', 'Lindqvist');
  put(db, thin, 'domain-accounts', 'DC', [{ SamAccountName: 'jdoe' }]);
  const full = run(db, 'domain-accounts', 'Reyes');
  put(db, full, 'domain-accounts', 'DC',
    [{ SamAccountName: 'jdoe', Enabled: 'True', whenCreated: '2026-05-12' }]);
  return { thin, full };
};

test('an unacknowledged gap still reads as changed, and is offered for acknowledging', () => {
  const db = fresh();
  const { thin } = twoRuns(db);
  const v = repoView(db, 'domain-accounts');

  assert.equal(v.counts.changed, 1);
  assert.equal(v.counts.partial, 0);
  assert.deepEqual(v.fieldGaps.candidates.map(c => c.field).sort(), ['enabled', 'whenCreated']);
  assert.deepEqual(v.fieldGaps.candidates[0].snapshots, [thin], 'the run that lacks the field');
});

test('once acknowledged the row is partial, not changed, and says why', () => {
  const db = fresh();
  const { thin } = twoRuns(db);
  setFieldGaps(db, thin, ['enabled', 'whenCreated'], { actor: 'Lindqvist', note: 'no -Properties' });

  const v = repoView(db, 'domain-accounts');
  assert.equal(v.counts.changed, 0, 'not a changed asset');
  assert.equal(v.counts.partial, 1);

  const row = v.rows[0];
  assert.equal(row.change, 'partial');
  assert.deepEqual(row.gaps.map(g => g.field).sort(), ['enabled', 'whenCreated']);
  assert.ok(row.gaps.every(g => g.acknowledged));
  assert.equal(v.fieldGaps.candidates.length, 0, 'nothing left to acknowledge');
});

test('acknowledging one field does not excuse a real change in another', () => {
  const db = fresh();
  const a = run(db, 'domain-accounts', 'Lindqvist');
  put(db, a, 'domain-accounts', 'DC', [{ SamAccountName: 'jdoe', Enabled: 'True' }]);
  const b = run(db, 'domain-accounts', 'Reyes');
  put(db, b, 'domain-accounts', 'DC',
    [{ SamAccountName: 'jdoe', Enabled: 'False', whenCreated: '2026-05-12' }]);
  setFieldGaps(db, a, ['whenCreated'], { actor: 'Lindqvist' });

  const v = repoView(db, 'domain-accounts');
  assert.equal(v.counts.changed, 1, 'Enabled really did flip');
  assert.equal(v.counts.partial, 0);
  assert.deepEqual(v.rows[0].changes.map(c => c.field), ['enabled']);
  assert.deepEqual(v.rows[0].gaps.map(g => g.field), ['whenCreated']);
});

test('a field the repository does not compare on cannot be acknowledged', () => {
  const db = fresh();
  const id = run(db, 'processes', 'Okafor');
  assert.throws(() => setFieldGaps(db, id, ['nonsense']), /no column named nonsense/);
  assert.throws(() => setFieldGaps(db, 'no-such-run', ['name']), /no such baseline/);
});

test('acknowledgement can be withdrawn', () => {
  const db = fresh();
  const { thin } = twoRuns(db);
  setFieldGaps(db, thin, ['enabled', 'whenCreated'], { actor: 'Lindqvist' });
  assert.equal(repoView(db, 'domain-accounts').counts.partial, 1);

  setFieldGaps(db, thin, [], { actor: 'Okafor' });
  assert.equal(fieldGapsFor(db, thin).length, 0);
  assert.equal(repoView(db, 'domain-accounts').counts.changed, 1, 'back to being a question');
});

// --- migration ------------------------------------------------------------------

test('a run that spanned repositories is split, losslessly', () => {
  const db = fresh();
  const id = run(db, 'accounts', 'Lindqvist');
  put(db, id, 'accounts', 'H', [{ UserName: 'root' }]);
  /*
    Put it back into the old shape: one run holding two repositories. The repo
    has to be cleared first, because the guard that makes this migration
    unnecessary going forward also refuses to let a test recreate the problem.
  */
  db.prepare('update char_snapshots set repo = null, label = ? where id = ?')
    .run('Everything 24 Aug', id);
  stageSnapshot(db, { repo: 'services', host: 'H', snapshotId: id, entities: [{ name: 'sshd' }] });

  initSchema(db);   // idempotent; finds the null and splits it

  assert.equal(listCharSnapshots(db, 'accounts').length, 1);
  assert.equal(listCharSnapshots(db, 'services').length, 1);
  for (const repo of ['accounts', 'services']) {
    const [s] = listCharSnapshots(db, repo);
    assert.match(s.label, /_Baseline_Lindqvist_\d{14}/, s.label);
    assert.equal(s.note, 'Everything 24 Aug', 'the operator wrote something meaningful; keep it');
  }
  assert.equal(repoView(db, 'accounts').rows.length, 1);
  assert.equal(repoView(db, 'services').rows.length, 1);
});
