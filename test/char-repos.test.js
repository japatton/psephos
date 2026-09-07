import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import {
  repoList, isRepo, stageSnapshot, createCharSnapshot, repoView,
} from '../store/characterization.js';

const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };
const stage = (db, repo, host, entities) => stageSnapshot(db, {
  repo, host, snapshotId: createCharSnapshot(db, { repo }).id, entities,
});

/*
  The bug this file exists for.

  The catch-all repository keyed rows on their label, and a label is a constant
  per format — every "PSConsoleHistory" row on a host carried the same identity,
  so each overwrote the last. A three-hundred-line console history was stored as
  one row. Across the case file 879 rows went that way before anyone noticed,
  because the repository still showed a row per host and looked populated.
*/
test('the catch-all repository never collapses distinct rows', () => {
  const db = fresh();
  const history = Array.from({ length: 40 }, (_, i) => ({
    label: 'PSConsoleHistory', name: 'administrator', value: `Get-Thing -Index ${i}`,
  }));
  stage(db, 'unclassified', 'HOST-A', history);
  assert.equal(repoView(db, 'unclassified').rows.length, 40,
    'forty distinct commands must be forty rows');
});

test('the catch-all still folds rows that really are identical', () => {
  const db = fresh();
  const dup = { label: 'SMBShares', name: 'ADMIN$', value: 'C:/Windows' };
  stage(db, 'unclassified', 'HOST-A', [dup, { ...dup }, { ...dup }]);
  assert.equal(repoView(db, 'unclassified').rows.length, 1);
});

test('two hosts with the same content stay two rows', () => {
  const db = fresh();
  const row = { label: 'SMBShares', name: 'C$', value: 'C:/' };
  stage(db, 'unclassified', 'HOST-A', [row]);
  stage(db, 'unclassified', 'HOST-B', [{ ...row }]);
  assert.equal(repoView(db, 'unclassified').rows.length, 2);
});

// --- the repositories that were missing ------------------------------------------

test('command history keys on the command, not on a constant', () => {
  const db = fresh();
  stage(db, 'command-history', 'HOST-A', [
    { user: 'administrator', command: 'Get-ExchangeServer -Status' },
    { user: 'administrator', command: 'net user /add svc_x' },
    { user: 'rangetech', command: 'Get-ExchangeServer -Status' },
  ]);
  const v = repoView(db, 'command-history');
  assert.equal(v.rows.length, 3, 'same command by a different user is a different fact');
});

test('a command repeated by one user is one baseline entry', () => {
  const db = fresh();
  stage(db, 'command-history', 'HOST-A', [
    { user: 'root', command: 'crontab -l' },
    { user: 'root', command: 'crontab -l' },
  ]);
  assert.equal(repoView(db, 'command-history').rows.length, 1);
});

test('shares key on the share name however the export spelled it', () => {
  const db = fresh();
  stage(db, 'shares', 'HOST-A', [
    { name: 'ADMIN$', path: 'C:/Windows', description: 'Remote Admin' },
    { shareName: 'Payroll', path: 'D:/Payroll', permissions: 'Everyone:Full' },
    { share: 'IPC$', path: '' },
  ]);
  const v = repoView(db, 'shares');
  assert.equal(v.rows.length, 3);
  // Labelled by whatever the export called the share, not by "unnamed".
  assert.deepEqual(v.rows.map(r => r.label).sort(), ['ADMIN$', 'D:/Payroll', 'IPC$']);
});

test('host configuration keys on the setting', () => {
  const db = fresh();
  stage(db, 'host-config', 'HOST-A', [
    { setting: 'SMBv1', value: 'enabled' },
    { setting: 'ScriptBlockLogging', value: 'disabled' },
  ]);
  const v = repoView(db, 'host-config');
  assert.equal(v.rows.length, 2);
  // A setting flipping is a change to the same row, not a new row.
  stage(db, 'host-config', 'HOST-A', [{ setting: 'SMBv1', value: 'disabled' }]);
  assert.equal(repoView(db, 'host-config').rows.filter(r => r.label === 'SMBv1').length, 1);
});

// --- the register itself -----------------------------------------------------------

test('every repository is declared consistently', () => {
  for (const r of repoList()) {
    assert.ok(isRepo(r.key), `${r.key} is not recognised by isRepo`);
    assert.ok(r.label && r.label.length > 2, `${r.key} needs a label`);
    assert.ok(['host', 'domain'].includes(r.scope), `${r.key} has scope ${r.scope}`);
    assert.ok(Array.isArray(r.columns) && r.columns.length, `${r.key} needs columns`);
    assert.ok(Array.isArray(r.identFields) && r.identFields.length,
      `${r.key} needs identFields, or the model cannot tell what makes a row unique`);
  }
});

test('the three new repositories are registered', () => {
  const keys = repoList().map(r => r.key);
  for (const k of ['command-history', 'shares', 'host-config']) {
    assert.ok(keys.includes(k), `${k} missing`);
  }
});


/*
  A source that spells the identity differently from the column list used to
  show as "unnamed" while the row itself stored and diffed perfectly well.
  Forty-seven domain accounts read that way, each carrying a full name that
  nothing looked at.
*/
/*
  Scheduled tasks take both Windows and Linux collections, and the two have
  nothing in common to key on. Windows has a full task path; cron has a name
  and a directory, and the same job name genuinely appears in two of them.
*/
test('a windows task keys on its path and a cron job keys on both', () => {
  const db = fresh();
  stage(db, 'scheduled-tasks', 'WIN-01', [
    { 'task.name': 'Updater', 'task.path': 'C:/Windows/System32/Tasks/Vendor/Updater' },
  ]);
  const [win] = repoView(db, 'scheduled-tasks', { host: 'WIN-01' }).rows;
  assert.equal(win.ident, 'c:/windows/system32/tasks/vendor/updater',
    'the path alone, exactly as before — Windows identities must not move');

  // Two jobs, one name, two directories. Keyed on the name they would be one
  // row, and two rows folding into one is far below the fold guard floor.
  const db2 = fresh();
  stage(db2, 'scheduled-tasks', 'RL-01', [
    { name: 'backup', location: '/etc/cron.d/backup', command: '/usr/bin/a' },
    { name: 'backup', location: '/etc/cron.daily/backup', command: '/usr/bin/b' },
  ]);
  const rows = repoView(db2, 'scheduled-tasks', { host: 'RL-01' }).rows;
  assert.equal(rows.length, 2, 'the directory is what tells them apart');
  assert.deepEqual(rows.map(r => r.ident).sort(),
    ['/etc/cron.d/backup|backup', '/etc/cron.daily/backup|backup']);
  // The label is still the job, not the path it lives at.
  assert.deepEqual([...new Set(rows.map(r => r.label))], ['backup']);
});

test('two shares with one name at two paths stay two shares', () => {
  const db = fresh();
  stage(db, 'shares', 'FS-01', [
    { name: 'data', path: 'C:/data' },
    { name: 'data', path: 'D:/data' },
  ]);
  const rows = repoView(db, 'shares', { host: 'FS-01' }).rows;
  assert.equal(rows.length, 2, 'the path is what tells them apart');
  assert.deepEqual([...new Set(rows.map(r => r.label))], ['data'], 'both still called data');

  // A source that reports no path is exactly as it was.
  const db2 = fresh();
  stage(db2, 'shares', 'FS-01', [{ name: 'lonely' }]);
  assert.equal(repoView(db2, 'shares', { host: 'FS-01' }).rows[0].ident, 'lonely');
});

test('two architectures of one package are two packages', () => {
  const db = fresh();
  stage(db, 'software', 'RL-01', [
    { name: 'glibc', version: '2.34', arch: 'x86_64' },
    { name: 'glibc', version: '2.34', arch: 'i686' },
  ]);
  assert.equal(repoView(db, 'software', { host: 'RL-01' }).rows.length, 2);

  // And a source with no architecture behaves as it always did.
  const db2 = fresh();
  stage(db2, 'software', 'W-01', [{ name: '7-Zip', version: '23.01' }]);
  assert.equal(repoView(db2, 'software', { host: 'W-01' }).rows[0].ident, '7-zip');
});

test('a cron job with no location still keys on its name', () => {
  const db = fresh();
  stage(db, 'scheduled-tasks', 'RL-01', [{ name: 'lonely', command: '/usr/bin/x' }]);
  assert.equal(repoView(db, 'scheduled-tasks', { host: 'RL-01' }).rows[0].ident, 'lonely');
});

test('a row is labelled by its identFields when no column matches', () => {
  const db = fresh();
  stage(db, 'domain-accounts', 'DOMAIN', [{ samAccountName: 'svc_backup' }]);
  assert.equal(repoView(db, 'domain-accounts').rows[0].label, 'svc_backup');
});

test('a row with only a human name is labelled with it, not "unnamed"', () => {
  const db = fresh();
  stage(db, 'domain-accounts', 'DOMAIN', [
    { GivenName: 'Joseph', Surname: 'Acaba', fullName: 'Joseph Acaba' },
  ]);
  assert.equal(repoView(db, 'domain-accounts').rows[0].label, 'Joseph Acaba');
});

test('a row with nothing name-like is still honestly unnamed', () => {
  const db = fresh();
  // No declared column, no identField, nothing a person would read as a name.
  stage(db, 'shares', 'HOST-A', [{ bytesFree: 1024, quota: 'none' }]);
  assert.equal(repoView(db, 'shares').rows[0].label, 'unnamed');
});

/*
  The guard that would have caught the catch-all bug on day one.

  Reconciliation asked only "did the model return what it claimed", so a fold
  always looked legitimate — three hundred console-history lines stored as one
  row and the upload was marked ok. Some folding is normal; this much means the
  identity is not identifying anything.
*/
test('a pathological fold is flagged rather than called ok', () => {
  const db = fresh();
  const many = Array.from({ length: 300 }, (_, i) => ({
    label: 'PSConsoleHistory', name: 'admin', value: `command ${i}`,
  }));
  // Force the old collapse by handing every row the same identity.
  const out = stageSnapshot(db, {
    repo: 'shares', host: 'HOST-A', claimedRows: 300,
    snapshotId: createCharSnapshot(db, { repo: 'shares' }).id,
    entities: many.map(() => ({ name: 'ADMIN$', path: 'C:/Windows' })),
  });
  assert.equal(out.status, 'incomplete');
  assert.match(out.note, /collapsed to 1/);
});

test('ordinary duplicate folding is still fine', () => {
  const db = fresh();
  // A host really does run several processes from one path.
  const rows = Array.from({ length: 30 }, (_, i) => ({
    name: i % 2 ? 'svchost.exe' : `proc${i}.exe`, path: 'C:/Windows/System32',
  }));
  const out = stageSnapshot(db, {
    repo: 'processes', host: 'HOST-A', claimedRows: rows.length,
    snapshotId: createCharSnapshot(db, { repo: 'processes' }).id, entities: rows,
  });
  assert.equal(out.status, 'ok', out.note ?? '');
});

test('a small upload is never flagged for folding', () => {
  const db = fresh();
  const out = stageSnapshot(db, {
    repo: 'shares', host: 'HOST-A', claimedRows: 4,
    snapshotId: createCharSnapshot(db, { repo: 'shares' }).id,
    entities: [{ name: 'C$' }, { name: 'C$' }, { name: 'C$' }, { name: 'C$' }],
  });
  assert.equal(out.status, 'ok', 'four rows folding to one is not evidence of anything');
});

test('what the model returned is recorded alongside what was stored', () => {
  const db = fresh();
  const out = stageSnapshot(db, {
    repo: 'processes', host: 'HOST-A', claimedRows: 3,
    snapshotId: createCharSnapshot(db, { repo: 'processes' }).id,
    entities: [
      { name: 'a.exe', path: 'C:/' }, { name: 'a.exe', path: 'C:/' }, { name: 'b.exe', path: 'C:/' },
    ],
  });
  assert.equal(out.returned_rows, 3, 'three rows arrived');
  assert.equal(out.extracted_rows, 2, 'two survived deduplication');
});
