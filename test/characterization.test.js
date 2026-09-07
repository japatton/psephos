import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import {
  REPOS, isRepo, countRows, stageSnapshot, repoView, summary,
  queryBaseline, listSnapshots, getEntity, hostsIn,
  createCharSnapshot, listCharSnapshots, setSnapshotComplete, setHostStatus,
  stagedPreview, commitStaged, discardStaged, reattributeStaged,
  correctEntity, reattributeEntity, moveEntity,
} from '../store/characterization.js';

const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };

const procs = (...names) => names.map(n => ({ name: n, path: `C:\\Windows\\System32\\${n}`, user: 'SYSTEM' }));

/*
  A snapshot is a collection run, not an upload. Two uploads into the SAME
  snapshot merge -- that is the entire point, because a paged collection
  arrives in chunks. To express two points in time, a test must create two
  snapshots.
*/
/*
  A run belongs to one repository, so these helpers name it. They used to name
  the moment instead ("point 0"), which is what the store no longer models: two
  moments of the same repository are two runs, and two repositories at one
  moment are also two runs.
*/
const run = (db, repo) => createCharSnapshot(db, { repo }).id;
const stage = (db, snapshotId, opts) => stageSnapshot(db, Object.assign({}, opts, { snapshotId }));

// --- identity ---------------------------------------------------------------

/*
  The keys are what decide whether diffing works at all. A process keyed on PID
  would report every reboot as a total replacement of the host.
*/
test('a process is the same process after a reboot changes its PID', () => {
  const db = fresh();
  const RUN0 = run(db, 'processes');
  const RUN1 = run(db, 'processes');
  const before = [{ name: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe', pid: 100 }];
  const after = [{ name: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe', pid: 900 }];
  stage(db, RUN0, { repo: 'processes', host: 'WS-1', entities: before });
  stage(db, RUN1, { repo: 'processes', host: 'WS-1', entities: after });

  const rows = repoView(db, 'processes').rows;
  assert.equal(rows.length, 1);
  assert.equal(rows[0].change, 'changed', 'the PID changed, so it is a change');
  assert.ok(!rows.some(r => r.change === 'new'), 'but it must not read as a brand new process');
  assert.ok(!rows.some(r => r.change === 'gone'), 'nor as one that disappeared');
});

test('the same program at a different path is a different thing', () => {
  const db = fresh();
  const RUN0 = run(db, 'processes');
  const RUN1 = run(db, 'processes');
  stage(db, RUN0, { repo: 'processes', host: 'WS-1',
    entities: [{ name: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe' }] });
  stage(db, RUN1, { repo: 'processes', host: 'WS-1',
    entities: [{ name: 'svchost.exe', path: 'C:\\Users\\Public\\svchost.exe' }] });

  const rows = repoView(db, 'processes').rows;
  assert.equal(rows.filter(r => r.change === 'new').length, 1, 'the one in Public is new');
  assert.equal(rows.filter(r => r.change === 'gone').length, 1, 'the real one is gone');
});

test('a software version bump reads as changed, not as add plus remove', () => {
  const db = fresh();
  const RUN0 = run(db, 'software');
  const RUN1 = run(db, 'software');
  stage(db, RUN0, { repo: 'software', host: 'WS-1', entities: [{ name: '7-Zip', version: '21.0' }] });
  stage(db, RUN1, { repo: 'software', host: 'WS-1', entities: [{ name: '7-Zip', version: '23.1' }] });
  const rows = repoView(db, 'software').rows;
  assert.equal(rows.length, 1);
  assert.equal(rows[0].change, 'changed');
  assert.equal(rows[0].previous.version, '21.0');
});

/*
  A real host runs dozens of svchost.exe from the same path. The baseline cares
  that svchost.exe is present, not how many copies — otherwise every snapshot
  differs from the last for no reason. But dedup must not look like row loss,
  or the reconciliation would flag every honest upload.
*/
test('repeated rows collapse to one, and that is not counted as loss', () => {
  const db = fresh();
  const s = stageSnapshot(db, {
    repo: 'processes', host: 'WS-1',
    entities: procs('svchost.exe', 'svchost.exe', 'svchost.exe', 'lsass.exe'),
    claimedRows: 4,
  });
  assert.equal(s.extracted_rows, 2, 'two distinct things were stored');
  assert.equal(s.status, 'ok', 'collapsing duplicates must not read as a short extraction');
  assert.equal(repoView(db, 'processes').rows.length, 2, 'but only two distinct things are baselined');
});

// --- diff -------------------------------------------------------------------

test('the first snapshot is a baseline, not a pile of new things', () => {
  const db = fresh();
  stageSnapshot(db, { repo: 'processes', host: 'WS-1', entities: procs('a.exe', 'b.exe') });
  const rows = repoView(db, 'processes').rows;
  assert.equal(rows.length, 2);
  assert.ok(rows.every(r => r.change === 'baseline'), 'nothing to compare against yet');
});

test('diff reports new, gone and unchanged against the previous snapshot', () => {
  const db = fresh();
  const RUN0 = run(db, 'processes');
  const RUN1 = run(db, 'processes');
  stage(db, RUN0, { repo: 'processes', host: 'WS-1', entities: procs('a.exe', 'b.exe', 'c.exe') });
  stage(db, RUN1, { repo: 'processes', host: 'WS-1', entities: procs('a.exe', 'b.exe', 'd.exe') });

  const v = repoView(db, 'processes');
  assert.equal(v.counts.new, 1);
  assert.equal(v.counts.gone, 1);
  assert.equal(v.rows.find(r => r.change === 'new').label, 'd.exe');
  assert.equal(v.rows.find(r => r.change === 'gone').label, 'c.exe');
  assert.equal(v.rows.filter(r => r.change === 'same').length, 2);
});

test('one host changing does not make another host look changed', () => {
  const db = fresh();
  const RUN0 = run(db, 'processes');
  const RUN1 = run(db, 'processes');
  stage(db, RUN0, { repo: 'processes', host: 'WS-1', entities: procs('a.exe') });
  stage(db, RUN0, { repo: 'processes', host: 'WS-2', entities: procs('a.exe') });
  stage(db, RUN1, { repo: 'processes', host: 'WS-1', entities: procs('a.exe', 'evil.exe') });

  const v = repoView(db, 'processes');
  const newRows = v.rows.filter(r => r.change === 'new');
  assert.equal(newRows.length, 1);
  assert.equal(newRows[0].host, 'WS-1');
});

test('changes are surfaced above unchanged rows', () => {
  const db = fresh();
  const RUN0 = run(db, 'processes');
  const RUN1 = run(db, 'processes');
  stage(db, RUN0, { repo: 'processes', host: 'WS-1', entities: procs('a.exe', 'b.exe') });
  stage(db, RUN1, { repo: 'processes', host: 'WS-1', entities: procs('a.exe', 'b.exe', 'zzz.exe') });
  assert.equal(repoView(db, 'processes').rows[0].change, 'new',
    'the analyst reads from the top; the delta belongs there');
});

test('scheduled tasks diff, which is the only detection since 4698 is absent', () => {
  const db = fresh();
  const RUN0 = run(db, 'scheduled-tasks');
  const RUN1 = run(db, 'scheduled-tasks');
  stage(db, RUN0, { repo: 'scheduled-tasks', host: 'EX-WS-12-4',
    entities: [{ name: 'Updater', taskPath: '\\Microsoft\\Updater', trigger: 'daily' }] });
  stage(db, RUN1, { repo: 'scheduled-tasks', host: 'EX-WS-12-4',
    entities: [
      { name: 'Updater', taskPath: '\\Microsoft\\Updater', trigger: 'daily' },
      { name: 'SyncLogs', taskPath: '\\SyncLogs', trigger: '0 18 * * 3', action: 'sync_logs.sh' },
    ] });
  const v = repoView(db, 'scheduled-tasks');
  assert.equal(v.counts.new, 1);
  assert.equal(v.rows[0].label, 'SyncLogs');
  assert.ok(REPOS['scheduled-tasks'].note.includes('4698'), 'the gap is documented on the repo');
});

// --- rarity -----------------------------------------------------------------

test('rarity counts hosts, and only their latest snapshot', () => {
  const db = fresh();
  const RUN0 = run(db, 'processes');
  for (const h of ['A', 'B', 'C']) stage(db, RUN0, { repo: 'processes', host: h, entities: procs('common.exe') });
  stage(db, RUN0, { repo: 'processes', host: 'A', entities: procs('common.exe', 'rare.exe') });

  const v = repoView(db, 'processes');
  assert.equal(v.rows.find(r => r.label === 'rare.exe').hosts, 1);
  assert.equal(v.rows.find(r => r.label === 'rare.exe').totalHosts, 3);
  assert.equal(v.rows.find(r => r.label === 'common.exe' && r.host === 'A').hosts, 3);
});

test('something removed everywhere stops counting as common', () => {
  const db = fresh();
  const RUN0 = run(db, 'processes');
  const RUN1 = run(db, 'processes');
  stage(db, RUN0, { repo: 'processes', host: 'A', entities: procs('x.exe') });
  stage(db, RUN0, { repo: 'processes', host: 'B', entities: procs('x.exe') });
  stage(db, RUN1, { repo: 'processes', host: 'A', entities: procs('other.exe') });
  // History must not inflate rarity, or a thing deleted last week still looks
  // ubiquitous and never gets investigated.
  assert.equal(repoView(db, 'processes').rows.find(r => r.label === 'x.exe' && r.host === 'B').hosts, 1);
});

// --- reconciliation ---------------------------------------------------------

test('countRows ignores blank lines', () => {
  assert.equal(countRows('a\n\nb\n   \nc\n'), 3);
  assert.equal(countRows(''), 0);
});

test('a short extraction is flagged rather than accepted quietly', () => {
  const db = fresh();
  const s = stageSnapshot(db, {
    repo: 'processes', host: 'WS-1', entities: procs('a.exe', 'b.exe'), claimedRows: 400,
  });
  assert.equal(s.status, 'incomplete');
  assert.match(s.note, /398 are missing/);
});

/*
  A non-blank line count cannot judge an extraction. A real ECS scheduled-task
  CSV spends about eight lines per task and a Velociraptor JSON export about
  thirty-two per user, so a lines-versus-rows heuristic flagged every honest
  upload as short. Crying wolf on all of them is worse than staying quiet: it
  teaches the team to ignore the one warning that is real.
*/
test('a multi-line source format is not mistaken for a short extraction', () => {
  const db = fresh();
  const s = stageSnapshot(db, {
    repo: 'accounts', host: 'EX2-RL-1',
    entities: Array.from({ length: 47 }, (_, i) => ({ UserName: `u${i}` })),
    claimedRows: 47, countedRows: 1506,   // 32 lines per record, as Velociraptor emits
  });
  assert.equal(s.status, 'ok');
  assert.equal(s.extracted_rows, 47);
});

test('a genuine short extraction is still caught', () => {
  const db = fresh();
  const s = stageSnapshot(db, {
    repo: 'scheduled-tasks', host: 'W-1',
    entities: Array.from({ length: 21 }, (_, i) => ({ 'task.name': `t${i}` })),
    claimedRows: 22, countedRows: 132,
  });
  assert.equal(s.status, 'incomplete');
  assert.match(s.note, /1 is missing/);
});

test('an honest complete extraction is not flagged', () => {
  const db = fresh();
  const s = stageSnapshot(db, {
    repo: 'processes', host: 'WS-1', entities: procs('a.exe', 'b.exe'),
    claimedRows: 2, countedRows: 2,
  });
  assert.equal(s.status, 'ok');
  assert.equal(s.note, null);
});

test('a line count slightly above the row count is tolerated', () => {
  // Headers, blank separators and wrapped lines all skew a line count, so only
  // a large shortfall is worth crying about.
  const db = fresh();
  const s = stageSnapshot(db, { repo: 'processes', host: 'WS-1', entities: procs('a', 'b', 'c'), countedRows: 4 });
  assert.equal(s.status, 'ok');
});

test('rows from an incomplete snapshot are marked not confident', () => {
  const db = fresh();
  const RUN0 = run(db, 'processes');
  const RUN1 = run(db, 'processes');
  stage(db, RUN0, { repo: 'processes', host: 'WS-1', entities: procs('a.exe') });
  stage(db, RUN1, { repo: 'processes', host: 'WS-1', entities: procs('a.exe', 'b.exe'), claimedRows: 50 });
  const v = repoView(db, 'processes');
  assert.equal(v.incompleteSnapshots, 1);
  assert.ok(v.rows.every(r => r.confident === false),
    'deltas from a snapshot that lost rows must not be presented as fact');
});

test('an empty extraction is refused as incomplete', () => {
  const db = fresh();
  assert.equal(stageSnapshot(db, { repo: 'processes', host: 'WS-1', entities: [] }).status, 'incomplete');
});

test('an unknown repository is refused', () => {
  const db = fresh();
  assert.throws(() => stageSnapshot(db, { repo: 'nonsense', entities: procs('a') }), /unknown repository/);
  assert.ok(isRepo('spns') && !isRepo('spn'));
});

// --- lookup -----------------------------------------------------------------

test('queryBaseline answers "is this normal here" with rarity', () => {
  const db = fresh();
  const before = run(db, 'processes');
  for (const h of ['A', 'B', 'C']) stage(db, before, { repo: 'processes', host: h, entities: procs('svchost.exe') });
  // A later run, so beacon.exe is genuinely new rather than merged into the
  // sweep that established the baseline.
  stage(db, run(db, 'processes'), { repo: 'processes', host: 'A', entities: procs('svchost.exe', 'beacon.exe') });

  const common = queryBaseline(db, { repo: 'processes', q: 'svchost' });
  assert.ok(common.length);
  assert.match(common[0].seenOn, /3 of 3/);

  const rare = queryBaseline(db, { repo: 'processes', q: 'beacon' });
  assert.equal(rare.length, 1);
  assert.match(rare[0].seenOn, /1 of 3/);
  assert.equal(rare[0].change, 'new');
});

test('queryBaseline on an empty store returns nothing rather than throwing', () => {
  assert.deepEqual(queryBaseline(fresh(), { repo: 'processes', q: 'anything' }), []);
});

test('queryBaseline can be scoped to one host', () => {
  const db = fresh();
  const RUN0 = run(db, 'accounts');
  stage(db, RUN0, { repo: 'accounts', host: 'A', entities: [{ username: 'svc_backup' }] });
  stage(db, RUN0, { repo: 'accounts', host: 'B', entities: [{ username: 'jdoe' }] });
  assert.equal(queryBaseline(db, { repo: 'accounts', host: 'B' }).length, 1);
});

// --- bookkeeping ------------------------------------------------------------

test('domain-scoped repositories work through the same host column', () => {
  const db = fresh();
  stageSnapshot(db, { repo: 'spns', host: 'example.test',
    entities: [{ account: 'svc_sql', spn: 'MSSQLSvc/fs.example.test:1433', privileged: 'yes' }] });
  const v = repoView(db, 'spns');
  assert.equal(v.rows.length, 1);
  assert.equal(v.rows[0].host, 'example.test');
  assert.equal(REPOS.spns.scope, 'domain');
});

test('an unattributed upload is kept but stays separable', () => {
  const db = fresh();
  const s = stageSnapshot(db, { repo: 'processes', host: '   ', entities: procs('a.exe') });
  assert.equal(s.host, null);
  assert.deepEqual(hostsIn(db, 'processes'), [null]);
});

test('the summary reports what is populated and how much moved', () => {
  const db = fresh();
  const RUN0 = run(db, 'processes');
  const RUN1 = run(db, 'processes');
  stage(db, RUN0, { repo: 'processes', host: 'A', entities: procs('a.exe') });
  stage(db, RUN1, { repo: 'processes', host: 'A', entities: procs('a.exe', 'b.exe') });
  const s = summary(db);
  const p = s.find(r => r.key === 'processes');
  assert.equal(p.snapshots, 2);
  assert.equal(p.hosts, 1);
  assert.equal(p.changed, 1);
  assert.equal(s.find(r => r.key === 'spns').snapshots, 0);
  assert.equal(s.length, Object.keys(REPOS).length);
});

test('snapshots are listed newest first and entities are retrievable', () => {
  const db = fresh();
  stageSnapshot(db, { repo: 'processes', host: 'A', entities: procs('a.exe'), analyst: 'Lindqvist' });
  const snaps = listSnapshots(db, { repo: 'processes' });
  assert.equal(snaps.length, 1);
  assert.equal(snaps[0].analyst, 'Lindqvist');
  const row = repoView(db, 'processes').rows[0];
  assert.equal(getEntity(db, row.id).attrs.name, 'a.exe');
});

test('search matches attribute values, not just the label', () => {
  const db = fresh();
  stageSnapshot(db, { repo: 'processes', host: 'A',
    entities: [{ name: 'rundll32.exe', path: 'C:\\Users\\Public\\odd.dll', user: 'jdoe' }] });
  assert.equal(repoView(db, 'processes', { q: 'public' }).rows.length, 1);
  assert.equal(repoView(db, 'processes', { q: 'nothing-like-this' }).rows.length, 0);
});

// --- vulnerabilities and the Nessus importer --------------------------------

test('a vulnerability is keyed on plugin id, not on CVE', () => {
  const db = fresh();
  // Two plugins can cover one CVE, and one plugin can carry several. The
  // plugin is the stable identity; the CVE is metadata.
  stageSnapshot(db, { repo: 'vulnerabilities', host: 'H1', entities: [
    { pluginId: '41028', cve: 'CVE-1999-0517', name: 'SNMP default community', risk: 'High' },
    { pluginId: '76474', cve: 'CVE-1999-0517', name: 'SNMP GETBULK reflection', risk: 'Medium' },
  ] });
  assert.equal(repoView(db, 'vulnerabilities').rows.length, 2);
});

test('the same plugin on two ports stays two rows', () => {
  const db = fresh();
  stageSnapshot(db, { repo: 'vulnerabilities', host: 'H1', entities: [
    { pluginId: '42873', port: '443', name: 'SWEET32', risk: 'High' },
    { pluginId: '42873', port: '3389', name: 'SWEET32', risk: 'High' },
  ] });
  assert.equal(repoView(db, 'vulnerabilities').rows.length, 2);
});

test('remediation shows up as GONE, which is how a fix gets confirmed', () => {
  const db = fresh();
  const RUN0 = run(db, 'vulnerabilities');
  const RUN1 = run(db, 'vulnerabilities');
  stage(db, RUN0, { repo: 'vulnerabilities', host: 'H1', entities: [
    { pluginId: '41028', name: 'SNMP default community', risk: 'High' },
    { pluginId: '10114', name: 'ICMP timestamp', risk: 'None' },
  ] });
  stage(db, RUN1, { repo: 'vulnerabilities', host: 'H1', entities: [
    { pluginId: '10114', name: 'ICMP timestamp', risk: 'None' },
  ] });
  const v = repoView(db, 'vulnerabilities');
  assert.equal(v.counts.gone, 1);
  assert.equal(v.rows.find(r => r.change === 'gone').label, 'SNMP default community');
});

test('severity outranks rarity when ordering vulnerabilities', () => {
  const db = fresh();
  stageSnapshot(db, { repo: 'vulnerabilities', host: 'H1', entities: [
    { pluginId: '1', name: 'Informational thing', risk: 'None' },
    { pluginId: '2', name: 'Critical thing', risk: 'High' },
  ] });
  // Everywhere else rarity leads; here a High on the same host must come first.
  assert.equal(repoView(db, 'vulnerabilities').rows[0].label, 'Critical thing');
});

test('the Nessus parser survives quoted multi-line fields', async () => {
  const { parseCsv, nessusToHosts } = await import('../tools/import-nessus.mjs');
  const csv = [
    'Plugin ID,CVE,Risk,Host,Name,Solution',
    '41028,CVE-1999-0517,High,10.0.0.1,SNMP public,"Disable the service.',
    'Or filter it, and change the default string."',
    '10114,CVE-1999-0524,None,10.0.0.2,ICMP timestamp,Filter it',
  ].join('\n');

  const rows = parseCsv(csv);
  assert.equal(rows.length, 3, 'the embedded newline must not split a row');
  assert.match(rows[1][5], /Or filter it, and change/, 'the embedded comma must not split a field');

  const { byHost, total } = nessusToHosts(csv);
  assert.equal(total, 2);
  assert.deepEqual([...byHost.keys()], ['10.0.0.1', '10.0.0.2']);
  assert.equal(byHost.get('10.0.0.1')[0].risk, 'High');
});

test('a doubled quote inside a Nessus field is one quote', async () => {
  const { parseCsv } = await import('../tools/import-nessus.mjs');
  const rows = parseCsv('a,b\n1,"he said ""public"" here"');
  assert.equal(rows[1][1], 'he said "public" here');
});

test('a CSV that is not a Nessus export is refused rather than half-parsed', async () => {
  const { nessusToHosts } = await import('../tools/import-nessus.mjs');
  assert.throws(() => nessusToHosts('foo,bar\n1,2'), /does not look like a Nessus export/);
});

test('a missing severity column defaults rather than throwing', async () => {
  const { nessusToHosts } = await import('../tools/import-nessus.mjs');
  const { byHost } = nessusToHosts('Plugin ID,Host,Name\n10114,10.0.0.1,ICMP');
  assert.equal(byHost.get('10.0.0.1')[0].risk, 'None');
});

// --- field naming -----------------------------------------------------------

/*
  The regression that mattered. Seventeen of the team's snapshots stored zero
  rows while reporting they had extracted dozens: the collections came back as
  ECS ("task.name") and Velociraptor ("UserName"), the identity functions
  looked for `taskPath` and `username`, found undefined, and skipped every row.
  Reconciliation compared the model's count against itself and saw nothing
  wrong.
*/
test('a Velociraptor account export is stored, not silently dropped', () => {
  const db = fresh();
  const s = stageSnapshot(db, { repo: 'accounts', host: 'EX2-RL-1', claimedRows: 3, entities: [
    { UserName: 'root', UserId: '0', GroupNames: ['root'], HomeDirectory: '/root', Shell: '/bin/bash' },
    { UserName: 'ftp', UserId: '14', GroupNames: ['ftp'], HomeDirectory: '/var/ftp' },
    { UserName: 'svc_backup', UserId: '1001', GroupNames: ['backup', 'wheel'], HomeDirectory: '/home/svc_backup' },
  ] });
  assert.equal(s.extracted_rows, 3);
  assert.equal(s.status, 'ok');

  const rows = repoView(db, 'accounts').rows;
  assert.equal(rows.length, 3);
  assert.deepEqual(rows.map(r => r.label).sort(), ['ftp', 'root', 'svc_backup']);
  /*
    Under the declared column, because the repository now knows GroupNames is
    how some sources spell groups. It used to appear under the source's own
    name — honest, but it left the Groups column empty on 518 rows that had
    the data, and made two spellings of one field read as a change.
    Joined, not [object Object].
  */
  const backup = rows.find(r => r.label === 'svc_backup');
  assert.equal(backup.display.groups, 'backup, wheel');
  assert.equal(backup.display.GroupNames, undefined, 'not shown twice under both names');
});

test('an ECS scheduled-task export is stored under the right identity', () => {
  const db = fresh();
  stageSnapshot(db, { repo: 'scheduled-tasks', host: 'EX2-WIN11-1', claimedRows: 2, entities: [
    { 'host.name': 'EX2-WIN11-1', 'task.name': '\Microsoft\Windows\Updater', 'task.author.name': 'SYSTEM' },
    { 'host.name': 'EX2-WIN11-1', 'task.name': '\SyncLogs', 'task.author.name': 'root' },
  ] });
  const rows = repoView(db, 'scheduled-tasks').rows;
  assert.equal(rows.length, 2);
  assert.ok(rows.some(r => r.ident === '\synclogs'), 'the dotted field must resolve to the identity');
});

test('the same account in two spellings is one thing, so it diffs', () => {
  const db = fresh();
  const RUN0 = run(db, 'accounts');
  const RUN1 = run(db, 'accounts');
  stage(db, RUN0, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  stage(db, RUN1, { repo: 'accounts', host: 'H', entities: [{ user_name: 'root' }] });
  const v = repoView(db, 'accounts');
  assert.equal(v.counts.new, 0, 'a change of spelling is not a new account');
  assert.equal(v.counts.gone, 0);
});

test('a row with no recognisable identity is kept and flagged, never dropped', () => {
  const db = fresh();
  const s = stageSnapshot(db, { repo: 'accounts', host: 'H', claimedRows: 2, entities: [
    { UserName: 'root' },
    { wildly: 'unexpected', shape: 'entirely' },
  ] });
  assert.equal(s.extracted_rows, 2, 'both rows survive');
  assert.equal(s.status, 'incomplete');
  assert.match(s.note, /no field this repository recognises/);
  assert.equal(repoView(db, 'accounts').rows.length, 2);
});

test('a snapshot that stores nothing is never reported as healthy', () => {
  // The precise hole that hid the bug: 47 returned, 47 claimed, 0 stored.
  const db = fresh();
  const s = stageSnapshot(db, { repo: 'accounts', host: 'H', claimedRows: 47, entities: [] });
  assert.equal(s.status, 'incomplete');
  assert.equal(s.extracted_rows, 0);
});

// --- snapshots: chunked uploads ---------------------------------------------

/*
  The case that motivated the whole model. RL-4's accounts arrived as 12 rows
  and then 35, two pages of one collection. Treated as two points in time that
  diffed as twenty-three accounts appearing overnight, and somebody would have
  gone looking for them.
*/
test('two chunks of one collection merge instead of diffing', () => {
  const db = fresh();
  const baseline = run(db, 'accounts');
  const page1 = Array.from({ length: 12 }, (_, i) => ({ UserName: `u${i}` }));
  const page2 = Array.from({ length: 35 }, (_, i) => ({ UserName: `u${i + 12}` }));

  stage(db, baseline, { repo: 'accounts', host: 'EX2-RL-4', entities: page1, claimedRows: 12 });
  stage(db, baseline, { repo: 'accounts', host: 'EX2-RL-4', entities: page2, claimedRows: 35 });

  const v = repoView(db, 'accounts');
  assert.equal(v.rows.length, 47, 'the snapshot holds the union of both pages');
  assert.equal(v.counts.new, 0, 'page two is not twenty-three new accounts');
  assert.equal(v.counts.gone, 0, 'nor does page one vanish');
  assert.ok(v.rows.every(r => r.change === 'baseline'));
});

test('a chunk re-sent into the same snapshot changes nothing', () => {
  const db = fresh();
  const r1 = run(db, 'accounts');
  stage(db, r1, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  stage(db, r1, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  assert.equal(repoView(db, 'accounts').rows.length, 1);
});

test('a later snapshot diffs against the merged earlier one, not against a chunk', () => {
  const db = fresh();
  const first = run(db, 'accounts');
  stage(db, first, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  stage(db, first, { repo: 'accounts', host: 'H', entities: [{ UserName: 'ftp' }] });

  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'H',
    entities: [{ UserName: 'root' }, { UserName: 'ftp' }, { UserName: 'svc_evil' }] });

  const v = repoView(db, 'accounts');
  assert.equal(v.counts.new, 1, 'only the genuinely new account');
  assert.equal(v.rows[0].label, 'svc_evil');
  assert.equal(v.counts.gone, 0, 'ftp came from a chunk but is still in the baseline');
});

/*
  Partial coverage. A run where somebody only gathered accounts must not make
  every scheduled task on those hosts read as GONE — "previous" is the most
  recent earlier snapshot that HAS DATA for this repo and host, not simply the
  run before it.

  Runs are now per repository, so this is structural rather than defended: a
  new accounts run is not in the scheduled-tasks chain at all. Kept because the
  chain still has to pick the right earlier run WITHIN a repository.
*/
test('a run that skipped a repository does not wipe its baseline', () => {
  const db = fresh();
  const full = run(db, 'accounts');
  const fullTasks = run(db, 'scheduled-tasks');
  stage(db, full, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  stage(db, fullTasks, { repo: 'scheduled-tasks', host: 'H', entities: [{ taskPath: '\Updater' }] });

  // A later run that only collected accounts.
  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });

  const tasks = repoView(db, 'scheduled-tasks');
  assert.equal(tasks.counts.gone, 0, 'the task baseline survives a run that never looked at tasks');
  assert.equal(tasks.rows.length, 1);
  assert.equal(tasks.rows[0].change, 'baseline');
});

test('a run that skipped a host does not wipe that host', () => {
  const db = fresh();
  const both = run(db, 'accounts');
  stage(db, both, { repo: 'accounts', host: 'A', entities: [{ UserName: 'root' }] });
  stage(db, both, { repo: 'accounts', host: 'B', entities: [{ UserName: 'root' }] });
  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'A', entities: [{ UserName: 'root' }] });

  const v = repoView(db, 'accounts');
  assert.equal(v.counts.gone, 0);
  assert.equal(v.rows.filter(r => r.host === 'B').length, 1, 'B still has its baseline');
});

test('the view names which runs it is comparing', () => {
  const db = fresh();
  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  assert.match(repoView(db, 'accounts').comparing.join(' '), /^Accounts_Baseline_\w+ \(first\)$/);

  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  assert.match(repoView(db, 'accounts').comparing.join(' '),
    /Accounts_Baseline_\S+ against Accounts_Baseline_\S+/);
});

test('a baseline belongs to one repository and names itself', () => {
  const db = fresh();
  assert.throws(() => createCharSnapshot(db, {}), /belongs to one repository/);
  assert.throws(() => createCharSnapshot(db, { repo: 'nonsense' }), /belongs to one repository/);

  const r = createCharSnapshot(db, { repo: 'accounts', createdBy: 'Lindqvist' });
  assert.match(r.label, /^Accounts_Baseline_Lindqvist_\d{14}$/, r.label);
  assert.equal(r.repo, 'accounts');

  stage(db, r.id, { repo: 'accounts', host: 'A', entities: [{ UserName: 'root' }] });
  stage(db, r.id, { repo: 'accounts', host: 'B', entities: [{ UserName: 'root' }] });

  const [only] = listCharSnapshots(db, 'accounts');
  assert.equal(only.hosts, 2);
  assert.equal(only.uploads, 2);
  assert.equal(only.rows, 2);
  // The whole point: another repository's picker sees none of this.
  assert.equal(listCharSnapshots(db, 'processes').length, 0);
});

test('an upload with no snapshot joins the most recent one rather than being lost', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  stageSnapshot(db, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  assert.equal(listCharSnapshots(db).length, 1, 'no stray snapshot is minted');
  assert.equal(listCharSnapshots(db)[0].id, r);
});

test('the very first upload on an empty store still gets a snapshot', () => {
  const db = fresh();
  stageSnapshot(db, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  assert.equal(listCharSnapshots(db).length, 1);
  assert.equal(repoView(db, 'accounts').rows.length, 1);
});

// --- coverage ---------------------------------------------------------------

/*
  The failure the adversarial pass caught. A snapshot accumulates, so five
  hosts uploaded of ten planned looks exactly like five that did not answer.
  Offering "unreachable, investigate" on a host merely next in the queue is how
  the line-count heuristic became worthless: thirteen false alarms hiding one
  real one.
*/
test('a snapshot still collecting never alarms about absent hosts', () => {
  const db = fresh();
  const first = run(db, 'accounts');
  for (const h of ['A', 'B', 'C']) stage(db, first, { repo: 'accounts', host: h, entities: [{ UserName: 'root' }] });
  setSnapshotComplete(db, first, true);

  const second = run(db, 'accounts');
  stage(db, second, { repo: 'accounts', host: 'A', entities: [{ UserName: 'root' }] });

  const v = repoView(db, 'accounts', { snapshot: second, against: first });
  assert.equal(v.coverage.collecting, true, 'an unfinished run must say so');
  assert.equal(v.coverage.missing.length, 2, 'the hosts are still named, just neutrally');
});

test('a completed collection names the hosts that did not report', () => {
  const db = fresh();
  const first = run(db, 'accounts');
  for (const h of ['A', 'B', 'C']) stage(db, first, { repo: 'accounts', host: h, entities: [{ UserName: 'root' }] });
  const second = run(db, 'accounts');
  stage(db, second, { repo: 'accounts', host: 'A', entities: [{ UserName: 'root' }] });
  setSnapshotComplete(db, second, true);

  const v = repoView(db, 'accounts', { snapshot: second, against: first });
  assert.equal(v.coverage.collecting, false);
  assert.deepEqual(v.coverage.missing.map(m => m.host).sort(), ['B', 'C']);
  assert.match(v.coverage.missing[0].lastSeen, /^Accounts_Baseline_\S+$/,
    'named by the run they were last seen in');
});

/*
  The default view is the one an analyst opens, and it was the one that could
  not see a host go dark.

  current/against were taken from `perHost[0]` — whichever host sorts first
  alphabetically. When that host is the one that stopped reporting, its chain
  does not reach the newest run, `against` resolves to null, and coverageFor
  returns an empty `missing` unconditionally. Whether the tool noticed a host
  going silent depended on how the estate's hosts happened to be named.

  Every other coverage test pins snapshot and against explicitly, so all of them
  passed while the default path was blind. Both orderings are checked here
  because one of them passed before the fix and proved nothing.
*/
test('the default view names a missing host whatever its name sorts like', () => {
  for (const dark of ['A', 'C']) {
    const db = fresh();
    const first = run(db, 'accounts');
    for (const h of ['A', 'B', 'C']) stage(db, first, { repo: 'accounts', host: h, entities: [{ UserName: 'root' }] });
    setSnapshotComplete(db, first, true);

    const second = run(db, 'accounts');
    for (const h of ['A', 'B', 'C'].filter(h => h !== dark)) {
      stage(db, second, { repo: 'accounts', host: h, entities: [{ UserName: 'root' }] });
    }
    setSnapshotComplete(db, second, true);

    assert.deepEqual(
      repoView(db, 'accounts', { snapshot: second, against: first }).coverage.missing.map(m => m.host),
      [dark], `the pinned view lost ${dark}`);
    assert.deepEqual(
      repoView(db, 'accounts').coverage.missing.map(m => m.host),
      [dark], `the default view did not notice ${dark} going dark`);
  }
});

test('a reason for silence is recorded and read back', () => {
  const db = fresh();
  const first = run(db, 'accounts');
  for (const h of ['A', 'B']) stage(db, first, { repo: 'accounts', host: h, entities: [{ UserName: 'root' }] });
  const second = run(db, 'accounts');
  stage(db, second, { repo: 'accounts', host: 'A', entities: [{ UserName: 'root' }] });
  setSnapshotComplete(db, second, true);

  setHostStatus(db, 'accounts', 'B', { reason: 'unreachable', note: 'agent not responding', actor: 'Lindqvist' });
  const v = repoView(db, 'accounts', { snapshot: second, against: first });
  assert.equal(v.coverage.missing.find(m => m.host === 'B').reason, 'unreachable');

  setHostStatus(db, 'accounts', 'B', { reason: null });
  assert.equal(repoView(db, 'accounts', { snapshot: second, against: first })
    .coverage.missing.find(m => m.host === 'B').reason, null);
});

test('coverage gaps are scoped to enclaves already being characterized', () => {
  const db = fresh();
  db.prepare("insert into hosts (id,name,ip,enclave,source) values ('1','A','10.0.0.1','Enclave B','seeded')").run();
  db.prepare("insert into hosts (id,name,ip,enclave,source) values ('2','B','10.0.0.2','Enclave B','seeded')").run();
  db.prepare("insert into hosts (id,name,ip,enclave,source) values ('3','OT-1','10.1.0.1','OT','seeded')").run();

  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'A', entities: [{ UserName: 'root' }] });

  const never = repoView(db, 'accounts').coverage.neverCharacterized;
  assert.equal(never.length, 1, 'only the enclave with a foothold counts');
  assert.equal(never[0].enclave, 'Enclave B');
  assert.deepEqual(never[0].hosts, ['B']);
  // OT has nothing characterized, so its host is a decision, not a gap.
  assert.ok(!never.some(e => e.enclave === 'OT'));
});

// --- literal comparison -----------------------------------------------------

test('an explicit comparison is literal and never falls back', () => {
  const db = fresh();
  const a = run(db, 'accounts');
  const b = run(db, 'accounts');
  const c = run(db, 'accounts');
  stage(db, a, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  stage(db, b, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }, { UserName: 'ftp' }] });
  stage(db, c, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }, { UserName: 'ftp' }, { UserName: 'svc' }] });

  assert.equal(repoView(db, 'accounts').counts.new, 1, 'default is C against B');
  assert.equal(repoView(db, 'accounts', { snapshot: c, against: a }).counts.new, 2,
    'asking for A means A, not whatever else has data');
});

test('a host missing from the right-hand side reads baseline, not new', () => {
  const db = fresh();
  const a = run(db, 'accounts');
  const b = run(db, 'accounts');
  stage(db, a, { repo: 'accounts', host: 'H1', entities: [{ UserName: 'root' }] });
  stage(db, b, { repo: 'accounts', host: 'H1', entities: [{ UserName: 'root' }] });
  stage(db, b, { repo: 'accounts', host: 'H2', entities: [{ UserName: 'root' }] });

  const v = repoView(db, 'accounts', { snapshot: b, against: a });
  const h2 = v.rows.filter(r => r.host === 'H2');
  assert.equal(h2.length, 1);
  assert.equal(h2[0].change, 'baseline',
    'nothing to compare against is not the same as newly appeared');
});

// --- manual uploads ---------------------------------------------------------

/*
  The second failure the adversarial pass caught, and the worse one. A host's
  current snapshot is the most recent holding its data. If a manual correction
  counted, moving one row into a newer snapshot would make that snapshot
  current with a single row in it, and the other forty-six would read GONE.
*/
test('a manual upload carries rows but does not make a host count as reported', () => {
  const db = fresh();
  const first = run(db, 'accounts');
  const rows = Array.from({ length: 47 }, (_, i) => ({ UserName: `u${i}` }));
  stage(db, first, { repo: 'accounts', host: 'H', entities: rows });

  const later = run(db, 'accounts');
  stageSnapshot(db, {
    repo: 'accounts', host: 'H', snapshotId: later, kind: 'manual',
    entities: [{ UserName: 'corrected' }],
  });

  const v = repoView(db, 'accounts');
  assert.equal(v.counts.gone, 0, 'the other forty-six must not vanish');
  assert.equal(v.rows.length, 47, 'the baseline is still the baseline');

  /*
    And H is named as not having reported, which is the point of the test's own
    title: a manual upload is an analyst typing a correction, not the collector
    answering. It used to read zero here, but only because the default view was
    blind — `against` resolved to null and `missing` came back empty whatever had
    happened. With that fixed the honest answer is that the newest run contains
    no collection from H at all.
  */
  assert.deepEqual(v.coverage.missing.map(m => m.host), ['H'],
    'a run holding only a manual correction must not count as H reporting');
});

// --- staging ----------------------------------------------------------------

test('a staged upload is invisible to every read until committed', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  stageSnapshot(db, {
    repo: 'accounts', host: 'H', snapshotId: r, staged: true,
    entities: [{ UserName: 'root' }],
  });

  assert.equal(repoView(db, 'accounts').rows.length, 0, 'nothing reaches a baseline unseen');
  assert.equal(hostsIn(db, 'accounts').length, 0);
  assert.deepEqual(queryBaseline(db, { repo: 'accounts' }), []);
});

test('ordinary staging commits on arrival, so the default is not a trap', () => {
  const db = fresh();
  stageSnapshot(db, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  assert.equal(repoView(db, 'accounts').rows.length, 1);
});

// --- staging and review -----------------------------------------------------

test('the preview reports per repository and per host, not just a total', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  const rt = run(db, 'scheduled-tasks');
  stageSnapshot(db, { repo: 'accounts', host: 'A', snapshotId: r, staged: true,
    sourceFormat: 'Velociraptor', claimedRows: 2, entities: [{ UserName: 'root' }, { UserName: 'ftp' }] });
  stageSnapshot(db, { repo: 'scheduled-tasks', host: 'B', snapshotId: rt, staged: true,
    entities: [{ taskPath: '\Updater' }] });

  const p = stagedPreview(db);
  assert.equal(p.length, 2, 'one entry per upload, not one lump');
  const acc = p.find(x => x.repo === 'accounts');
  assert.equal(acc.host, 'A');
  assert.equal(acc.rows, 2);
  assert.equal(acc.sourceFormat, 'Velociraptor');
  assert.ok(acc.samples.length, 'samples are what make a wrong extraction visible');
});

test('the preview flags the three things that went wrong before', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  // no host at all
  const a = stageSnapshot(db, { repo: 'accounts', snapshotId: r, staged: true, entities: [{ UserName: 'x' }] });
  // a host this repository has never seen
  const b = stageSnapshot(db, { repo: 'accounts', host: 'BRAND-NEW', snapshotId: r, staged: true,
    entities: [{ UserName: 'y' }] });
  // fewer rows than the model claimed
  const c = stageSnapshot(db, { repo: 'accounts', host: 'Z', snapshotId: r, staged: true,
    claimedRows: 40, entities: [{ UserName: 'z' }] });

  const p = stagedPreview(db);
  assert.equal(p.find(x => x.id === a.id).unattributed, true);
  assert.equal(p.find(x => x.id === b.id).newHost, true);
  assert.equal(p.find(x => x.id === c.id).status, 'incomplete');
});

test('committing makes staged rows visible, and only those asked for', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  const a = stageSnapshot(db, { repo: 'accounts', host: 'A', snapshotId: r, staged: true,
    entities: [{ UserName: 'root' }] });
  const b = stageSnapshot(db, { repo: 'accounts', host: 'B', snapshotId: r, staged: true,
    entities: [{ UserName: 'root' }] });

  assert.equal(repoView(db, 'accounts').rows.length, 0);
  assert.equal(commitStaged(db, [a.id]), 1);
  assert.equal(repoView(db, 'accounts').rows.length, 1, 'only the committed one');
  assert.equal(stagedPreview(db).length, 1, 'the other is still held');
  commitStaged(db, [b.id]);
  assert.equal(repoView(db, 'accounts').rows.length, 2);
});

test('committing twice does not double-count', () => {
  const db = fresh();
  const a = stageSnapshot(db, { repo: 'accounts', host: 'A', snapshotId: run(db, 'accounts'), staged: true,
    entities: [{ UserName: 'root' }] });
  assert.equal(commitStaged(db, [a.id]), 1);
  assert.equal(commitStaged(db, [a.id]), 0, 'already committed');
});

test('discarding removes the rows entirely, leaving no husk', () => {
  const db = fresh();
  const a = stageSnapshot(db, { repo: 'accounts', host: 'A', snapshotId: run(db, 'accounts'), staged: true,
    entities: [{ UserName: 'root' }, { UserName: 'ftp' }] });
  assert.equal(discardStaged(db, [a.id]), 1);
  assert.equal(stagedPreview(db).length, 0);
  assert.equal(db.prepare('select count(*) n from char_entities').get().n, 0);
  assert.equal(db.prepare('select count(*) n from char_uploads').get().n, 0);
});

test('a committed upload cannot be discarded by mistake', () => {
  const db = fresh();
  const a = stageSnapshot(db, { repo: 'accounts', host: 'A', entities: [{ UserName: 'root' }] });
  assert.equal(discardStaged(db, [a.id]), 0, 'only staged uploads are discardable');
  assert.equal(repoView(db, 'accounts').rows.length, 1);
});

test('a mis-attributed host is fixed before commit, rows and all', () => {
  const db = fresh();
  const a = stageSnapshot(db, { repo: 'accounts', host: 'WRONG', snapshotId: run(db, 'accounts'), staged: true,
    entities: [{ UserName: 'root' }] });
  const fixed = reattributeStaged(db, a.id, 'RIGHT');
  assert.equal(fixed.host, 'RIGHT');
  commitStaged(db, [a.id]);
  assert.equal(repoView(db, 'accounts').rows[0].host, 'RIGHT', 'the rows moved with the upload');
});

test('reattributing something already committed is refused', () => {
  const db = fresh();
  const a = stageSnapshot(db, { repo: 'accounts', host: 'A', entities: [{ UserName: 'root' }] });
  assert.throws(() => reattributeStaged(db, a.id, 'B'), /no such staged upload/);
});

// --- corrections ------------------------------------------------------------

test('a correction keeps the collected value and writes to the audit log', () => {
  const db = fresh();
  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'H',
    entities: [{ UserName: 'svc_backup', shell: '/bin/false' }] });
  const row = repoView(db, 'accounts').rows[0];

  const out = correctEntity(db, row.id, {
    attrs: { shell: '/bin/bash' }, reason: 'collector reported the wrong shell', actor: 'Lindqvist',
  });
  assert.equal(out.attrs.shell, '/bin/bash');
  assert.equal(JSON.parse(out.collected_attrs).shell, '/bin/false', 'what was observed is kept');
  assert.equal(out.edited_by, 'Lindqvist');
  assert.equal(db.prepare("select count(*) n from audit where action = 'characterization.correct'").get().n, 1);
});

test('an identity field cannot be corrected', () => {
  const db = fresh();
  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  const row = repoView(db, 'accounts').rows[0];
  assert.throws(
    () => correctEntity(db, row.id, { attrs: { UserName: 'toor' }, reason: 'typo' }),
    /part of the row identity/);
});

test('a correction needs a reason', () => {
  const db = fresh();
  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'H', entities: [{ UserName: 'root', shell: '/x' }] });
  const row = repoView(db, 'accounts').rows[0];
  assert.throws(() => correctEntity(db, row.id, { attrs: { shell: '/y' } }), /needs a reason/);
});

test('reattributing moves the row between host groups without touching identity', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  stage(db, r, { repo: 'accounts', host: 'WRONG', entities: [{ UserName: 'root' }] });
  stage(db, r, { repo: 'accounts', host: 'RIGHT', entities: [{ UserName: 'other' }] });
  const row = repoView(db, 'accounts').rows.find(x => x.host === 'WRONG');

  reattributeEntity(db, row.id, { host: 'RIGHT', reason: 'model guessed the wrong box', actor: 'Lindqvist' });
  const v = repoView(db, 'accounts');
  assert.equal(v.rows.filter(x => x.host === 'RIGHT').length, 2);
  assert.equal(v.rows.filter(x => x.host === 'WRONG').length, 0);
  assert.equal(db.prepare("select count(*) n from audit where action = 'characterization.reattribute'").get().n, 1);
});

/*
  The refusal that keeps a moved row from becoming an orphan. A manual upload
  does not establish presence, so a row moved into a snapshot that never
  collected this host would sit where no view could ever show it.
*/
test('a move into a snapshot that never collected the host is refused', () => {
  const db = fresh();
  const a = run(db, 'accounts');
  const b = run(db, 'accounts');
  stage(db, a, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  stage(db, b, { repo: 'accounts', host: 'OTHER', entities: [{ UserName: 'root' }] });
  const row = repoView(db, 'accounts').rows.find(x => x.host === 'H');

  assert.throws(() => moveEntity(db, row.id, { snapshotId: b, reason: 'wrong run' }),
    /never collected this host/);
});

test('a legitimate move lands the row in the target snapshot', () => {
  const db = fresh();
  const a = run(db, 'accounts');
  const b = run(db, 'accounts');
  stage(db, a, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }, { UserName: 'stray' }] });
  stage(db, b, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });

  const stray = repoView(db, 'accounts', { snapshot: a }).rows.find(x => x.label === 'stray');
  moveEntity(db, stray.id, { snapshotId: b, reason: 'collected in the later run', actor: 'Lindqvist' });

  const inB = repoView(db, 'accounts', { snapshot: b }).rows.map(x => x.label).sort();
  assert.deepEqual(inB, ['root', 'stray']);
  assert.equal(db.prepare("select count(*) n from audit where action = 'characterization.move'").get().n, 1);
});

test('moving a row does not make the rest of the host disappear', () => {
  const db = fresh();
  const a = run(db, 'accounts');
  const b = run(db, 'accounts');
  const many = Array.from({ length: 47 }, (_, i) => ({ UserName: `u${i}` }));
  stage(db, a, { repo: 'accounts', host: 'H', entities: many });
  stage(db, b, { repo: 'accounts', host: 'H', entities: many });

  const one = repoView(db, 'accounts', { snapshot: a }).rows[0];
  moveEntity(db, one.id, { snapshotId: b, reason: 'test', actor: 'Lindqvist' });

  assert.equal(repoView(db, 'accounts').counts.gone, 0, 'the other forty-six survive');
});

// --- filters ----------------------------------------------------------------

test('column filters run over the whole repository, before truncation', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  const rows = Array.from({ length: 600 }, (_, i) => ({ UserName: `user${i}`, shell: '/bin/false' }));
  rows.push({ UserName: 'needle', shell: '/bin/bash' });
  stage(db, r, { repo: 'accounts', host: 'H', entities: rows });

  assert.equal(repoView(db, 'accounts').rows.length, 601);

  const hit = repoView(db, 'accounts', { filters: { username: 'needle' } });
  assert.equal(hit.rows.length, 1, 'found past the 500 the table would render');
  assert.equal(hit.matched, 1, 'and the reported total is the filtered total');
});

test('column filters compose, and match against display values', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  stage(db, r, { repo: 'accounts', host: 'A', entities: [{ UserName: 'root', shell: '/bin/bash' }] });
  stage(db, r, { repo: 'accounts', host: 'B', entities: [{ UserName: 'root', shell: '/bin/false' }] });

  assert.equal(repoView(db, 'accounts', { filters: { host: 'A' } }).rows.length, 1);
  assert.equal(repoView(db, 'accounts', { filters: { username: 'root', host: 'B' } }).rows.length, 1);
  assert.equal(repoView(db, 'accounts', { filters: { username: 'nobody' } }).rows.length, 0);
});

test('filtering on change surfaces only the delta', () => {
  const db = fresh();
  const a = run(db, 'accounts');
  const b = run(db, 'accounts');
  stage(db, a, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }] });
  stage(db, b, { repo: 'accounts', host: 'H', entities: [{ UserName: 'root' }, { UserName: 'svc_new' }] });

  const v = repoView(db, 'accounts', { filters: { change: 'new' } });
  assert.equal(v.rows.length, 1);
  assert.equal(v.rows[0].label, 'svc_new');
});

/*
  The same refusal, one function over. A row reattributed to a host this
  snapshot never collected lands in a manual upload, and manual uploads do not
  establish presence — so repoView, hostCharacterization and queryBaseline all
  stop being able to see it. It was still in char_entities and reachable from
  nowhere, which is the orphan moveEntity already refuses to make.
*/
test('reattributing to a host this snapshot never collected is refused', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  stage(db, r, { repo: 'accounts', host: 'WRONG', entities: [{ UserName: 'root' }] });
  const row = repoView(db, 'accounts').rows.find(x => x.host === 'WRONG');

  assert.throws(() => reattributeEntity(db, row.id,
    { host: 'NEVER-COLLECTED', reason: 'the model guessed', actor: 'Lindqvist' }),
  /never collected NEVER-COLLECTED/);
  assert.equal(repoView(db, 'accounts').rows.filter(x => x.host === 'WRONG').length, 1,
    'the row stays where it is, visible, rather than vanishing');
});

/*
  What was COLLECTED survives every correction, not just the first.

  collected_attrs exists so the observed value can always be recovered — that
  is the whole difference between a correction and an edit. Written as a plain
  assignment rather than coalesce, the second correction of the same row
  overwrote the collected value with the first correction's, and the original
  observation was gone with nothing to say so. One correction cannot tell the
  two implementations apart, and one correction was all this file tested.
*/
test('a second correction still keeps what the collector reported', () => {
  const db = fresh();
  stage(db, run(db, 'accounts'), { repo: 'accounts', host: 'H',
    entities: [{ UserName: 'svc_backup', shell: '/bin/false' }] });
  const row = repoView(db, 'accounts').rows[0];

  correctEntity(db, row.id, { attrs: { shell: '/bin/bash' }, reason: 'first', actor: 'Lindqvist' });
  const out = correctEntity(db, row.id, { attrs: { shell: '/bin/zsh' }, reason: 'second', actor: 'Okafor' });

  assert.equal(out.attrs.shell, '/bin/zsh', 'the correction applies');
  assert.equal(JSON.parse(out.collected_attrs).shell, '/bin/false',
    'the second correction overwrote what the collector actually reported');
});

/*
  The review queue is per session. An analyst opening it sees what THEY sent
  for extraction; showing everybody's staged imports invites one person to
  commit another's, into a baseline the whole estate is measured against.
*/
test('the staged queue is scoped to the session that sent it', () => {
  const db = fresh();
  const r = run(db, 'accounts');
  stage(db, r, { repo: 'accounts', host: 'MINE', sessionId: 's-mine', staged: true,
    entities: [{ UserName: 'root' }] });
  stage(db, r, { repo: 'accounts', host: 'THEIRS', sessionId: 's-theirs', staged: true,
    entities: [{ UserName: 'other' }] });

  assert.deepEqual(stagedPreview(db, { sessionId: 's-mine' }).map(u => u.host), ['MINE']);
  assert.deepEqual(stagedPreview(db, { sessionId: 's-theirs' }).map(u => u.host), ['THEIRS']);
  assert.equal(stagedPreview(db).length, 2, 'unscoped still sees the whole queue');
});
