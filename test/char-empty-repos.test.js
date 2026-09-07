import { test, before } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { stageSnapshot, repoView, summary } from '../store/characterization.js';

/*
  Whether `listening-ports` and `spns` are empty because nobody collected them
  or because ingest quietly dropped what was collected.

  From the UI those look identical, and the difference decides whether the next
  person goes and runs a collection or goes looking for a bug. Answered here by
  pushing what the real collectors actually emit through the ingest path and
  seeing what survives, so nobody has to decide it by reading the code again.

  The check is not only "did the rows land". A row whose field names the
  repository does not recognise still lands — stageSnapshot falls back to
  hashing the row's content rather than dropping it, which is the right call —
  but it lands under an identity that changes whenever any field changes. Those
  rows never diff against the next collection: every one reads as gone and a new
  one as new, forever. That failure is invisible until somebody takes a second
  snapshot, so it is worth asserting now while both repositories are empty and
  the cost of being wrong is nothing.
*/

let db;
before(() => { db = openDb(':memory:'); initSchema(db); });

/** The content-hash fallback stageSnapshot uses for a row it cannot name. */
const unnamed = (rows) => rows.filter(r => String(r.ident).startsWith('raw:'));

const identsIn = (repo) =>
  db.prepare('select ident, host from char_entities where repo = ?').all(repo);

// --- listening ports ---------------------------------------------------------------

/*
  Three shapes, because the estate is mixed and each tool names things its own
  way: PowerShell returns PascalCase objects, ss returns lower-case columns, and
  netstat returns something else again. All three are plausible on this estate,
  so all three have to be recognised by the same repository.
*/
test('listening-ports keeps every row a real collector would produce', () => {
  const out = stageSnapshot(db, {
    repo: 'listening-ports', host: 'RL-01.range.example', sourceFormat: 'Get-NetTCPConnection',
    entities: [
      { LocalAddress: '0.0.0.0', LocalPort: 22, State: 'Listen', OwningProcess: 'sshd', Protocol: 'TCP' },
      { LocalAddress: '0.0.0.0', LocalPort: 8080, State: 'Listen', OwningProcess: 'java', Protocol: 'TCP' },
      { LocalAddress: '127.0.0.1', LocalPort: 5432, State: 'Listen', OwningProcess: 'postgres', Protocol: 'TCP' },
    ],
  });
  assert.equal(out.returned_rows, 3);
  assert.equal(out.extracted_rows, 3, 'ingest dropped a row it was given');
});

test('an ss-shaped row and a netstat-shaped row are both understood', () => {
  const ss = stageSnapshot(db, {
    repo: 'listening-ports', host: 'RL-02.range.example', sourceFormat: 'ss -ltnp',
    entities: [{ netid: 'tcp', 'local address': '0.0.0.0', port: 111, process: 'rpcbind' }],
  });
  const netstat = stageSnapshot(db, {
    repo: 'listening-ports', host: 'WKS-04.range.example', sourceFormat: 'netstat -ano',
    entities: [{ Proto: 'TCP', 'Local Address': '0.0.0.0:445', Port: 445, PID: 4, Program: 'System' }],
  });
  assert.equal(ss.extracted_rows, 1);
  assert.equal(netstat.extracted_rows, 1);
});

/*
  The one that would have gone unnoticed. A row stored under a content hash is
  not lost, but it is not comparable either, so the repository would look like
  it worked right up until the second collection.
*/
test('every listening-ports row is named by its own fields, not by a content hash', () => {
  const raw = unnamed(identsIn('listening-ports'));
  assert.deepEqual(raw.map(r => r.ident), [],
    'these rows fell back to a content hash and will never diff against the next collection');
});

test('two ports on one host stay two rows', () => {
  const rows = identsIn('listening-ports').filter(r => r.host === 'RL-01.range.example');
  assert.equal(new Set(rows.map(r => r.ident)).size, rows.length, 'distinct ports folded together');
  assert.equal(rows.length, 3);
});

// --- SPNs --------------------------------------------------------------------------

/*
  Domain-scoped rather than host-scoped, so it takes a different path through
  ingest than every host repository above and is worth exercising separately.
*/
test('spns keeps every row a real collector would produce', () => {
  const out = stageSnapshot(db, {
    repo: 'spns', host: 'range.example', sourceFormat: 'setspn -Q */*',
    entities: [
      { account: 'svc_sql', spn: 'MSSQLSvc/db-01.range.example:1433' },
      { account: 'svc_web', spn: 'HTTP/www.range.example' },
    ],
  });
  assert.equal(out.extracted_rows, 2, 'ingest dropped an SPN it was given');
});

test('the ActiveDirectory spelling is understood too', () => {
  const out = stageSnapshot(db, {
    repo: 'spns', host: 'range.example', sourceFormat: 'Get-ADUser -Properties ServicePrincipalName',
    entities: [
      { SamAccountName: 'svc_backup', ServicePrincipalName: 'CIFS/backup.range.example',
        PasswordLastSet: '2024-01-04', Privileged: false },
    ],
  });
  assert.equal(out.extracted_rows, 1);
});

test('every spns row is named by its own fields, not by a content hash', () => {
  const raw = unnamed(identsIn('spns'));
  assert.deepEqual(raw.map(r => r.ident), [],
    'these rows fell back to a content hash and will never diff against the next collection');
});

test('one account holding two SPNs stays two rows', () => {
  stageSnapshot(db, {
    repo: 'spns', host: 'range.example',
    entities: [
      { account: 'svc_multi', spn: 'HTTP/a.range.example' },
      { account: 'svc_multi', spn: 'HTTP/b.range.example' },
    ],
  });
  const rows = identsIn('spns').filter(r => String(r.ident).includes('svc_multi'));
  assert.equal(rows.length, 2, 'two SPNs on one account collapsed into one row');
});

/*
  The failure the issue actually asks about: could a collection have arrived and
  been thrown away for having field names nothing recognised?

  This is the shape that caused the original loss — seventeen uploads reported
  extracting dozens of rows and stored none, because a row with no identity was
  skipped and 47 == 47 looked healthy the whole way. The guard is that an
  unrecognised row is stored under a content hash instead of being dropped.

  Written after the fact, and worth saying why: with only realistic rows above,
  deleting that guard entirely still passed every test here, because no sample
  ever reached it. A test that cannot fail is not evidence.
*/
test('a row whose fields nothing recognises is still stored, never dropped', () => {
  const before = identsIn('listening-ports').length;
  const out = stageSnapshot(db, {
    repo: 'listening-ports', host: 'RL-09.range.example', sourceFormat: 'something unheard of',
    entities: [
      { wibble: 'tcp', flange: 9999, grommet: 'unknown-daemon' },
      { wibble: 'udp', flange: 5353, grommet: 'mdns' },
    ],
  });
  assert.equal(out.extracted_rows, 2, 'rows were dropped for having unfamiliar field names');
  assert.equal(identsIn('listening-ports').length, before + 2);
});

test('and it is marked as unnamed rather than passed off as understood', () => {
  const raw = unnamed(identsIn('listening-ports'));
  assert.equal(raw.length, 2,
    'an unrecognised row must be distinguishable from one the repository could name');
});

// --- what the answer means ----------------------------------------------------------

test('both repositories read back through the view the analyst uses', () => {
  for (const repo of ['listening-ports', 'spns']) {
    const v = repoView(db, repo);
    assert.ok(v.rows.length > 0, `${repo} stored rows that the view cannot see`);
  }
});

/*
  The conclusion, asserted rather than left in a comment: with rows pushed
  through, both repositories report content. So an empty one in a real store
  means the collection was never run — not that ingest ate it.
*/
test('a repository is only empty when nothing was collected into it', () => {
  const byKey = Object.fromEntries(summary(db).map(r => [r.key, r]));
  assert.ok(byKey['listening-ports'].hosts > 0);
  assert.ok(byKey.spns.hosts > 0);

  // And one nobody has touched in this test stays empty, so the assertion above
  // is measuring ingest rather than measuring nothing.
  assert.equal(byKey.software.hosts, 0);
});
