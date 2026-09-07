import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { seedHosts, listHosts, resolveHost, setVerdict, normalizeIp, getHost } from '../store/hosts.js';
import { seedThreads, listThreads } from '../store/threads.js';

const fresh = () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db);
  return db;
};

test('seeded hosts all carry source=seeded', () => {
  const hosts = listHosts(fresh());
  assert.ok(hosts.length >= 8, `expected the profile's terrain, got ${hosts.length}`);
  assert.ok(hosts.every(h => h.source === 'seeded'));
});

test('seeding twice does not duplicate', () => {
  const db = fresh();
  const n = listHosts(db).length;
  seedHosts(db);
  assert.equal(listHosts(db).length, n);
});

// An inventory that lists two hosts at one address is almost certainly a typo
// at the source, but the store must not paper over it by dropping a host — the
// operator should see both and decide. Both profiles carry such a pair.
test('two hosts sharing an address are both kept', () => {
  const shared = listHosts(fresh()).filter(h => h.ip === '10.40.1.5');
  assert.deepEqual(shared.map(h => h.name).sort(), ['ControlThings', 'Sift']);
});

test('threads come from the profile, and seeding twice does not duplicate', () => {
  const db = fresh();
  seedThreads(db);
  const once = listThreads(db).map(t => t.key);
  seedThreads(db);
  assert.deepEqual(listThreads(db).map(t => t.key), once);
  assert.ok(once.length > 0, 'the example profile declares some');
});

/*
  Threads are what a hunt discovers, not what it is issued with. They used to
  be a const holding one exercise's actors and one team's names, so every new
  mission started by inheriting somebody else's threads.
*/
test('a profile with no threads file gets no threads', () => {
  const db = openDb(':memory:');
  initSchema(db);
  assert.equal(seedThreads(db, []), 0);
  assert.deepEqual(listThreads(db), []);
});

test('known ip resolves without creating a row', () => {
  const db = fresh();
  const before = listHosts(db).length;
  const id = resolveHost(db, { ip: '10.20.1.11' });
  assert.ok(id);
  assert.equal(getHost(db, id).name, 'EX-FILE.example.test');
  assert.equal(listHosts(db).length, before);
});

test('an FQDN resolves to its terrain entry rather than inventing one', () => {
  // A survey turns a bare inventory label into an FQDN, so evidence naming
  // that host by its full name must land on the row already there.
  const db = fresh();
  const before = listHosts(db).length;
  const id = resolveHost(db, { hostname: 'EX-FILE.example.test', ip: null });
  assert.equal(getHost(db, id).source, 'seeded');
  assert.equal(getHost(db, id).ip, '10.20.1.11');
  assert.equal(listHosts(db).length, before, 'no duplicate is created');
});

test('unmapped ip creates exactly one discovered host, idempotently', () => {
  // 10.21.2.16 is now known terrain (EX2-RL-6), so this uses an address
  // the survey has never seen.
  const db = fresh();
  const before = listHosts(db).length;
  const id = resolveHost(db, { ip: '203.0.113.77' });
  assert.equal(listHosts(db).length, before + 1);
  assert.equal(getHost(db, id).source, 'discovered');
  assert.equal(resolveHost(db, { ip: '203.0.113.77' }), id);
  assert.equal(listHosts(db).length, before + 1);
});

test('an address with a port resolves to the same host as without', () => {
  const db = fresh();
  const a = resolveHost(db, { ip: '203.0.113.25:443' });
  const b = resolveHost(db, { ip: '203.0.113.25' });
  assert.equal(a, b);
});

test('values that identify nothing resolve to null', () => {
  const db = fresh();
  const before = listHosts(db).length;
  for (const junk of [{}, { ip: 'N/A' }, { hostname: '' }, { ip: 'Not collected' }, { hostname: '-' }]) {
    assert.equal(resolveHost(db, junk), null, JSON.stringify(junk));
  }
  assert.equal(listHosts(db).length, before, 'junk must not create hosts');
});

test('normalizeIp extracts the address and rejects nonsense', () => {
  assert.equal(normalizeIp('203.0.113.101:9861'), '203.0.113.101');
  assert.equal(normalizeIp('10.21.1.20 (web)'), '10.21.1.20');
  assert.equal(normalizeIp('999.1.1.1'), null);
  assert.equal(normalizeIp('N/A'), null);
  assert.equal(normalizeIp(null), null);
});

test('verdict records who and when, and writes one audit row', () => {
  const db = fresh();
  const id = resolveHost(db, { ip: '10.20.1.11' });
  const h = setVerdict(db, id, 'confirmed', 'Lindqvist');
  assert.equal(h.verdict, 'confirmed');
  assert.equal(h.verdict_by, 'Lindqvist');
  assert.ok(h.verdict_at);
  assert.equal(db.prepare('select count(*) c from audit where target_id = ?').get(id).c, 1);
});

test('a terrain with no survey data defaults to unsurveyed', () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db, [{ name: 'Plain', ip: '10.9.9.9', enclave: 'X', segment: 'y', cidr: '10.9.9.0/24' }]);
  assert.equal(listHosts(db)[0].presence, 'unsurveyed');
});

test('a host discovered from evidence is not claimed to be alive', () => {
  // Referenced in a record is a weaker claim than answered on the wire.
  const db = fresh();
  const id = resolveHost(db, { ip: '203.0.113.25' });
  const h = getHost(db, id);
  assert.equal(h.presence, 'evidence-only');
  assert.match(h.presence_note, /not surveyed/);
});

test('the presence column is added to a store that predates it', () => {
  // Simulates upgrading a server whose database already holds data.
  const db = openDb(':memory:');
  db.exec(`CREATE TABLE hosts (id TEXT PRIMARY KEY, name TEXT NOT NULL, ip TEXT,
    enclave TEXT, segment TEXT, cidr TEXT, os TEXT, role TEXT,
    source TEXT NOT NULL CHECK (source IN ('seeded','discovered')),
    verdict TEXT NOT NULL DEFAULT 'unknown', verdict_by TEXT, verdict_at TEXT)`);
  db.prepare("insert into hosts (id,name,ip,source) values ('a','Old','203.0.113.4','seeded')").run();
  initSchema(db);
  const cols = db.prepare('pragma table_info(hosts)').all().map(c => c.name);
  assert.ok(cols.includes('presence'), 'migration adds presence');
  assert.ok(cols.includes('presence_note'), 'migration adds presence_note');
  assert.equal(db.prepare("select presence from hosts where id='a'").get().presence, 'unsurveyed');
});

// --- re-seeding when the terrain changes -----------------------------------

test('re-seeding updates a relocated host in place rather than duplicating it', () => {
  // The survey moves EX-DC from .2 to .11 and gives it an FQDN. That is the
  // same box, not a new one: the old row must not survive alongside it, the id
  // must persist so audit history still resolves, and the analyst's verdict
  // must not be reset by a survey.
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db, [{ name: 'DC', ip: '10.20.1.2', enclave: 'Enclave A', segment: 'servers', cidr: '10.20.1.0/24' }]);
  const first = listHosts(db)[0];
  setVerdict(db, first.id, 'suspected', 'Lindqvist');

  seedHosts(db, [{
    name: 'EX-DC.example.test', ip: '10.20.1.10', enclave: 'Enclave A', segment: 'servers',
    cidr: '10.20.1.0/24', presence: 'relocated', presenceNote: 'moved', domainJoined: true,
  }]);

  const rows = listHosts(db);
  assert.equal(rows.length, 1, 'one host, not two');
  assert.equal(rows[0].id, first.id, 'the id survives so audit history still resolves');
  assert.equal(rows[0].ip, '10.20.1.10');
  assert.equal(rows[0].name, 'EX-DC.example.test');
  assert.equal(rows[0].presence, 'relocated');
  assert.equal(rows[0].verdict, 'suspected', 'the analyst verdict is not reset by a survey');
});

test('a seeded host the terrain drops is removed, and a lost verdict is reported', () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db, [{ name: 'Gone', ip: '10.1.1.1' }, { name: 'Stays', ip: '10.1.1.2' }]);
  const gone = listHosts(db).find(h => h.name === 'Gone');
  setVerdict(db, gone.id, 'confirmed', 'Lindqvist');

  const res = seedHosts(db, [{ name: 'Stays', ip: '10.1.1.2' }]);
  assert.deepEqual(listHosts(db).map(h => h.name), ['Stays']);
  assert.equal(res.orphanedVerdicts.length, 1, 'the discarded verdict is surfaced, not swallowed');
  assert.equal(res.orphanedVerdicts[0].verdict, 'confirmed');
});

test('seeding the profile terrain absorbs evidence-discovered duplicates', () => {
  const db = openDb(':memory:');
  initSchema(db);
  // Evidence found this address before any survey named it.
  resolveHost(db, { ip: '10.30.2.100' });
  assert.equal(listHosts(db).filter(h => h.ip === '10.30.2.100').length, 1);

  const result = seedHosts(db);
  const at16 = listHosts(db).filter(h => h.ip === '10.30.2.100');
  assert.equal(at16.length, 1, 'the address appears exactly once after seeding');
  assert.equal(at16[0].source, 'seeded', 'and it is the terrain entry that survives');
  assert.ok(Array.isArray(result.absorbed));
});

test('terrain fields reach the store', () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db);
  const hosts = listHosts(db);
  assert.ok(hosts.some(h => h.presence === 'alive-unidentified'), 'presence is carried');
  assert.ok(hosts.some(h => h.domain_joined === 1), 'domain_joined is carried');
  assert.ok(hosts.some(h => h.domain_joined === 0), 'and non-joined hosts are marked');
  assert.ok(hosts.some(h => h.observed_from), 'vantage provenance is carried');
});

test('a relocation is not mistaken for a host in another enclave', () => {
  // Both enclaves record a "DC". A Enclave A relocation must not claim Enclave B's.
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db, [
    { name: 'DC', ip: '10.20.1.2', enclave: 'Enclave A', segment: 'servers', cidr: '10.20.1.0/24' },
    { name: 'DC', ip: '10.21.8.250', enclave: 'Enclave B', segment: 'domain servers', cidr: '10.21.8.0/24' },
  ]);
  seedHosts(db, [
    { name: 'EX-DC.example.test', ip: '10.20.1.10', enclave: 'Enclave A', segment: 'servers', cidr: '10.20.1.0/24' },
    { name: 'EX2-DC.example2.test', ip: '10.21.8.250', enclave: 'Enclave B', segment: 'domain servers', cidr: '10.21.8.0/24' },
  ]);
  const rows = listHosts(db);
  assert.equal(rows.length, 2, 'still two hosts');
  assert.equal(rows.find(h => h.enclave === 'Enclave A').ip, '10.20.1.10');
  assert.equal(rows.find(h => h.enclave === 'Enclave B').ip, '10.21.8.250');
});

test('a store created before members can be upgraded in place', () => {
  // initSchema runs the schema block first, so anything depending on a
  // migrated column has to come after it. An index over sessions.member_id
  // placed in the schema block failed on every existing database while
  // passing on every fresh one.
  const db = openDb(':memory:');
  db.exec(`CREATE TABLE sessions (id TEXT PRIMARY KEY, title TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('chat','intake')), analyst TEXT,
    claude_session_id TEXT, state TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL)`);
  db.prepare("insert into sessions (id,title,kind,created_at) values ('s','old','chat','now')").run();
  db.exec(`CREATE TABLE messages (id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
    role TEXT NOT NULL, content TEXT NOT NULL, ts TEXT NOT NULL)`);

  assert.doesNotThrow(() => initSchema(db), 'migration must survive a pre-existing store');
  const cols = db.prepare('pragma table_info(sessions)').all().map(c => c.name);
  assert.ok(cols.includes('member_id'));
  assert.ok(db.prepare('pragma table_info(messages)').all().map(c => c.name).includes('mode'));
  assert.equal(db.prepare("select title from sessions where id='s'").get().title, 'old',
    'existing rows survive');
});

/*
  Seeding rewrites the whole seeded estate on every start: inserts, updates, a
  delete of absorbed rows whose records are reassigned first, then the hand
  corrections laid back on top. mergeHosts wraps the same shape in a
  transaction; this did not, so a throw partway left records pointing at a host
  that had been deleted and overrides never reapplied — at boot, where the
  operator's first sight of it is a map that is wrong.
*/
test('a terrain row that cannot be stored leaves the estate as it was', () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db, [
    { name: 'A-host', ip: '192.0.2.1', enclave: 'E', segment: 'S', os: 'Linux', role: 'app' },
    { name: 'B-host', ip: '192.0.2.2', enclave: 'E', segment: 'S', os: 'Linux', role: 'app' },
  ]);
  const before = listHosts(db).map(h => h.name).sort();
  assert.deepEqual(before, ['A-host', 'B-host']);

  // A value the driver cannot bind, midway through the run.
  assert.throws(() => seedHosts(db, [
    { name: 'A-host', ip: '192.0.2.1', enclave: 'E', segment: 'S', os: 'Linux', role: 'app' },
    { name: 'C-host', ip: '192.0.2.3', enclave: 'E', segment: 'S', os: { bad: 1 }, role: 'app' },
    { name: 'B-host', ip: '192.0.2.2', enclave: 'E', segment: 'S', os: 'Linux', role: 'app' },
  ]));

  assert.deepEqual(listHosts(db).map(h => h.name).sort(), before,
    'a failed seed left the estate half-rewritten');

  // And the next honest seed still works, so the transaction was not left open.
  seedHosts(db, [
    { name: 'A-host', ip: '192.0.2.1', enclave: 'E', segment: 'S', os: 'Linux', role: 'app' },
    { name: 'B-host', ip: '192.0.2.2', enclave: 'E', segment: 'S', os: 'Linux', role: 'app' },
  ]);
  assert.deepEqual(listHosts(db).map(h => h.name).sort(), before);
});
