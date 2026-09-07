import { test } from 'node:test';
import assert from 'node:assert';
import { terrainNamer } from '../lib/terrain-names.js';
import { openDb, initSchema } from '../store/db.js';
import { createCharSnapshot, stageSnapshot, repoView, colValue } from '../store/characterization.js';

/*
  Lining an exported identifier up with terrain, and the two ways that went
  wrong on real data.
*/

const TERRAIN = [
  { ip: '192.0.2.21', name: 'WKS-01.range.example' },
  { ip: '10.20.40.1', name: '10.20.40.1' },
  { ip: '10.124.10.111', name: 'PLC-B' },
  { ip: '10.125.10.111', name: 'PLC-B' },
];

test('an exact address wins', () => {
  const name = terrainNamer(TERRAIN);
  assert.equal(name('192.0.2.21'), 'WKS-01.range.example');
});

test('a short name is expanded to what terrain calls it', () => {
  const name = terrainNamer(TERRAIN);
  assert.equal(name('WKS-01'), 'WKS-01.range.example');
  assert.equal(name('wks-01.other.suffix'), 'WKS-01.range.example');
});

/*
  The one that bit. The short-name fallback split on the dot, so the first
  octet of any address became a "short name" — and terrain holds a host
  literally named 10.20.40.1, whose short name is "10". Dozens of distinct
  scanned addresses collapsed onto that one machine.
*/
test('an unknown address is itself, never the first host whose name starts 10', () => {
  const name = terrainNamer(TERRAIN);
  for (const ip of ['10.125.10.255', '10.124.10.0', '10.20.20.7', '10.99.99.99']) {
    assert.equal(name(ip), ip, ip);
  }
  // The host that really is named after its address still resolves to itself.
  assert.equal(name('10.20.40.1'), '10.20.40.1');
});

/*
  The second one. Terrain deliberately holds PLC-B twice, once
  per substation subnet. Answering with the name merges two devices and hands
  back the union of their open ports as though it were one box.
*/
test('a name two machines share cannot identify either of them', () => {
  const name = terrainNamer(TERRAIN);
  assert.equal(name('10.124.10.111'), '10.124.10.111');
  assert.equal(name('10.125.10.111'), '10.125.10.111');
  assert.notEqual(name('10.124.10.111'), name('10.125.10.111'));
});

test('a non-host is null rather than a host called nothing', () => {
  const name = terrainNamer(TERRAIN);
  for (const v of ['', '   ', null, undefined, 'System.Object[]']) assert.equal(name(v), null, String(v));
});

// --- the repositories those datasets needed ------------------------------------

const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };
const put = (db, repo, host, entities) => stageSnapshot(db, {
  repo, host, entities, snapshotId: createCharSnapshot(db, { repo, createdBy: 'Lindqvist' }).id,
});

test('a named pipe is keyed on its path, not on the process holding it', () => {
  const db = fresh();
  const pipe = (pid) => ({
    'host.name': 'WKS-01', 'file.name': 'InitShutdown',
    'file.path': '\\\\.\\pipe\\InitShutdown', 'process.id': pid, 'process.path': 'C:/svc.exe',
  });
  put(db, 'named-pipes', 'WKS-01', [pipe('576')]);
  put(db, 'named-pipes', 'WKS-01', [pipe('912')]);   // same pipe after a reboot

  const v = repoView(db, 'named-pipes');
  assert.equal(v.rows.length, 1, 'a new PID is not a new pipe');
  assert.equal(v.counts.new, 0);
  // host.name must not claim the bare "name" ahead of file.name.
  assert.equal(v.rows[0].display.name, 'InitShutdown');
  assert.equal(v.rows[0].display.processPath, 'C:/svc.exe');
});

test('a BITS job is keyed on name, owner and destination, never its GUID', () => {
  const db = fresh();
  const job = (id) => ({
    'bits.name': 'Font Download', 'bits.id': id, 'bits.owner': 'NT AUTHORITY\\LOCAL SERVICE',
    'bits.file.remote': 'https://fs.microsoft.test/config.json',
    'bits.file.local': 'C:/Windows/Temp/wct' + id + '.tmp',
  });
  put(db, 'bits-jobs', 'H', [job('aaa')]);
  put(db, 'bits-jobs', 'H', [job('bbb')]);
  assert.equal(repoView(db, 'bits-jobs').rows.length, 1, 'a fresh GUID is not a fresh job');

  // Two people with the same job name and URL are two jobs.
  const db2 = fresh();
  put(db2, 'bits-jobs', 'H', [
    { 'bits.name': 'OAB', 'bits.owner': 'EXAMPLE\\alice', 'bits.file.remote': 'https://ex.test/OAB' },
    { 'bits.name': 'OAB', 'bits.owner': 'EXAMPLE\\bob', 'bits.file.remote': 'https://ex.test/OAB' },
  ]);
  assert.equal(repoView(db2, 'bits-jobs').rows.length, 2);
});

test('a scanned service is keyed on port and protocol', () => {
  const db = fresh();
  put(db, 'network-services', '10.20.20.5', [
    { port: '80', protocol: 'tcp', state: 'open', service: 'http', version: 'lighttpd 1.4.55' },
    { port: '502', protocol: 'tcp', state: 'open', service: 'mbap' },
  ]);
  const v = repoView(db, 'network-services');
  assert.equal(v.rows.length, 2);
  assert.deepEqual(v.rows.map(r => r.display.port).sort(), ['502', '80']);
  assert.equal(v.rows.find(r => r.display.port === '80').display.version, 'lighttpd 1.4.55');
});

test('a run-key export lands in persistence under the right columns', () => {
  const db = fresh();
  put(db, 'persistence', 'DC-01', [{
    'host.name': 'DC-01', 'user.name': 'NT AUTHORITY\\LOCAL SERVICE',
    'registry.path': 'HKEY_USERS\\S-1-5-19\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
    'registry.key': 'Device', 'registry.value': 'winspool',
  }]);
  const [row] = repoView(db, 'persistence').rows;
  // The name column is the value name, NOT the user — a bare "name" in one of
  // these exports is user.name, and it used to win.
  assert.equal(row.display.name, 'Device');
  assert.equal(row.display.value, 'winspool');
  assert.equal(row.display.user, 'NT AUTHORITY\\LOCAL SERVICE');
  assert.match(row.display.location, /CurrentVersion/);
});

test('host and os columns never masquerade as the row own name', () => {
  const row = { 'host.name': 'THE-HOST', 'os.name': 'Windows 10', 'task.name': 'Updater' };
  assert.equal(colValue('scheduled-tasks', row, 'name'), 'Updater');
});
