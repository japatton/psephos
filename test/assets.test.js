import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import {
  seedHosts, resolveHost, matchHost, bindUnplacedRecords, listHosts, getHost,
  setHostOverride, hostOverrides, applyHostOverrides, mergeHosts, createHost,
  removeHost, hostEvidence,
} from '../store/hosts.js';
import { createRecord, getRecord, bindRecordHost, listRecords } from '../store/records.js';
import { stageSnapshot, createCharSnapshot, repoView } from '../store/characterization.js';

const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };

/** Two hosts sharing a short name, which is what the estate actually has. */
const TWO_WEBS = [
  { name: 'Web', ip: '10.20.1.12', enclave: 'Enclave A', segment: 'servers', os: 'Windows Server' },
  { name: 'Web', ip: '10.21.1.20', enclave: 'Enclave B', segment: 'dmz', os: 'Windows Server' },
  { name: 'EX-DC.example.test', ip: '10.20.1.10', enclave: 'Enclave A', segment: 'servers' },
];

/*
  The bug this whole change exists for. Two seeded hosts are both called "Web",
  a record said "Web (Enclave B DMZ)", and the short-name match put one rootkit
  finding on both of them while resolveHost bound it to whichever row came
  first. An unresolved host is recoverable; a confidently wrong one is not.
*/
test('an ambiguous short name resolves to nothing rather than to the wrong host', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  assert.equal(resolveHost(db, { hostname: 'Web (Enclave B DMZ)' }), null);
  // A name only one host answers to still resolves.
  assert.ok(resolveHost(db, { hostname: 'EX-DC' }));
});

test('a record remembers which host it landed on', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const dc = listHosts(db).find(h => h.ip === '10.20.1.10');
  const rec = createRecord(db, { hostname: 'EX-DC', description: 'x' }, { analyst: 'Lindqvist' });
  assert.equal(getRecord(db, rec.id).host_id, dc.id, 'resolveHost result is stored, not discarded');
});

test('an unresolvable record is left unbound rather than bound wrongly', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const rec = createRecord(db, { hostname: 'Web (Enclave B DMZ)', description: 'rootkit' });
  assert.equal(getRecord(db, rec.id).host_id, null);
});

test('binding by hand puts the finding on exactly one host', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const dmz = listHosts(db).find(h => h.ip === '10.21.1.20');
  const diad = listHosts(db).find(h => h.ip === '10.20.1.12');
  const rec = createRecord(db, { hostname: 'Web (Enclave B DMZ)', description: 'rootkit' });

  bindRecordHost(db, rec.id, dmz.id, { reason: 'record text names the DMZ host', analyst: 'Okafor' });
  const bound = getRecord(db, rec.id);
  assert.equal(bound.host_id, dmz.id);
  assert.notEqual(bound.host_id, diad.id);
  assert.equal(bound.host_bound_by, 'Okafor');
  assert.equal(db.prepare("select count(*) n from audit where action = 'record.bind'").get().n, 1);
});

test('binding to a host that does not exist is refused', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const rec = createRecord(db, { hostname: 'x', description: 'y' });
  assert.throws(() => bindRecordHost(db, rec.id, 'nope'), /no such host/);
});

// --- overrides ---------------------------------------------------------------

test('a pinned field survives a terrain re-seed', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const web = listHosts(db).find(h => h.ip === '10.20.1.12');

  setHostOverride(db, web.id, 'role', 'Enclave A public web', 'Lindqvist');
  assert.equal(getHost(db, web.id).role, 'Enclave A public web');

  seedHosts(db, TWO_WEBS);   // the survey runs again
  assert.equal(getHost(db, web.id).role, 'Enclave A public web', 'the correction outlived the re-seed');
});

test('an un-pinned field still tracks terrain across a re-seed', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const web = listHosts(db).find(h => h.ip === '10.20.1.12');
  setHostOverride(db, web.id, 'role', 'pinned role', 'Lindqvist');

  // A later survey learns the OS version. That must still reach the host.
  seedHosts(db, TWO_WEBS.map(h => h.ip === '10.20.1.12' ? { ...h, os: 'Windows Server 2019' } : h));
  const after = getHost(db, web.id);
  assert.equal(after.os, 'Windows Server 2019', 'terrain still owns what nobody pinned');
  assert.equal(after.role, 'pinned role');
});

test('clearing an override hands the field back to terrain', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const web = listHosts(db).find(h => h.ip === '10.20.1.12');
  setHostOverride(db, web.id, 'os', 'something wrong', 'Lindqvist');
  assert.equal(getHost(db, web.id).os, 'something wrong');

  setHostOverride(db, web.id, 'os', null, 'Lindqvist');
  // Immediately, not at the next restart: a revert that leaves the discarded
  // value sitting in the row reads as a revert that did nothing.
  assert.equal(getHost(db, web.id).os, 'Windows Server');
  assert.equal(hostOverrides(db, web.id).length, 0);

  seedHosts(db, TWO_WEBS);
  assert.equal(getHost(db, web.id).os, 'Windows Server');
});

test('re-pinning a field still reverts to terrain, not to the previous guess', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const web = listHosts(db).find(h => h.ip === '10.20.1.12');
  setHostOverride(db, web.id, 'os', 'first guess', 'Lindqvist');
  setHostOverride(db, web.id, 'os', 'second guess', 'Lindqvist');
  setHostOverride(db, web.id, 'os', null, 'Lindqvist');
  assert.equal(getHost(db, web.id).os, 'Windows Server');
});

test('reverting a field on a host terrain never knew simply empties it', () => {
  const db = fresh();
  const h = createHost(db, { name: 'phantom', actor: 'Lindqvist' });
  setHostOverride(db, h.id, 'role', 'guessed role', 'Lindqvist');
  assert.equal(getHost(db, h.id).role, 'guessed role');
  setHostOverride(db, h.id, 'role', null, 'Lindqvist');
  assert.equal(getHost(db, h.id).role, null);
});

test('verdict and presence cannot be overridden by hand', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const web = listHosts(db)[0];
  assert.throws(() => setHostOverride(db, web.id, 'verdict', 'cleared'), /cannot be overridden/);
  assert.throws(() => setHostOverride(db, web.id, 'presence', 'alive-named'), /cannot be overridden/);
});

test('an override for a host terrain drops goes inert rather than resurrecting it', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const gone = listHosts(db).find(h => h.ip === '10.21.1.20');
  setHostOverride(db, gone.id, 'role', 'x', 'Lindqvist');

  seedHosts(db, TWO_WEBS.filter(h => h.ip !== '10.21.1.20'));
  assert.equal(getHost(db, gone.id), undefined, 'the host is gone');
  assert.doesNotThrow(() => applyHostOverrides(db), 'and its override is simply ignored');
});

// --- merge -------------------------------------------------------------------

test('merging a phantom carries its evidence to the real host', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const real = listHosts(db).find(h => h.ip === '10.20.1.12');

  // A record whose hostname is prose invents a phantom, as it did in practice.
  const rec = createRecord(db,
    { hostname: 'Enclave A webserver (host not in terrain inventory; IP not collected)', description: 'defacement' });
  const phantom = listHosts(db).find(h => h.source === 'discovered');
  assert.ok(phantom, 'the prose name created a host');

  const out = mergeHosts(db, phantom.id, real.id, { reason: 'it is 10.20.1.12', actor: 'Lindqvist' });
  assert.equal(out.records, 1);
  assert.equal(getRecord(db, rec.id).host_id, real.id);
  assert.equal(getHost(db, phantom.id), undefined, 'the phantom is gone');
  assert.equal(db.prepare("select count(*) n from audit where action = 'host.merge'").get().n, 1);
});

test('merge carries characterization rows too', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const real = listHosts(db).find(h => h.ip === '10.20.1.12');
  const phantom = createHost(db, { name: 'webserver-typo', actor: 'Lindqvist' });

  stageSnapshot(db, { repo: 'accounts', host: 'webserver-typo',
    snapshotId: createCharSnapshot(db, { repo: 'accounts' }).id, entities: [{ UserName: 'root' }] });

  const out = mergeHosts(db, phantom.id, real.id, { reason: 'typo', actor: 'Lindqvist' });
  assert.equal(out.characterizationRows, 1);
  assert.equal(repoView(db, 'accounts').rows[0].host, 'Web');
});

/*
  Terrain would recreate a merged-away seeded host at the next re-seed, leaving
  the duplicate back in place with its evidence now pointing elsewhere — worse
  than the state we started in.
*/
test('merging away a seeded host is refused', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const [a, b] = listHosts(db).filter(h => h.name === 'Web');
  assert.throws(() => mergeHosts(db, a.id, b.id, { actor: 'Lindqvist' }), /comes from terrain/);
});

test('a host cannot be merged into itself', () => {
  const db = fresh();
  const h = createHost(db, { name: 'x', actor: 'Lindqvist' });
  assert.throws(() => mergeHosts(db, h.id, h.id), /into itself/);
});

// --- create and remove --------------------------------------------------------

test('a hand-created host survives seeding, because terrain never owned it', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const made = createHost(db, { name: 'EX-WEB-2', ip: '10.20.1.13', enclave: 'Enclave A', actor: 'Lindqvist' });
  assert.equal(made.source, 'discovered');
  assert.equal(made.created_by, 'Lindqvist');

  seedHosts(db, TWO_WEBS);
  assert.ok(getHost(db, made.id), 'seeding only removes rows terrain used to own');
});

test('a host needs a name or an address, and an address cannot be duplicated', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  assert.throws(() => createHost(db, {}), /needs a name or an address/);
  assert.throws(() => createHost(db, { name: 'dup', ip: '10.20.1.12' }), /already on the map/);
});

test('removing a host that carries evidence is refused, and points at merge', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const h = createHost(db, { name: 'has-evidence', actor: 'Lindqvist' });
  createRecord(db, { hostname: 'has-evidence', description: 'something' });
  assert.ok(hostEvidence(db, h.id).records > 0);
  assert.throws(() => removeHost(db, h.id, { actor: 'Lindqvist' }), /merge it into the right host instead/);
});

/*
  The way a discovered host most often comes into being is a finding that names
  an external address: createRecord invents the host for it and binds no
  host_id, because only source_ip binds. The removal guard counted the binding
  and the name and not the addresses, so it reported zero evidence for exactly
  that host and deleted it — while the map drew a badge on it, the drawer
  listed the finding, and derivedConnections kept an edge pointing at it.
*/
test('a host reached only through an address still counts as carrying evidence', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  createRecord(db, {
    hostname: 'Web', source_ip: '10.20.1.12',
    destination_ip: '198.51.100.110:8080', description: 'rootkit fetched from here',
  });
  const drop = listHosts(db).find(h => h.ip === '198.51.100.110');
  assert.ok(drop, 'the destination should have been discovered as a host');
  assert.equal(getRecord(db, listRecords(db)[0].id).host_id !== drop.id, true,
    'and nothing binds a record to a destination, which is the point');

  assert.ok(hostEvidence(db, drop.id).records > 0,
    'the finding names this host and would be orphaned by removing it');
  assert.throws(() => removeHost(db, drop.id, { actor: 'Lindqvist' }), /still carries/);
});

test('an empty hand-made host can be removed', () => {
  const db = fresh();
  const h = createHost(db, { name: 'mistake', actor: 'Lindqvist' });
  assert.deepEqual(removeHost(db, h.id, { actor: 'Lindqvist' }), { removed: 'mistake' });
  assert.equal(getHost(db, h.id), undefined);
});

test('a seeded host cannot be removed, because terrain would bring it back', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const seeded = listHosts(db).find(h => h.source === 'seeded');
  assert.throws(() => removeHost(db, seeded.id, { actor: 'Lindqvist' }), /would return at the next re-seed/);
});

// --- placing records that predate binding -------------------------------------

test('matchHost never invents a host, however unplaceable the text', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const before = listHosts(db).length;
  assert.equal(matchHost(db, { hostname: 'Enclave A webserver (not in inventory; IP not collected)' }), null);
  assert.equal(listHosts(db).length, before, 'the prose did not become a host');
});

test('resolveHost refuses to invent a host for an ambiguous short name', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const before = listHosts(db).length;
  assert.equal(resolveHost(db, { hostname: 'Web (Enclave B DMZ)' }), null);
  assert.equal(listHosts(db).length, before, 'and did not add a third "Web" alongside the two');
});

test('the backfill binds the unambiguous and leaves the ambiguous alone', () => {
  const db = fresh();
  seedHosts(db, TWO_WEBS);
  const dc = listHosts(db).find(h => h.ip === '10.20.1.10');

  // Records written before host_id existed.
  for (const r of [
    { hostname: 'EX-DC', description: 'placeable by name' },
    { hostname: 'Web (Enclave B DMZ)', description: 'two hosts answer to Web' },
  ]) {
    const rec = createRecord(db, r);
    db.prepare('update records set host_id = null where id = ?').run(rec.id);
  }

  assert.equal(bindUnplacedRecords(db), 1);
  const rows = listRecords(db);
  assert.equal(rows.find(r => r.hostname === 'EX-DC').host_id, dc.id);
  assert.equal(rows.find(r => r.hostname.startsWith('Web')).host_id, null);
});

test('a host arriving in a later survey places a record nothing could place before', () => {
  const db = fresh();
  seedHosts(db, [TWO_WEBS[2]]);
  const rec = createRecord(db, { hostname: 'EX2-RL-6', description: 'beacon' });
  db.prepare('update records set host_id = null where id = ?').run(rec.id);
  db.prepare("delete from hosts where source = 'discovered'").run();
  assert.equal(getRecord(db, rec.id).host_id, null);

  seedHosts(db, [...TWO_WEBS, { name: 'EX2-RL-6', ip: '10.21.2.16', enclave: 'Enclave B' }]);
  const host = listHosts(db).find(h => h.name === 'EX2-RL-6');
  assert.equal(getRecord(db, rec.id).host_id, host.id, 'the seed bound it');
});

/*
  seedHosts folds a discovered host into a seeded row at the same address. Once
  a record carries host_id, deleting that row without re-pointing the binding
  would leave the finding attached to a host that no longer exists — visible
  nowhere at all, which is worse than the duplicate the fold exists to remove.
*/
test('absorbing a discovered host carries its bound records to the seeded row', () => {
  const db = fresh();
  const rec = createRecord(db, { hostname: 'web-01', source_ip: '10.20.1.12', description: 'x' });
  const discovered = listHosts(db)[0];
  assert.equal(getRecord(db, rec.id).host_id, discovered.id);

  seedHosts(db, TWO_WEBS);
  const seededWeb = listHosts(db).find(h => h.ip === '10.20.1.12' && h.source === 'seeded');
  assert.equal(getRecord(db, rec.id).host_id, seededWeb.id, 'the binding followed the fold');
  assert.equal(getHost(db, discovered.id), undefined);
});
