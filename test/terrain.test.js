import { test } from 'node:test';
import assert from 'node:assert';
import { loadTerrain, terrainHosts } from '../terrain/load.js';
import { writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('the profile terrain loads and flattens with enclave context', () => {
  const t = loadTerrain();
  assert.ok(t.enclaves.length > 0, 'a profile with no enclaves is refused at load');
  const hosts = terrainHosts(t);
  assert.ok(hosts.length > 0);
  for (const h of hosts) {
    assert.ok(h.enclave, `${h.name} lost its enclave`);
    assert.ok('segment' in h, `${h.name} lost its segment`);
  }
});

test('survey fields default rather than going missing', () => {
  // A hand-built terrain has no survey data at all. Every consumer reads these
  // fields unconditionally, so the flattener has to supply them.
  const hosts = terrainHosts({ enclaves: [{ key: 'x', name: 'X', segments:
    [{ name: 's', hosts: [{ name: 'bare', ip: '10.0.0.1' }] }] }] });
  assert.equal(hosts[0].presence, 'unsurveyed');
  assert.equal(hosts[0].domainJoined, null);
  assert.deepEqual(hosts[0].observedFrom, []);
});

test('domain membership is recorded both ways', () => {
  const hosts = terrainHosts();
  assert.ok(hosts.some(h => h.domainJoined === true), 'joined hosts marked');
  assert.ok(hosts.some(h => h.domainJoined === false), 'non-joined hosts marked');
});

test('vantage provenance survives into the terrain file', () => {
  assert.ok(terrainHosts().some(h => h.observedFrom.length > 0),
    'every surveyed host records which vantage saw it');
});

test('two hosts sharing an address are still both present', () => {
  const shared = terrainHosts().filter(h => h.ip === '10.40.1.5');
  assert.deepEqual(shared.map(h => h.name).sort(), ['ControlThings', 'Sift']);
});

test('a terrain with no enclaves is refused rather than seeded empty', () => {
  const tmp = join(tmpdir(), `terrain-empty-${process.pid}.json`);
  writeFileSync(tmp, JSON.stringify({ enclaves: [] }), 'utf8');
  try {
    assert.throws(() => loadTerrain(tmp), /no enclaves/);
  } finally {
    rmSync(tmp, { force: true });
  }
});

test('a terrain file with a UTF-8 BOM still loads', () => {
  // PowerShell's Set-Content -Encoding UTF8 writes one, as does Notepad.
  // JSON.parse rejects it with a message that never mentions the BOM.
  const tmp = join(tmpdir(), `terrain-bom-${process.pid}.json`);
  const body = JSON.stringify({ enclaves: [{ key: 'x', name: 'X', segments: [] }] });
  writeFileSync(tmp, '\uFEFF' + body, 'utf8');
  try {
    assert.equal(loadTerrain(tmp).enclaves.length, 1);
  } finally {
    rmSync(tmp, { force: true });
  }
});
