import { test } from 'node:test';
import assert from 'node:assert';
import { state, recordsForHost, unboundRecords } from '../web/core.js';

/*
  The browser side of placement. This is where the defect was visible: two
  seeded hosts named "Web" and one rootkit finding drawn on both of them.
*/
const SITE_A_WEB = { id: 'h-site-a', name: 'Web', ip: '10.20.1.12', enclave: 'Enclave A' };
const DMZ_WEB = { id: 'h-dmz', name: 'Web', ip: '10.21.1.20', enclave: 'Enclave B' };
const DROP = { id: 'h-drop', name: '198.51.100.110', ip: '198.51.100.110' };
const DC = { id: 'h-dc', name: 'EX-DC.example.test', ip: '10.20.1.10' };

function load(records) {
  state.hosts = [SITE_A_WEB, DMZ_WEB, DROP, DC];
  state.records = records.map(r => ({ state: 'filed', host_id: null, ...r }));
}

test('a bound finding is drawn on the host it names, and not on its namesake', () => {
  load([{
    id: 'r1', host_id: 'h-dmz', hostname: 'Web (Enclave B DMZ)',
    source_ip: '10.21.1.20', destination_ip: '198.51.100.110:8080', description: 'rootkit',
  }]);
  assert.deepEqual(recordsForHost(DMZ_WEB).map(r => r.id), ['r1']);
  assert.deepEqual(recordsForHost(SITE_A_WEB).map(r => r.id), [], 'the Enclave A box shares only a name');
});

test('the far end of the connection is drawn too, so adversary infrastructure shows', () => {
  load([{
    id: 'r1', host_id: 'h-dmz', hostname: 'Web (Enclave B DMZ)',
    source_ip: '10.21.1.20', destination_ip: '198.51.100.110:8080', description: 'rootkit',
  }]);
  assert.deepEqual(recordsForHost(DROP).map(r => r.id), ['r1'],
    'binding says what the finding is about; an address says who took part');
});

test('an unbound short name claims nothing at all', () => {
  load([{ id: 'r1', hostname: 'Web (Enclave B DMZ)', description: 'rootkit' }]);
  assert.equal(recordsForHost(DMZ_WEB).length, 0);
  assert.equal(recordsForHost(SITE_A_WEB).length, 0);
  assert.deepEqual(unboundRecords().map(r => r.id), ['r1'], 'and is offered for binding instead');
});

test('an exact name still places a finding with no address on it', () => {
  load([{ id: 'r1', hostname: 'EX-DC.example.test', description: 'sudo abuse' }]);
  assert.deepEqual(recordsForHost(DC).map(r => r.id), ['r1']);
  assert.equal(unboundRecords().length, 0);
});

test('a name cannot claim back a finding already placed on another host', () => {
  load([{ id: 'r1', host_id: 'h-dmz', hostname: 'Web', description: 'rootkit' }]);
  assert.deepEqual(recordsForHost(SITE_A_WEB).map(r => r.id), []);
  assert.deepEqual(recordsForHost(DMZ_WEB).map(r => r.id), ['r1']);
});

test('a denied finding is drawn nowhere', () => {
  load([{ id: 'r1', host_id: 'h-dmz', state: 'denied', description: 'ruled out' }]);
  assert.equal(recordsForHost(DMZ_WEB).length, 0);
  assert.equal(unboundRecords().length, 0);
});
