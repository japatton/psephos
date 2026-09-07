import { test } from 'node:test';
import assert from 'node:assert';
import { recordsToMispEvent, recordsToStixBundle } from '../export/iocs.js';

const rec = (over = {}) => ({
  id: 'r1', event_id: 'EV-1', state: 'filed',
  hostname: 'EX-DC', source_ip: '10.20.1.11', destination_ip: '203.0.113.25',
  indicator: 'svchost.exe', sha256: 'a'.repeat(64), command: 'schtasks /create',
  description: 'scheduled task persistence', mitre: 'T1053.005', ...over,
});

const values = (ev) => ev.Event.Attribute.map(a => a.value);
const typed = (ev, type) => ev.Event.Attribute.filter(a => a.type === type).map(a => a.value);

// --- MISP ------------------------------------------------------------------------

test('an event carries the fields MISP needs to accept it', () => {
  const ev = recordsToMispEvent([rec()]);
  assert.ok(ev.Event.info, 'an event needs a description');
  assert.match(ev.Event.date, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(Array.isArray(ev.Event.Attribute));
});

test('each column becomes the attribute type that column actually means', () => {
  const ev = recordsToMispEvent([rec()]);
  assert.deepEqual(typed(ev, 'ip-src'), ['10.20.1.11']);
  assert.deepEqual(typed(ev, 'ip-dst'), ['203.0.113.25']);
  assert.deepEqual(typed(ev, 'sha256'), ['a'.repeat(64)]);
  assert.deepEqual(typed(ev, 'filename'), ['svchost.exe']);
  assert.deepEqual(typed(ev, 'hostname'), ['EX-DC']);
});

/*
  The eighteen columns are filled in by hand, and an analyst with nothing to put
  in one writes N/A rather than leaving it blank. Shipping that to a sharing
  community as an indicator is worse than shipping nothing.
*/
test('placeholders are not indicators', () => {
  const ev = recordsToMispEvent([rec({
    source_ip: 'N/A', destination_ip: '', sha256: 'n/a', indicator: '-', hostname: 'unknown',
  })]);
  assert.deepEqual(values(ev), [], `these were exported: ${values(ev).join(', ')}`);
});

test('one value appears once however many records carry it', () => {
  const ev = recordsToMispEvent([
    rec({ id: 'r1', event_id: 'EV-1' }),
    rec({ id: 'r2', event_id: 'EV-2' }),
  ]);
  assert.equal(new Set(values(ev)).size, values(ev).length, 'duplicated attributes');
});

test('an attribute says which records it came from', () => {
  const ev = recordsToMispEvent([rec({ event_id: 'EV-7' })]);
  assert.ok(ev.Event.Attribute.every(a => a.comment.includes('EV-7')));
});

/*
  to_ids is the flag that says "turn this into a detection". Setting it on a
  proposal nobody has adjudicated pushes an unreviewed model output into
  somebody else's alerting.
*/
test('only an adjudicated indicator is marked for detection', () => {
  const filed = recordsToMispEvent([rec({ state: 'filed' })]);
  const pending = recordsToMispEvent([rec({ state: 'pending' })]);
  assert.ok(filed.Event.Attribute.every(a => a.to_ids === true));
  assert.ok(pending.Event.Attribute.every(a => a.to_ids === false));
});

test('denied records export nothing at all', () => {
  assert.deepEqual(recordsToMispEvent([rec({ state: 'denied' })]).Event.Attribute, []);
});

// --- STIX ------------------------------------------------------------------------

test('a bundle is a bundle of indicators with STIX patterns', () => {
  const b = recordsToStixBundle([rec()]);
  assert.equal(b.type, 'bundle');
  assert.match(b.id, /^bundle--[0-9a-f-]{36}$/);
  const ind = b.objects.filter(o => o.type === 'indicator');
  assert.ok(ind.length > 0);
  for (const o of ind) {
    assert.equal(o.spec_version, '2.1');
    assert.match(o.id, /^indicator--[0-9a-f-]{36}$/);
    assert.equal(o.pattern_type, 'stix');
    assert.match(o.pattern, /^\[.+\]$/, `not a pattern: ${o.pattern}`);
  }
});

test('the pattern names the right STIX object for the value', () => {
  const pats = recordsToStixBundle([rec()]).objects
    .filter(o => o.type === 'indicator').map(o => o.pattern);
  assert.ok(pats.some(p => p.includes("ipv4-addr:value = '203.0.113.25'")), pats.join(' | '));
  assert.ok(pats.some(p => p.includes("file:hashes.'SHA-256'")), pats.join(' | '));
});

/*
  Exports get diffed and re-run. Random ids would make every export look like a
  wholly new set of indicators to whatever consumes it.
*/
test('the same records export identically', () => {
  const at = '2026-09-01T00:00:00.000Z';
  assert.deepEqual(
    recordsToStixBundle([rec()], { generatedAt: at }),
    recordsToStixBundle([rec()], { generatedAt: at }));
});
