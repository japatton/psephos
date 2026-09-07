import { test } from 'node:test';
import assert from 'node:assert';
import { recordsToNavigatorLayer } from '../export/navigator.js';

/*
  The MITRE column is free text an analyst typed, so it arrives as "T1053.005",
  as "T1053.005 — Scheduled Task", as two IDs in one cell, and in lower case.
  A layer built by trusting the cell verbatim shows one technique per spelling
  and none of them line up with the matrix.
*/

const rec = (over = {}) => ({
  id: 'r1', event_id: 'EV-1', mitre: 'T1053.005', state: 'filed',
  hostname: 'EX-DC', description: 'scheduled task persistence', thread_id: null, ...over,
});

test('a layer carries what Navigator needs to open it', () => {
  const l = recordsToNavigatorLayer([rec()]);
  assert.equal(l.domain, 'enterprise-attack');
  assert.equal(l.versions.layer, '4.5');
  assert.ok(l.name, 'a layer needs a name');
  assert.ok(Array.isArray(l.techniques));
  assert.ok(l.gradient.minValue < l.gradient.maxValue, 'the gradient must span the scores');
});

test('a technique id is found however the analyst wrote the cell', () => {
  const ids = (mitre) => recordsToNavigatorLayer([rec({ mitre })]).techniques.map(t => t.techniqueID);
  assert.deepEqual(ids('T1053.005'), ['T1053.005']);
  assert.deepEqual(ids('T1053.005 — Scheduled Task/Job: Scheduled Task'), ['T1053.005']);
  assert.deepEqual(ids('t1053.005'), ['T1053.005'], 'lower case is the same technique');
  assert.deepEqual(ids('see T1078 and T1021.001'), ['T1078', 'T1021.001']);
});

test('a cell naming no technique contributes nothing rather than throwing', () => {
  for (const mitre of [null, '', 'N/A', 'unknown', 'lateral movement']) {
    assert.deepEqual(recordsToNavigatorLayer([rec({ mitre })]).techniques, [], String(mitre));
  }
});

test('one technique appears once however many records name it', () => {
  const l = recordsToNavigatorLayer([
    rec({ id: 'r1', event_id: 'EV-1' }),
    rec({ id: 'r2', event_id: 'EV-2' }),
  ]);
  assert.equal(l.techniques.length, 1);
  assert.equal(l.techniques[0].techniqueID, 'T1053.005');
});

/*
  The distinction a spreadsheet cannot show: a technique somebody confirmed and
  a technique a model proposed and nobody has looked at are not the same claim,
  and colouring them alike is how a coverage map starts lying.
*/
test('an adjudicated technique scores above one still waiting for a call', () => {
  const l = recordsToNavigatorLayer([
    rec({ id: 'r1', mitre: 'T1053.005', state: 'filed' }),
    rec({ id: 'r2', mitre: 'T1021.001', state: 'pending' }),
  ]);
  const by = Object.fromEntries(l.techniques.map(t => [t.techniqueID, t.score]));
  assert.ok(by['T1053.005'] > by['T1021.001'],
    'a confirmed technique must outrank a proposed one');
});

test('a technique with both a confirmed and a pending record takes the confirmed score', () => {
  const l = recordsToNavigatorLayer([
    rec({ id: 'r1', state: 'pending' }),
    rec({ id: 'r2', state: 'filed' }),
  ]);
  assert.equal(l.techniques.length, 1);
  assert.equal(l.techniques[0].score, recordsToNavigatorLayer([rec()]).techniques[0].score);
});

test('denied records are left out, because a denial is not coverage', () => {
  const l = recordsToNavigatorLayer([rec({ state: 'denied' })]);
  assert.deepEqual(l.techniques, []);
});

test('every technique says which records put it there', () => {
  const l = recordsToNavigatorLayer([
    rec({ id: 'r1', event_id: 'EV-1' }),
    rec({ id: 'r2', event_id: 'EV-2' }),
  ]);
  const c = l.techniques[0].comment;
  assert.match(c, /EV-1/);
  assert.match(c, /EV-2/, 'a layer nobody can trace back is a picture, not evidence');
});

test('the legend explains the scores rather than leaving them as numbers', () => {
  const l = recordsToNavigatorLayer([rec()]);
  assert.ok(l.legendItems.length >= 2);
  assert.ok(l.legendItems.every(i => i.label && i.color));
});
