import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { trimBundle } from '../tools/import-attack.mjs';

/*
  The importer is run by hand and its output is committed, so a mistake here is
  discovered weeks later in a file nobody re-reads. The bundle is 51 MB of STIX
  and almost none of it is wanted; what matters is that the parts that are
  wanted survive and the parts that must not appear are gone.
*/

const bundle = JSON.parse(readFileSync('test/fixtures/attack-slice.json', 'utf8'));
const out = trimBundle(bundle, 'enterprise');
const byId = Object.fromEntries(out.techniques.map(t => [t.id, t]));

test('the bundle version travels with the output', () => {
  assert.equal(out.domain, 'enterprise');
  assert.equal(out.version, '17.1');
  assert.match(out.generated, /^\d{4}-\d{2}-\d{2}/);
});

test('live techniques are kept and deprecated or revoked ones are not', () => {
  assert.ok(byId['T1053.005'], 'a live technique was dropped');
  assert.ok(byId.T1053, 'the parent technique was dropped');
  assert.equal(byId.T9998, undefined, 'a deprecated technique survived');
  assert.equal(byId.T9999, undefined, 'a revoked technique survived');
});

test('a sub-technique knows it is one, and which parent it belongs to', () => {
  assert.equal(byId['T1053.005'].isSub, true);
  assert.equal(byId['T1053.005'].parent, 'T1053');
  assert.equal(byId.T1053.isSub, false);
  assert.equal(byId.T1053.parent, null);
});

test('only the first paragraph of the description is carried', () => {
  assert.equal(byId['T1053.005'].desc, 'Adversaries may abuse task scheduling.');
});

/*
  The cap used to be a hard slice(0, 240), which cut mid-word as often as not —
  "...applied consistently and thus produce misleading summaries..." from the
  raw text becomes a stub reading "...without trun" mid-cut. Cutting back to
  the last space keeps a whole word and marks the elision instead.
*/
test('a description longer than the cap is cut at a word boundary, not mid-word', () => {
  const desc = byId.T1600.desc;
  assert.ok(desc.length <= 240, `expected the cap to still bound the length, got ${desc.length}`);
  assert.ok(desc.endsWith('…'), `expected an elision mark, got: ${JSON.stringify(desc)}`);
  const withoutMark = desc.slice(0, -1);
  assert.ok(!withoutMark.endsWith(' '), 'trailing space left before the elision mark');
  assert.equal(withoutMark, 'Adversaries may leverage extremely long identifiers when naming scheduled '
    + 'tasks so that defenders scanning task names must read through unusually verbose descriptions that '
    + 'exceed the typical display width used across dashboards without',
  `truncated mid-word: ${JSON.stringify(desc)}`);
});

/*
  The part that is not a field. x_mitre_data_sources is empty in this bundle
  version; detection hangs off separate strategy and analytic objects reached
  through a detects relationship, and an importer that reads the old field
  reports no data sources for every technique while looking like it worked.
*/
test('the detection chain is walked, not read off a field', () => {
  const d = byId['T1053.005'].detection;
  assert.equal(d.length, 1);
  assert.equal(d[0].strategy, 'Detection of Suspicious Scheduled Task Creation');
  assert.deepEqual(d[0].logSources, ['WinEventLog:Security', 'WinEventLog:Sysmon'],
    'log sources should be resolved by name and de-duplicated');
});

test('a technique with no detection strategy carries an empty list, not undefined', () => {
  assert.deepEqual(byId.T1053.detection, []);
});
