import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { addMissionPhases } from '../plans/mission-phases.mjs';
import { expandPlan } from '../plans/expansion.mjs';
import { isLiveTechnique } from '../store/bank.js';

/*
  Every technique id this repository ships in plan content still exists.

  Written after finding five that did not. ATT&CK revoked T0855, T0812 and T0857
  out of the ICS matrix and T1070.001 and T1562.002 out of Enterprise, all into
  the T16xx series, and the doctrine and the OT expansion went on naming the old
  numbers. A task naming a revoked id colours no cell in the coverage view and
  counts toward no state, so the plan claimed ground the matrix could not show
  it covering and nothing said otherwise for however long it had been true.

  The coverage view reports them now, which is what surfaced these. This is the
  other half: the reporting tells an analyst about a plan they uploaded, and this
  stops the ones shipped in the box from going stale again on the next release.
  Both are needed — one is about somebody else's plan, this is about ours.

  Structural rather than a grep over the source, because a comment explaining a
  dead id is not a defect and a grep cannot tell the difference. This walks the
  plan objects the two modules actually build.
*/

/** Every mitre id reachable in a plan-shaped object, wherever it sits. */
function techniqueIds(node, found = new Set()) {
  if (Array.isArray(node)) { for (const x of node) techniqueIds(x, found); return found; }
  if (!node || typeof node !== 'object') return found;
  if (Array.isArray(node.mitre)) for (const id of node.mitre) found.add(id);
  for (const v of Object.values(node)) techniqueIds(v, found);
  return found;
}

const dead = (ids) => [...ids].filter(id => !isLiveTechnique(id)).sort();

test('the doctrinal frame names only live techniques', () => {
  const ids = techniqueIds(addMissionPhases({ phases: [] }));
  assert.ok(ids.size > 20, `expected the frame to carry technique ids, got ${ids.size}`);
  assert.deepEqual(dead(ids), [],
    'plans/mission-phases.mjs names a technique ATT&CK has revoked; look up the current number');
});

test('the OT and Linux expansion names only live techniques', () => {
  const ids = techniqueIds(expandPlan({ phases: [] }));
  assert.ok(ids.size > 10, `expected the expansion to carry technique ids, got ${ids.size}`);
  assert.deepEqual(dead(ids), [],
    'plans/expansion.mjs names a technique ATT&CK has revoked; look up the current number');
});

test('the example mission plan names only live techniques', () => {
  const ids = techniqueIds(JSON.parse(readFileSync('missions/example/plan.json', 'utf8')));
  assert.deepEqual(dead(ids), [],
    'missions/example/plan.json names a technique ATT&CK has revoked');
});

/*
  demo-data.mjs refuses to load without its environment set, so it is read as
  text — but only its mitre fields, not its prose, which keeps the same rule as
  the tests above: explaining a dead id is fine, shipping one is not. The demo
  is what the published screenshots are made from, so a stale id there is a
  stale id on the README.
*/
test('the demo data names only live techniques', () => {
  const src = readFileSync('tools/demo-data.mjs', 'utf8');
  const ids = new Set();
  for (const m of src.matchAll(/mitre:\s*(\[[^\]]*\]|'[^']*')/g)) {
    for (const id of m[1].match(/T\d{4}(?:\.\d{3})?/g) ?? []) ids.add(id);
  }
  assert.ok(ids.size > 0, 'found no mitre fields in the demo data — has it been restructured?');
  assert.deepEqual(dead(ids), [], 'tools/demo-data.mjs names a technique ATT&CK has revoked');
});
