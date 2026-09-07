import { test } from 'node:test';
import assert from 'node:assert';
import { listBank, getBankEntry, orphanOverlays, matrixVersion, UnknownDomainError } from '../store/bank.js';

/*
  A bank entry is a generated stub joined to an authored overlay when one exists.
  The join is by technique id so regenerating the matrix for a new ATT&CK release
  rewrites only the generated half and never touches what somebody wrote.

  The distinction the tests below protect is not cosmetic: a stub is a prompt and
  a deep entry is tradecraft somebody stands behind, and the two must not become
  indistinguishable in the data any more than they may in the UI.
*/

test('every live technique is in the bank', () => {
  const all = listBank({ domain: 'enterprise' });
  assert.ok(all.length > 600, `expected the whole matrix, got ${all.length}`);
  assert.ok(all.every(e => e.kind === 'technique'));
});

test('a stub carries what MITRE says and no authored depth', () => {
  const e = getBankEntry('T1053.005');
  assert.ok(e, 'T1053.005 missing from the bank');
  assert.equal(e.name, 'Scheduled Task');
  assert.ok(e.tactics.includes('persistence'));
  assert.ok(e.detection.length > 0, 'the detection strategy did not survive the join');
  assert.ok(e.detection[0].logSources.length > 0);
});

test('an overlay adds depth without replacing the stub', () => {
  const e = getBankEntry('T1053.005');
  assert.ok(e.depth, 'the authored overlay did not join');
  assert.ok(e.depth.steps.length > 0, 'depth must carry steps or it is not depth');
  // The generated half is still there underneath.
  assert.equal(e.name, 'Scheduled Task');
});

test('a technique with no overlay is a stub, and says so by having no depth', () => {
  const e = getBankEntry('T1592.004');
  assert.ok(e, 'expected an un-authored technique to still be in the bank');
  assert.equal(e.depth, null);
});

/*
  An overlay whose technique no longer exists upstream is authored tradecraft
  about to disappear silently. It is surfaced rather than dropped.
*/
test('overlays that match no technique are reported', () => {
  assert.deepEqual(orphanOverlays(), [], 'an overlay no longer matches a live technique');
});

test('orphanOverlays actually detects an orphan, and clears a live id', () => {
  // A throwaway map, not the real OVERLAYS: the assertion above only ever sees
  // today's overlays, which have no orphans, so it can't tell a working
  // implementation from one that always returns []. Drive the branch directly.
  const orphaned = orphanOverlays({ enterprise: { 'T9999.999': {} } });
  assert.deepEqual(orphaned, ['T9999.999'], 'a technique id absent from the matrix must be reported');

  const clean = orphanOverlays({ enterprise: { 'T1053.005': {} } });
  assert.deepEqual(clean, [], 'a technique id present in the matrix must not be reported');
});

// --- the entries that are not techniques -------------------------------------------

test('practice entries are in the bank and carry no technique id', () => {
  const prac = listBank({ domain: 'practice' });
  assert.ok(prac.length >= 3, 'expected telemetry, hypothesis and deconfliction entries');
  assert.ok(prac.every(e => e.kind === 'practice'));
  assert.ok(prac.every(e => e.depth && e.depth.steps.length > 0),
    'a practice entry is authored by definition; a stub would be an empty prompt');
});

test('the three categories the plan does not otherwise cover are present', () => {
  const cats = new Set(listBank({ domain: 'practice' }).map(e => e.category));
  for (const c of ['telemetry', 'hypothesis', 'deconfliction']) {
    assert.ok(cats.has(c), `no ${c} entries in the bank`);
  }
});

// --- filtering ----------------------------------------------------------------------

test('the bank can be narrowed by tactic and by free text', () => {
  const persistence = listBank({ domain: 'enterprise', tactic: 'persistence' });
  assert.ok(persistence.length > 0);
  assert.ok(persistence.every(e => e.tactics.includes('persistence')));

  const q = listBank({ domain: 'enterprise', q: 'scheduled task' });
  assert.ok(q.some(e => e.id === 'T1053.005'), 'a name search missed an obvious match');
});

// --- domain validation ---------------------------------------------------------------

/*
  domain arrives as a raw query parameter over HTTP, and matrix() used to hand
  it straight to readFileSync as `${domain}.json` — an unknown value read
  whatever ENOENT said (an absolute path, in the response body), and `..` in
  it walked straight out of plans/attack/.
*/
test('an unknown domain is refused, not handed to a file read', () => {
  assert.throws(() => listBank({ domain: 'nope' }), UnknownDomainError);
  assert.throws(() => listBank({ domain: '../../missions/example/plan' }), UnknownDomainError);
});

/*
  'practice' is a real domain for the bank listing — it is served from
  plans/bank/practice.mjs, not a matrix file — but it has no ATT&CK matrix, so
  asking for its version (what the coverage route does) is refused rather than
  attempting to read a plans/attack/practice.json that was never generated.
*/
test('practice lists fine but carries no matrix version', () => {
  assert.ok(listBank({ domain: 'practice' }).length > 0);
  assert.throws(() => matrixVersion('practice'), UnknownDomainError);
});

// --- ICS ----------------------------------------------------------------------------

/*
  The OT ring is a second matrix, not a footnote. It shipped with every technique
  a stub, which is honest but useless: an analyst who has never hunted ICS is
  exactly the one who needs the depth, and "here is what MITRE says about Modify
  Parameter" does not tell them that a write from the usual HMI during a shift
  may be fine and the same write at 03:00 from a workstation is not.
*/

test('the ICS techniques this estate plans against carry authored depth', () => {
  // The ids plans/expansion.mjs already argues for, mapped to their live
  // numbering — ATT&CK revoked three of them into the T16xx series.
  const authored = [
    'T0842', 'T0885', 'T0886', 'T1692.001', 'T0836', 'T0831', 'T0846',
    'T1694.001', 'T0832', 'T0882', 'T0866', 'T0889', 'T1693.001',
  ];
  for (const id of authored) {
    const e = getBankEntry(id);
    assert.ok(e, `${id} is not in the ICS matrix`);
    assert.ok(e.depth, `${id} has no authored overlay`);
    assert.ok(e.depth.steps.length > 0, `${id}'s overlay carries no steps, so it is not depth`);
    assert.ok(e.depth.intent.length > 120, `${id}'s intent does not argue anything`);
  }
});

/*
  ICS no longer has a stub tier — every technique carries depth now — so the
  assertion that used to live here (T0800 is a stub) is obsolete by design
  rather than broken. The tier itself still has to work, and Enterprise is
  where it still applies: 697 techniques against one authored overlay.
*/
test('a technique nobody has written anything for is still a stub', () => {
  const e = getBankEntry('T1595');
  assert.ok(e, 'expected T1595 in the Enterprise matrix');
  assert.equal(e.depth, null, 'depth must be null for a stub, never an empty object');

  const stubs = listBank({ domain: 'enterprise' }).filter(x => !x.depth);
  assert.ok(stubs.length > 600, `expected Enterprise to be mostly stubs, got ${stubs.length}`);
});

/*
  Every OT step in this repository is passive by construction. Active scanning of
  a PLC is a recognised cause of process upset, so a command that probes one is
  not a hunting technique here, it is the incident. The plan's own terrain task
  says DO NOT scan those ranges; the bank must not hand somebody a command that
  does.
*/
test('no ICS overlay hands the analyst something that touches a device', () => {
  const probing = /\bnmap\b|\bmasscan\b|modbus-cli|mbpoll|\bwrite_(coil|register)|--write\b|snmpset|plcscan/i;
  for (const e of listBank({ domain: 'ics' })) {
    for (const c of e.depth?.commands ?? []) {
      assert.ok(!probing.test(c), `${e.id} carries an active command: ${c}`);
    }
  }
});

// --- provenance ---------------------------------------------------------------------

/*
  Who stands behind an entry.

  Two tiers were enough while depth only existed where somebody had written it.
  They stopped being enough the moment depth got drafted from general practice
  rather than from this team's own doctrine: a drafted entry and a reviewed one
  are both "authored" against a stub, and telling them apart afterwards is
  impossible if the file does not say. The design spec named exactly this as the
  reason not to draft depth at all — "it needs its own design about provenance
  before it is worth having" — so this is that design, and the rule is that the
  flattering value is never the default.
*/

/*
  Three values, in increasing order of what stands behind them. The ladder is
  about what backs an entry, not who typed it:

    drafted   written from general practice, checked by nobody
    reviewed  independently checked for correctness and specificity, but not
              against any particular estate
    authored  grounded in this engagement's own doctrine and reviewed against
              the estate it describes

  The middle one exists because a review can honestly establish that an entry is
  correct and says something worth knowing, and cannot establish that anybody
  validated it against the site in front of you. Collapsing it into 'authored'
  would make the top of the ladder mean nothing, which is the whole failure the
  tiers were built to prevent.
*/
const TIERS = ['drafted', 'reviewed', 'authored'];

test('every overlay declares who stands behind it', () => {
  for (const domain of ['enterprise', 'ics']) {
    for (const e of listBank({ domain })) {
      if (!e.depth) continue;
      assert.ok(TIERS.includes(e.depth.provenance),
        `${e.id} has depth but no provenance — it must be one of ${TIERS.join(', ')}`);
    }
  }
});

test('practice entries declare it too', () => {
  for (const e of listBank({ domain: 'practice' })) {
    assert.ok(TIERS.includes(e.depth.provenance), `${e.id} has no provenance`);
  }
});

/*
  The thirteen generalised out of plans/expansion.mjs are authored: a person on
  this engagement wrote that argument and it was reviewed against this estate.
  Anything drafted from general ICS practice is not, however well it reads.
*/
test('the overlays taken from this estate\'s own doctrine are marked authored', () => {
  for (const id of ['T0842', 'T1692.001', 'T0836', 'T0889']) {
    assert.equal(getBankEntry(id).depth.provenance, 'authored');
  }
});

test('a drafted entry says so rather than defaulting to the flattering value', () => {
  const byTier = (t) => listBank({ domain: 'ics' }).filter(e => e.depth?.provenance === t);
  for (const t of ['drafted', 'reviewed']) {
    assert.ok(byTier(t).length > 0, `expected the ${t} tier to exist`);
    for (const e of byTier(t)) {
      assert.ok(e.depth.steps.length > 0, `${e.id} is marked ${t} but carries no steps`);
    }
  }
  /*
    The five a reviewer would not pass. Pinned so a later edit cannot quietly
    promote one: the whole value of the tier is that something was held back.
  */
  assert.deepEqual(byTier('drafted').map(e => e.id).sort(),
    ['T0815', 'T0869', 'T0873.001', 'T1691.001', 'T1693'],
    'the set a review declined to pass has changed');
});

/*
  An id cannot be in both tiers.

  The drafted set is assembled from six separately written fragments, and the
  failure that invites is an id appearing twice: object spread takes the last
  one silently, so a drafted entry could quietly displace an authored one and
  the only symptom would be a badge nobody was looking at. Object literals also
  swallow a duplicate key within a single fragment without a word.
*/
test('the three ICS tiers are disjoint', async () => {
  const { overlays } = await import('../plans/bank/ics.mjs');
  const { reviewed } = await import('../plans/bank/ics-reviewed.mjs');
  const { drafted } = await import('../plans/bank/ics-drafted.mjs');
  const sets = { authored: overlays, reviewed, drafted };
  for (const [a, b] of [['authored', 'reviewed'], ['authored', 'drafted'], ['reviewed', 'drafted']]) {
    const both = Object.keys(sets[b]).filter(id => id in sets[a]);
    assert.deepEqual(both, [], `these ids are in both the ${a} and ${b} files`);
  }
  assert.equal(Object.keys(overlays).length + Object.keys(reviewed).length
    + Object.keys(drafted).length, 97, 'the three files no longer account for every ICS technique');
});

/*
  The count is asserted, not eyeballed. "Complete the ICS" means every live
  technique carries something, and the number that proves it is the matrix's
  own — so this stays true across an ATT&CK release rather than pinning 97.
*/
test('every ICS technique now carries depth', () => {
  const ics = listBank({ domain: 'ics' });
  const bare = ics.filter(e => !e.depth).map(e => e.id);
  assert.deepEqual(bare, [], `${bare.length} ICS techniques still have no overlay`);
  assert.equal(ics.filter(e => e.depth.provenance === 'authored').length, 13,
    'the authored count moved; a lesser tier may have been promoted without a person reading it');
});

/*
  Commands that read Zeek fields base Zeek does not emit.

  Base modbus.log carries ts, uid, the connection tuple, func and exception. The
  register address is not in it — that needs
  policy/protocols/modbus/track-memmap.zeek, which writes its own
  modbus_register_change.log. A zeek-cut asking base modbus.log for `address`
  returns nothing, and nothing is exactly what a clean result looks like: the
  analyst reads "no writes to hunt" off a command that was never going to
  answer.

  Caught by one reviewer on one entry and missed by another on a different one,
  which is the argument for a test rather than more reading. If a command wants
  the register, it must say which script puts it there.
*/
test('no command reads a register address off base modbus.log', () => {
  const MEMMAP = /track-memmap|modbus_register_change/;
  const offenders = [];
  for (const domain of ['enterprise', 'ics', 'practice']) {
    for (const e of listBank({ domain })) {
      for (const c of e.depth?.commands ?? []) {
        if (!/modbus\.log/.test(c)) continue;
        if (/\b(address|quantity|register|new_val)\b/.test(c) && !MEMMAP.test(c)) {
          offenders.push(`${e.id}: ${c}`);
        }
      }
    }
  }
  assert.deepEqual(offenders, [],
    'these read a field base modbus.log does not have, and return silence that reads as a clean result');
});
