/**
 * What the plan intends to hunt, against the matrix.
 *
 * Computed from the plan's mitre arrays, not from findings. The Navigator export
 * already answers "what did we find"; this answers "what did we set out to look
 * for", and the two are different questions. A plan that covers nothing can
 * still produce findings, and a hunt that found nothing can still have been
 * thorough — only this view can say which.
 *
 * Three states, because two would hide the one that matters: a task naming a
 * technique with nothing written under it looks like coverage in a list and is
 * not coverage in a briefing.
 */
import { listPlan } from './plan.js';
import { listBank, matrixVersion, isLiveTechnique } from './bank.js';
import { stepsSourceOf } from './plan-file.js';

export function planCoverage(db, domain = 'enterprise') {
  const named = new Map();   // technique id -> best state so far
  /*
    Ids the plan names that no longer exist in either matrix — revoked or
    renumbered upstream. They colour no cell and count toward no state, so
    without this the plan claims ground the matrix cannot show and nothing says
    so.

    This is not hypothetical: it found five in this repository's own plan files
    on the day it was written, three ICS and two Enterprise, all revoked into the
    T16xx series. Those are migrated now, which is the point — nothing had told
    anybody they were there.

    Checked against both matrices, not the one on screen: an Enterprise id is
    not dead because you happen to be looking at ICS.
  */
  const orphans = new Set();
  for (const task of listPlan(db)) {
    // The same rule the editor stamps on the task, not a second copy of it.
    const authored = stepsSourceOf(task) === 'authored';
    for (const id of task.mitre ?? []) {
      if (!isLiveTechnique(id)) { orphans.add(id); continue; }
      const prev = named.get(id);
      // Authored wins: one filled-out task is enough, however many stubs sit
      // beside it naming the same technique.
      if (prev !== 'authored') named.set(id, authored ? 'authored' : 'named');
    }
  }

  const entries = listBank({ domain });
  const byTactic = new Map();
  const counts = { none: 0, named: 0, authored: 0 };

  for (const e of entries) {
    const state = named.get(e.id) ?? 'none';
    counts[state] += 1;
    // A technique can belong to several tactics and appears under each.
    for (const tac of e.tactics.length ? e.tactics : ['(no tactic)']) {
      if (!byTactic.has(tac)) byTactic.set(tac, []);
      byTactic.get(tac).push({ id: e.id, name: e.name, state, isSub: e.isSub });
    }
  }

  const tactics = [...byTactic.entries()]
    .map(([tactic, techniques]) => ({
      tactic,
      techniques: techniques.sort((a, b) => a.id.localeCompare(b.id)),
    }))
    .sort((a, b) => a.tactic.localeCompare(b.tactic));

  return { domain, version: matrixVersion(domain), tactics, counts, orphans: [...orphans].sort() };
}
