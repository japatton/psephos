/**
 * The bank: what a hunt can be built from.
 *
 * An entry is a generated stub joined to an authored overlay when one exists.
 * The two halves are kept apart on purpose — the stub is what MITRE says and
 * regenerates with each release; the overlay is what somebody who has hunted it
 * wrote, and a release must never be able to overwrite that.
 *
 * Read from disk once. The matrices are a few hundred kilobytes and never change
 * while the server runs.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { overlays as enterpriseOverlays } from '../plans/bank/enterprise.mjs';
import { overlays as icsOverlays } from '../plans/bank/ics.mjs';
import { reviewed as icsReviewed } from '../plans/bank/ics-reviewed.mjs';
import { drafted as icsDrafted } from '../plans/bank/ics-drafted.mjs';
import { entries as practiceEntries } from '../plans/bank/practice.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ATTACK = join(HERE, '..', 'plans', 'attack');

/*
  Authored first, drafted second — but the two sets are disjoint and a test
  enforces that, because spread would otherwise let a drafted entry displace an
  authored one silently and the only symptom would be a badge nobody was
  watching.
*/
const OVERLAYS = {
  enterprise: enterpriseOverlays,
  ics: { ...icsOverlays, ...icsReviewed, ...icsDrafted },
};

// Every domain the bank answers for, versus the subset backed by a generated
// matrix file. 'practice' is a real domain (listBank serves it from
// plans/bank/practice.mjs) but has no plans/attack/practice.json, so a
// coverage request against it is a 400 naming that, not a 500 from a failed
// read of a file that was never going to exist.
const DOMAINS = ['enterprise', 'ics', 'practice'];
const MATRIX_DOMAINS = ['enterprise', 'ics'];

/**
 * Thrown for a domain outside what this module knows about. Raised instead of
 * letting the caller's value reach a filesystem read: `${domain}.json` was
 * reachable from a raw query parameter before this existed, `..` included, and
 * the failure that produced was a 500 carrying an absolute path.
 */
export class UnknownDomainError extends Error {
  constructor(domain, valid) {
    super(`unknown domain: ${JSON.stringify(domain)} (expected one of: ${valid.join(', ')})`);
    this.name = 'UnknownDomainError';
  }
}

const matrices = new Map();
function matrix(domain) {
  if (!MATRIX_DOMAINS.includes(domain)) throw new UnknownDomainError(domain, MATRIX_DOMAINS);
  if (!matrices.has(domain)) {
    matrices.set(domain, JSON.parse(readFileSync(join(ATTACK, `${domain}.json`), 'utf8')));
  }
  return matrices.get(domain);
}

export const matrixVersion = (domain) => matrix(domain).version;

const entryFor = (domain, t) => ({
  id: t.id,
  kind: 'technique',
  domain,
  name: t.name,
  tactics: t.tactics,
  platforms: t.platforms,
  desc: t.desc,
  detection: t.detection,
  isSub: t.isSub,
  parent: t.parent,
  // null, not an empty object: a caller must not be able to read a stub as
  // depth that happens to be blank.
  depth: OVERLAYS[domain]?.[t.id] ?? null,
});

const practice = () => practiceEntries.map(e => ({
  id: e.id, kind: 'practice', domain: 'practice', category: e.category,
  name: e.name, tactics: [], platforms: [], desc: e.desc, detection: [],
  isSub: false, parent: null, depth: e.depth,
}));

/** @param opts {{ domain?: string, tactic?: string, q?: string }} */
export function listBank({ domain = 'enterprise', tactic = null, q = '' } = {}) {
  if (!DOMAINS.includes(domain)) throw new UnknownDomainError(domain, DOMAINS);
  const all = domain === 'practice'
    ? practice()
    : matrix(domain).techniques.map(t => entryFor(domain, t));

  const needle = String(q ?? '').trim().toLowerCase();
  return all.filter((e) => {
    if (tactic && !e.tactics.includes(tactic)) return false;
    if (!needle) return true;
    return `${e.id} ${e.name} ${e.desc}`.toLowerCase().includes(needle);
  });
}

export function getBankEntry(id) {
  for (const domain of ['enterprise', 'ics']) {
    const t = matrix(domain).techniques.find(x => x.id === id);
    if (t) return entryFor(domain, t);
  }
  return practice().find(e => e.id === id) ?? null;
}

/**
 * Whether an id names a technique that still exists in either matrix.
 *
 * A Set built once, rather than getBankEntry's scan, because the caller asks
 * this for every mitre id on every task in the plan.
 */
let liveIds = null;
export function isLiveTechnique(id) {
  if (!liveIds) {
    liveIds = new Set(MATRIX_DOMAINS.flatMap(d => matrix(d).techniques.map(t => t.id)));
  }
  return liveIds.has(id);
}

/**
 * Overlays whose technique is no longer in the matrix.
 *
 * Deprecated, revoked or renumbered upstream. Reported rather than dropped: an
 * overlay is authored tradecraft, and losing it silently on a version bump is
 * exactly the kind of quiet deletion this repository does not do.
 *
 * Takes the overlay map as a parameter, defaulting to the module's own
 * OVERLAYS, so a test can drive the orphan branch with a throwaway map instead
 * of waiting for a real matrix release to strand a real overlay.
 */
export function orphanOverlays(overlays = OVERLAYS) {
  const out = [];
  for (const [domain, over] of Object.entries(overlays)) {
    const ids = new Set(matrix(domain).techniques.map(t => t.id));
    for (const id of Object.keys(over)) if (!ids.has(id)) out.push(id);
  }
  return out.sort();
}
