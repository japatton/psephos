/**
 * The generated name of a collection run.
 *
 * Hard-coded rather than typed, because five operators naming their own runs
 * produced "Scheduled Tasks - 25 Aug", "Initial Collection Scheduled tasks 24
 * Aug", "Services Aug 24" and "SMB Collection aug 24" — four different
 * conventions, each hand-encoding the repository into a field that had no idea
 * what a repository was. The repository is now structural, so the name states
 * it instead of the operator remembering to.
 *
 *   Processes_Baseline_Okafor_20260826083024
 *
 * Sortable, greppable, and unique per second per operator per repository.
 */

/** processes -> Processes, domain-accounts -> DomainAccounts. */
export const repoToken = (repo) => String(repo ?? '')
  .split(/[^A-Za-z0-9]+/)
  .filter(Boolean)
  .map(w => w[0].toUpperCase() + w.slice(1))
  .join('') || 'Unclassified';

/**
 * Whatever the operator is called, reduced to something safe in a filename and
 * a URL. Names arrive as surnames already ("Okafor", "Reyes"), but the token
 * is attribution and must not be able to break the label's own separator.
 */
export const operatorToken = (who) => {
  const t = String(who ?? '').replace(/[^A-Za-z0-9]+/g, '');
  return t ? t[0].toUpperCase() + t.slice(1) : 'Unknown';
};

/** YYYYMMDDHHMMSS, UTC. The exercise runs across time zones; local would lie. */
export const stampToken = (date = new Date()) => {
  const d = date instanceof Date ? date : new Date(date);
  const at = Number.isNaN(d.getTime()) ? new Date() : d;
  return at.toISOString().replace(/[-:T]/g, '').slice(0, 14);
};

export function snapshotLabel(repo, who, date = new Date()) {
  return `${repoToken(repo)}_Baseline_${operatorToken(who)}_${stampToken(date)}`;
}

/**
 * The same name, with a counter if something already holds it.
 *
 * Two runs seeded in the same second collided exactly, which in a picker is
 * indistinguishable from one run listed twice. The format is fixed, so the
 * disambiguator goes on the end rather than into the timestamp.
 */
export function uniqueLabel(base, exists) {
  if (!exists(base)) return base;
  for (let n = 2; n < 1000; n++) {
    if (!exists(`${base}_${n}`)) return `${base}_${n}`;
  }
  throw new Error(`cannot find a free name for ${base}`);
}
