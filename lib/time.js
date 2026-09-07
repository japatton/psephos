/**
 * Event-time parsing for hunt records.
 *
 * Source data is inconsistent by nature — analysts record what they can see.
 * Real values from the analyst workbook include:
 *
 *   2026-08-13 17:59:02Z
 *   2026-08-17 22:02:35.446Z
 *   2026-08-19 ~11:59 (discovered; removal reported)
 *   Scheduled: 0 18 * * 3 = Wednesday 18:00 - TODAY (2026-08-19)
 *   N/A (host forensics - cron)
 *
 * Rather than discard what will not parse cleanly, every value gets a tier:
 *
 *   exact        a full timestamp to the second
 *   approximate  a recoverable position, but fuzzy — tilde times, bare dates,
 *                cron expressions resolved against a stated date
 *   unplaceable  nothing recoverable; the timeline docks these rather than
 *                dropping them
 *
 * This function must never throw. A parse failure is a tier, not an error.
 */

const NOT_APPLICABLE = /^\s*n\s*\/\s*a\b/i;
const DATE = /(\d{4})-(\d{2})-(\d{2})/;
const EXACT = /(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?/;
// An HH:MM not part of an HH:MM:SS, and not preceded by another digit or colon.
const HHMM = /(?:^|[^\d:])(\d{1,2}):(\d{2})(?!:?\d)/;

const UNPLACEABLE = Object.freeze({ iso: null, tier: 'unplaceable' });

/**
 * Build an ISO string, returning null if the components are not a real date.
 * Naive timestamps are treated as UTC — the range reports in Z and mixing in a
 * local offset would silently shift every mark on the timeline.
 */
function toIso(y, mo, d, h = 0, mi = 0, s = 0, ms = 0) {
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  if (h > 23 || mi > 59 || s > 59) return null;
  const t = Date.UTC(y, mo - 1, d, h, mi, s, ms);
  if (Number.isNaN(t)) return null;
  const iso = new Date(t);
  // Reject overflow such as 2026-02-31 rolling into March.
  if (iso.getUTCMonth() !== mo - 1 || iso.getUTCDate() !== d) return null;
  return iso.toISOString();
}

/** Same UTC calendar day? */
const sameUtcDay = (a, b) => a.getUTCFullYear() === b.getUTCFullYear()
  && a.getUTCMonth() === b.getUTCMonth() && a.getUTCDate() === b.getUTCDate();

/**
 * @param {string|null|undefined} raw
 * @param {{ recordedAt?: string|null }} [opts]
 *   recordedAt — when the record was written, ISO UTC. Used only to place a
 *   bare date; see the note at the bare-date branch.
 * @returns {{ iso: string|null, tier: 'exact'|'approximate'|'unplaceable' }}
 */
export function parseEventTime(raw, { recordedAt = null } = {}) {
  try {
    if (raw == null) return UNPLACEABLE;
    const s = String(raw).trim();
    if (s === '') return UNPLACEABLE;

    // "N/A", "N/A (host forensics - cron)" and friends carry no time at all.
    // Checked first so a parenthetical date elsewhere cannot fake a position.
    if (NOT_APPLICABLE.test(s)) return UNPLACEABLE;

    // Full timestamp to the second.
    const exact = EXACT.exec(s);
    if (exact) {
      const [, y, mo, d, h, mi, sec, frac] = exact;
      const ms = frac ? Math.round(parseFloat(frac) * 1000) : 0;
      const iso = toIso(+y, +mo, +d, +h, +mi, +sec, ms);
      if (iso) return { iso, tier: 'exact' };
    }

    // Everything below is fuzzy. We need a date to anchor to.
    const date = DATE.exec(s);
    if (!date) return UNPLACEABLE;
    const [, y, mo, d] = date;

    // A time of day somewhere in the string: "~11:59", "Wednesday 18:00".
    const hhmm = HHMM.exec(s);
    if (hhmm) {
      const iso = toIso(+y, +mo, +d, +hhmm[1], +hhmm[2]);
      if (iso) return { iso, tier: 'approximate' };
    }

    /*
      A bare date. Midnight is the obvious anchor and the wrong one: it sorts a
      live observation made at six in the evening ahead of everything that
      actually happened that day, so the timeline reads backwards.

      Where the record was written on the same UTC day it describes — which is
      what "live observation, exact time not recorded" means — the moment it
      was written is a much better estimate, and a true upper bound: the
      analyst cannot have recorded it before seeing it. Only same-day, because
      for an event dated a week before the write-up the write-up time says
      nothing, and midnight at least stays inside the right day.

      The tier stays approximate either way. This buys a better position, not
      precision, and the raw text the analyst typed is kept verbatim in
      event_time regardless.
    */
    const iso = toIso(+y, +mo, +d);
    if (!iso) return UNPLACEABLE;

    if (recordedAt) {
      const written = new Date(recordedAt);
      if (!Number.isNaN(written.getTime()) && sameUtcDay(written, new Date(iso))) {
        return { iso: written.toISOString(), tier: 'approximate' };
      }
    }
    return { iso, tier: 'approximate' };
  } catch {
    return UNPLACEABLE;
  }
}
