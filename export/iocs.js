/**
 * The indicators in the case file, in the two formats other tools read.
 *
 * Export only, and deliberately. The other half of what a sharing platform does
 * is enrichment — sending an observable out to a reputation service and reading
 * back what the internet thinks of it — and that is wrong for this tool. It runs
 * offline on the analyst's machine, and it is pointed at exercise estates where
 * sending an address to a third party ranges from meaningless to disclosive.
 *
 * Confirmed records only, by default. Everything here is written for somebody
 * else's detection stack, and a proposal nobody has adjudicated is not a thing
 * to put in one.
 */
import { createHash } from 'node:crypto';

/*
  Eighteen columns filled in by hand. An analyst with nothing to put in one
  writes N/A, or a dash, or "unknown" — and a sharing community that receives
  those as indicators is worse off than one that receives nothing.
*/
const PLACEHOLDER = new Set(['', 'n/a', 'na', '-', '--', 'none', 'null', 'unknown', 'tbd', '?']);
const real = (v) => {
  const s = String(v ?? '').trim();
  return PLACEHOLDER.has(s.toLowerCase()) ? null : s;
};

/**
 * Which column means which kind of indicator.
 *
 * `command` is deliberately absent. A command line is context that explains an
 * indicator; as an indicator itself it matches on an attacker's whitespace.
 */
const MAPPING = [
  { column: 'source_ip', misp: 'ip-src', category: 'Network activity', stix: (v) => `[ipv4-addr:value = '${v}']` },
  { column: 'destination_ip', misp: 'ip-dst', category: 'Network activity', stix: (v) => `[ipv4-addr:value = '${v}']` },
  { column: 'sha256', misp: 'sha256', category: 'Payload delivery', stix: (v) => `[file:hashes.'SHA-256' = '${v}']` },
  { column: 'indicator', misp: 'filename', category: 'Payload delivery', stix: (v) => `[file:name = '${v}']` },
  { column: 'hostname', misp: 'hostname', category: 'Network activity', stix: (v) => `[domain-name:value = '${v}']` },
];

const EXPORTABLE = new Set(['filed', 'pending']);

/** Collect one indicator per distinct value, remembering every record behind it. */
function collect(records) {
  const found = new Map();
  for (const r of records) {
    if (!EXPORTABLE.has(r.state)) continue;
    for (const m of MAPPING) {
      const value = real(r[m.column]);
      if (!value) continue;
      // A STIX pattern is single-quoted, so a value carrying one would break
      // out of it. Nothing legitimate in these columns contains a quote.
      if (/['\\]/.test(value)) continue;
      const key = `${m.misp}:${value}`;
      const prev = found.get(key) ?? { ...m, value, from: [], confirmed: false };
      prev.from.push(r.event_id || r.id);
      // One confirmation is enough to mark the value as adjudicated; the rest
      // of the records naming it do not weaken that.
      prev.confirmed ||= r.state === 'filed';
      found.set(key, prev);
    }
  }
  return [...found.values()];
}

const seen = (from) => `From ${from.length} record${from.length === 1 ? '' : 's'}: ${from.join(', ')}`;

/**
 * The indicators as plain rows, for the report's own table.
 *
 * Shares collect() with the MISP and STIX exports on purpose: three formats
 * disagreeing about what counts as an indicator would be three answers to one
 * question.
 */
export const listIndicators = (records = []) => collect(records)
  .map(i => ({ type: i.misp, value: i.value, from: i.from.join(', '), confirmed: i.confirmed }));

/** A MISP event, ready to be pushed into a community or imported into a case. */
export function recordsToMispEvent(records = [], {
  info = 'Hunt findings',
  generatedAt = new Date().toISOString(),
} = {}) {
  return {
    Event: {
      info,
      date: generatedAt.slice(0, 10),
      // Undefined threat level and unpublished: this is a hunt's own working
      // set, and asserting a severity on somebody else's behalf is not ours.
      threat_level_id: '4',
      analysis: '1',
      distribution: '0',
      published: false,
      Attribute: collect(records).map(i => ({
        type: i.misp,
        category: i.category,
        value: i.value,
        // The flag that says "turn this into a detection". Setting it on an
        // unadjudicated proposal pushes an unreviewed model output into
        // somebody else's alerting.
        to_ids: i.confirmed,
        comment: seen(i.from),
      })),
    },
  };
}

/*
  Derived from the value rather than random. Exports get re-run and diffed, and
  fresh ids every time make an unchanged indicator set look wholly new to
  whatever consumes it.
*/
function stableUuid(seed) {
  const h = createHash('sha256').update(seed).digest('hex');
  return [h.slice(0, 8), h.slice(8, 12), `5${h.slice(13, 16)}`,
    ((parseInt(h.slice(16, 18), 16) & 0x3f) | 0x80).toString(16) + h.slice(18, 20),
    h.slice(20, 32)].join('-');
}

/** A STIX 2.1 bundle of indicators. */
export function recordsToStixBundle(records = [], {
  generatedAt = new Date().toISOString(),
} = {}) {
  const objects = collect(records).map(i => ({
    type: 'indicator',
    spec_version: '2.1',
    id: `indicator--${stableUuid(`${i.misp}:${i.value}`)}`,
    created: generatedAt,
    modified: generatedAt,
    name: `${i.misp} ${i.value}`,
    description: seen(i.from),
    pattern: i.stix(i.value),
    pattern_type: 'stix',
    valid_from: generatedAt,
    confidence: i.confirmed ? 85 : 15,
  }));
  return {
    type: 'bundle',
    id: `bundle--${stableUuid(objects.map(o => o.id).join('|') || 'empty')}`,
    objects,
  };
}
