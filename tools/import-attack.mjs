/**
 * MITRE ATT&CK STIX bundle -> the trimmed matrix this application reads.
 *
 *   node tools/import-attack.mjs --domain enterprise --in ~/Downloads/enterprise-attack.json
 *
 * Run by hand; the output is committed. The application needs no network and no
 * dependency, the same reasoning that vendors D3 — and the bundles are 51 MB
 * and 3.9 MB against 393 KB and 46 KB of what is actually wanted.
 *
 * Download from:
 *   https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
 *   https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const mitreId = (o) =>
  o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id ?? null;

/*
  The first line, not the first 240 characters of it. A hard slice cuts mid-word
  as often as not, which reads as a broken importer rather than a trimmed one.
  Cutting back to the last space keeps a whole word and marks the elision, at
  the cost of a few characters short of the cap — a trade worth making for text
  that gets read by a person.
*/
function firstLine(description, max = 240) {
  const line = String(description ?? '').split('\n')[0].trim();
  if (line.length <= max) return line;
  const cut = line.slice(0, max);
  const lastSpace = cut.lastIndexOf(' ');
  return `${lastSpace > 0 ? cut.slice(0, lastSpace) : cut}…`;
}

/**
 * @param bundle  the parsed STIX bundle
 * @param domain  'enterprise' | 'ics'
 */
export function trimBundle(bundle, domain) {
  const objects = bundle.objects ?? [];
  const byId = new Map(objects.map(o => [o.id, o]));

  /*
    Detection is not a field. x_mitre_data_sources is unpopulated in this bundle
    version; what carries the answer is a detection strategy pointing at the
    technique, holding analytics, holding log source references. Reading the old
    field returns nothing for every technique and looks like a working importer,
    which is the whole reason this walk is written out rather than assumed.
  */
  const logName = new Map(objects
    .filter(o => o.type === 'x-mitre-log-source')
    .map(o => [o.id, o.name]));

  const analyticLogs = (a) => {
    const seen = [];
    for (const ref of a?.x_mitre_log_source_references ?? []) {
      const n = logName.get(ref.x_mitre_data_component_ref) ?? ref.name;
      // De-duplicated: one analytic commonly cites the same log twice.
      if (n && !seen.includes(n)) seen.push(n);
    }
    return seen;
  };

  const detectionFor = new Map();
  for (const r of objects) {
    if (r.type !== 'relationship' || r.relationship_type !== 'detects') continue;
    const strat = byId.get(r.source_ref);
    if (!strat || strat.type !== 'x-mitre-detection-strategy') continue;
    const logSources = [];
    for (const ref of strat.x_mitre_analytic_refs ?? []) {
      for (const n of analyticLogs(byId.get(ref))) if (!logSources.includes(n)) logSources.push(n);
    }
    detectionFor.set(r.target_ref, [
      ...(detectionFor.get(r.target_ref) ?? []),
      { strategy: strat.name, logSources },
    ]);
  }

  const techniques = objects
    .filter(o => o.type === 'attack-pattern' && !o.x_mitre_deprecated && !o.revoked && mitreId(o))
    .map((o) => {
      const id = mitreId(o);
      return {
        id,
        name: o.name,
        tactics: (o.kill_chain_phases ?? [])
          .filter(p => p.kill_chain_name?.startsWith('mitre'))
          .map(p => p.phase_name),
        platforms: o.x_mitre_platforms ?? [],
        // The first paragraph only. The full description is prose for a website.
        desc: firstLine(o.description),
        isSub: Boolean(o.x_mitre_is_subtechnique),
        parent: o.x_mitre_is_subtechnique ? id.split('.')[0] : null,
        detection: detectionFor.get(o.id) ?? [],
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));

  const collection = objects.find(o => o.type === 'x-mitre-collection');
  return {
    domain,
    // Recorded so a plan built against one release is identifiable later.
    version: collection?.x_mitre_version ?? 'unknown',
    generated: new Date().toISOString().slice(0, 10),
    techniques,
  };
}

const arg = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : null;
};

if (process.argv[1]?.endsWith('import-attack.mjs')) {
  const domain = arg('domain');
  const input = arg('in');
  if (!['enterprise', 'ics'].includes(domain) || !input) {
    console.error('usage: node tools/import-attack.mjs --domain enterprise|ics --in <bundle.json>');
    process.exit(1);
  }
  const out = arg('out') ?? `plans/attack/${domain}.json`;
  const trimmed = trimBundle(JSON.parse(readFileSync(input, 'utf8')), domain);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(trimmed, null, 0)}\n`, 'utf8');
  const withDetection = trimmed.techniques.filter(t => t.detection.length).length;
  console.log(`  ${out}`);
  console.log(`  ${trimmed.techniques.length} techniques, ATT&CK ${trimmed.version}`);
  console.log(`  ${withDetection} carry a detection strategy`);

  /*
    Imported here, not at module top level, so trimBundle stays reachable by
    its test (and any future importer) without pulling store/bank.js's own
    file reads along for the ride. An orphaned overlay is authored tradecraft
    about to disappear on this exact regeneration — the one moment this tool
    runs — so it is surfaced here rather than left for the orphan test to
    notice weeks later.
  */
  const { orphanOverlays } = await import('../store/bank.js');
  const orphans = orphanOverlays();
  if (orphans.length) {
    console.log(`  ORPHANED OVERLAYS (technique no longer in either matrix): ${orphans.join(', ')}`);
  }
}
