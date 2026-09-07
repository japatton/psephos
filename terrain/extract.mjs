/**
 * One-shot generator: an asset-inventory HTML export -> terrain JSON.
 *
 * Committed so the seed is reproducible and reviewable rather than a
 * hand-typed artifact. Re-run it if the asset inventory changes:
 *
 *   node terrain/extract.mjs <assets.html> [out.json]
 *
 * The generated <profile>/terrain.json is what the server actually loads, so
 * the app has no runtime dependency on the source HTML.
 *
 * The input path is required rather than defaulted. The default that used to
 * be here pointed at one operator's Downloads folder and named the engagement
 * in the filename, which is engagement data sitting in a tracked file — and a
 * default nobody passes is also a default nobody notices is wrong.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { missionPaths } from '../store/mission.js';

const decode = (s) => (s ?? '')
  .replace(/<[^>]+>/g, '')
  .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
  .replace(/&quot;/g, '"').replace(/&#x27;|&#39;/g, "'")
  .replace(/&middot;/g, '·').replace(/&nbsp;/g, ' ')
  .replace(/&#8209;/g, '-')
  .trim();

const pick = (html, cls) => {
  const m = new RegExp(`<span class="${cls}"[^>]*>(.*?)</span>`, 's').exec(html);
  return m ? decode(m[1]) : '';
};

export function extract(html, sourceName = 'asset inventory export') {
  const enclaves = [];

  // Each enclave is a <section class="enclave" id="...">.
  const sections = html.split(/<section class="enclave"/).slice(1);

  for (const raw of sections) {
    const id = /id="([^"]+)"/.exec(raw)?.[1] ?? 'unknown';
    const h2 = /<h2>(.*?)<\/h2>/s.exec(raw)?.[1] ?? '';
    const name = decode(h2.replace(/<span class="eroot".*?<\/span>/s, ''));
    const cidr = pick(h2, 'eroot');
    const description = decode(/<p>(.*?)<\/p>/s.exec(raw)?.[1] ?? '');

    const segments = [];
    for (const segRaw of raw.split(/<div class="seg"/).slice(1)) {
      const segName = pick(segRaw, 'segname');
      const segCidr = pick(segRaw, 'cidr');
      const note = decode(/<div class="segnote">(.*?)<\/div>/s.exec(segRaw)?.[1] ?? '');

      const hosts = [];
      const hostRe = /<div class="host ([^"]*)"[^>]*>(.*?)<\/div>/gs;
      let m;
      while ((m = hostRe.exec(segRaw)) !== null) {
        const [, kind, body] = m;
        const os = pick(body, 'hos');
        hosts.push({
          name: pick(body, 'hn'),
          ip: pick(body, 'hip'),
          os: os === '—' ? '' : os,
          role: pick(body, 'hrole'),
          kind: kind.trim(), // win | nix | unk
        });
      }
      segments.push({ name: segName, cidr: segCidr, note, hosts });
    }
    enclaves.push({ key: id, name, cidr, description, segments });
  }
  return { source: sourceName, enclaves };
}

// Run directly, not when imported by a test.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  const src = process.argv[2];
  if (!src) {
    console.error('usage: node terrain/extract.mjs <assets.html> [out.json]');
    process.exit(1);
  }
  // Stamped with the file it actually read, so the terrain says where it came
  // from rather than where it came from the first time this was written.
  const terrain = extract(readFileSync(src, 'utf8'), basename(src));
  // Third argument, or the active profile's terrain. Writing into a profile
  // rather than into the source tree is the point of the split.
  const out = process.argv[3] || missionPaths().terrain;
  writeFileSync(out, JSON.stringify(terrain, null, 2) + '\n');
  const segs = terrain.enclaves.flatMap(e => e.segments);
  const hosts = segs.flatMap(s => s.hosts);
  console.log(`wrote ${out}`);
  console.log(`  ${terrain.enclaves.length} enclaves, ${segs.length} segments, ${hosts.length} named hosts`);
}
