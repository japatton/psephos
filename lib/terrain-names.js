/**
 * Line an exported host identifier up with the name terrain uses for it.
 *
 * Shared rather than copied, because the interesting case is the one that is
 * easy to get wrong twice: an address that terrain does not know.
 *
 * The short-name fallback exists because an export may say WKS-01 where
 * terrain says WKS-01.range.example. Applied to an address it is a
 * disaster — "10.125.10.255".split('.')[0] is "10", which matched a terrain
 * host literally named 10.20.40.1, so dozens of distinct scanned addresses
 * collapsed onto one machine. An address terrain has never seen is its own
 * identity and nothing else's.
 */

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** PowerShell prints an unexpanded array like this; it is not a host. */
const NOT_A_HOST = new Set(['', 'system.object[]', 'null', 'n/a', '-']);

/**
 * @param {Array<{ip: string, name: string}>} terrain
 * @returns {(value: string) => string|null} null only when there is no identifier at all
 */
export function terrainNamer(terrain) {
  const byIp = new Map();
  const byShort = new Map();
  const held = new Map();          // name -> how many terrain rows carry it
  for (const h of terrain ?? []) {
    if (h.ip) byIp.set(String(h.ip).trim(), h.name);
    held.set(h.name, (held.get(h.name) ?? 0) + 1);
    const short = String(h.name ?? '').split('.')[0].toLowerCase();
    // First writer wins, so two hosts sharing a short name do not silently
    // trade places depending on table order.
    if (short && !byShort.has(short)) byShort.set(short, h.name);
  }

  /*
    A name two machines share cannot identify either of them.
    Terrain holds PLC-B twice, once per substation subnet, and
    an HMI twice; answering with the name would merge two devices into one
    baseline and hand back the union of their open ports as though it were one
    box. The address is the only thing that tells them apart, so it wins.
  */
  const ambiguous = (name) => (held.get(name) ?? 0) > 1;

  return function resolve(value) {
    const s = String(value ?? '').trim();
    if (NOT_A_HOST.has(s.toLowerCase())) return null;

    const exact = byIp.get(s);
    if (exact) return ambiguous(exact) ? s : exact;
    if (IPV4.test(s)) return s;          // an address is never a short name

    const byName = byShort.get(s.split('.')[0].toLowerCase());
    if (byName) return ambiguous(byName) ? s : byName;
    return s;
  };
}
