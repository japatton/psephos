import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

/**
 * Shared bearer token. Generated on first start, persisted next to the server
 * so a restart does not invalidate everyone's browser tab.
 *
 * This is the only thing standing between the LAN and an evidence store that
 * can also spawn Claude runs on this machine. The threat model it is built to
 * is in SECURITY.md.
 */
export function loadOrCreateToken(path = '.hunt-token') {
  if (existsSync(path)) {
    const t = readFileSync(path, 'utf8').trim();
    if (t) return { token: t, created: false };
  }
  const token = randomBytes(32).toString('hex');
  writeFileSync(path, token + '\n', { mode: 0o600 });
  return { token, created: true };
}

/**
 * Cookie header to object.
 *
 * A value that is not valid percent-encoding is kept raw rather than throwing.
 * decodeURIComponent('%ZZ') raises URIError, and because every request parses
 * cookies before anything else, one malformed cookie turned every single
 * request into a 500 — including the login page, so there was no way back
 * except clearing cookies by hand. The server does not set such a value, but
 * a truncated cookie or another application on the same host can.
 */
export function parseCookies(header = '') {
  const out = {};
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const raw = part.slice(i + 1).trim();
    let value;
    try { value = decodeURIComponent(raw); } catch { value = raw; }
    out[part.slice(0, i).trim()] = value;
  }
  return out;
}

/**
 * Constant-time comparison for the operator token.
 *
 * `===` short-circuits on the first differing byte. Over a LAN the jitter
 * almost certainly buries the signal, but this is the credential that grants
 * the whole case file and the ability to spawn model runs, and the correct
 * primitive costs nothing.
 */
export function sameToken(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  // Length alone is not secret, and timingSafeEqual demands equal lengths.
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

/**
 * Accepts the token as a bearer header or a cookie. The cookie path exists
 * because EventSource cannot set request headers, and the map and timeline are
 * useless without the SSE stream.
 *
 * The analyst name is attribution, not authentication — anyone holding the
 * token can claim any name. It exists so an audit row says who decided, not to
 * gate access.
 */
export function checkAuth(req, token, db = null, memberByToken = null) {
  const cookies = parseCookies(req.headers.cookie);
  const header = req.headers.authorization ?? '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  const supplied = bearer ?? cookies.hunt_token ?? null;
  if (!supplied) return { ok: false, analyst: null, member: null };

  // A member token identifies who is asking, which is what makes attribution
  // automatic and stops anyone typing into a colleague's window by accident.
  if (db && memberByToken) {
    const m = memberByToken(db, supplied);
    if (m) return { ok: true, analyst: m.name, member: m };
  }

  /*
    The server token stays valid for operator access and scripted calls. It
    grants read and adjudication but is nobody's chat window.

    The analyst name is fixed to 'operator' rather than read from the
    hunt_analyst cookie. That cookie is client-supplied, and the same value
    gates DM membership and stamps chat authorship — so honouring it here let
    anyone holding the operator token set hunt_analyst=Lindqvist and then read
    Lindqvist's DMs and post as Lindqvist. A member token still supplies its own name,
    which is the case where the name is actually attested.
  */
  if (sameToken(supplied, token)) {
    return { ok: true, analyst: 'operator', member: null };
  }
  return { ok: false, analyst: null, member: null };
}
