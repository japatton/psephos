import { createHash } from 'node:crypto';
import { newId, nowIso } from '../lib/ids.js';

/** Generous enough for a day of logs, small enough not to bloat the store. */
export const MAX_FILE_BYTES = 25 * 1024 * 1024;

/** Extensions an analyst actually shares. Everything else is stored as bytes. */
const TEXTUAL = /\.(txt|log|csv|tsv|json|xml|yaml|yml|md|conf|cfg|ini|pcap-summary|evtx-txt|ps1|sh|py)$/i;

/**
 * Is this content text we can put in front of a model, or opaque bytes?
 *
 * Decided from the content, not the extension: analysts rename things, and a
 * .log that is actually a gzip must not be pasted into a prompt as mojibake.
 * A NUL byte in the first 8k is the reliable tell.
 */
export function looksTextual(buf, name = '') {
  const head = buf.subarray(0, 8192);
  if (head.includes(0)) return false;
  // Count bytes that are neither printable ASCII nor ordinary whitespace.
  let odd = 0;
  for (const b of head) {
    if (b === 9 || b === 10 || b === 13) continue;
    if (b < 32 || b === 127) odd++;
  }
  if (head.length && odd / head.length > 0.05) return false;
  return TEXTUAL.test(name) || head.length > 0;
}

export function saveFile(db, { name, mime, buffer, uploadedBy }) {
  if (!buffer?.length) throw new Error('empty file');
  if (buffer.length > MAX_FILE_BYTES) {
    throw new Error(`file is ${Math.round(buffer.length / 1048576)}MB; the limit is ${MAX_FILE_BYTES / 1048576}MB`);
  }
  const id = newId();
  const sha = createHash('sha256').update(buffer).digest('hex');
  const isText = looksTextual(buffer, name) ? 1 : 0;
  db.prepare(`insert into files (id,name,mime,size,sha256,body,is_text,uploaded_by,uploaded_at)
              values (?,?,?,?,?,?,?,?,?)`)
    .run(id, name || 'unnamed', mime || 'application/octet-stream',
      buffer.length, sha, buffer, isText, uploadedBy ?? null, nowIso());
  return getFileMeta(db, id);
}

export const getFileMeta = (db, id) => db.prepare(
  'select id,name,mime,size,sha256,is_text,uploaded_by,uploaded_at from files where id = ?').get(id) ?? null;

export const getFileBody = (db, id) => db.prepare('select * from files where id = ?').get(id) ?? null;

/**
 * File content for a prompt, bounded.
 *
 * Binary files are described rather than decoded — a hash and a size are
 * useful to an analyst, a megabyte of mojibake is not.
 */
export function fileAsPromptText(db, id, { limit = 200_000 } = {}) {
  const f = getFileBody(db, id);
  if (!f) return null;
  if (!f.is_text) {
    return `--- ${f.name} (${f.size} bytes, ${f.mime}) ---\n` +
      `[binary; not decoded. sha256 ${f.sha256}]`;
  }
  const text = Buffer.from(f.body).toString('utf8');
  const clipped = text.slice(0, limit);
  return `--- ${f.name} (${f.size} bytes, sha256 ${f.sha256}) ---\n${clipped}` +
    (text.length > limit ? `\n--- truncated at ${limit} of ${text.length} characters ---` : '');
}
