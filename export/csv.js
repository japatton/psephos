import { COLUMNS, HEADERS } from '../store/records.js';

/**
 * RFC 4180. CRLF line endings and a UTF-8 BOM so Excel opens the file as
 * UTF-8 rather than mangling the analyst notes.
 */
/*
  A spreadsheet runs a cell that starts with one of these; RFC 4180 quoting does
  not stop it, because quotes are CSV structure and not a formula escape.

  Every column in this export is text an adversary may have authored — `command`
  is a command line and `indicator` a process name, both lifted verbatim from
  logs on a compromised host — so `=cmd|'/C calc'!A0` reaches the analyst's
  machine as a formula unless something here refuses it.

  A leading apostrophe is the mitigation every spreadsheet understands: it shows
  the text and runs none of it. It does mean the CSV no longer byte-matches the
  stored value, which in a forensics tool is a real cost — so it is applied only
  to values that would otherwise execute, and the xlsx export is untouched
  because its inlineStr cells were never evaluated. An analyst who needs the
  bytes exactly has that route.
*/
const RUNS_IN_A_SPREADSHEET = /^[=+\-@\t\r]/;

const cell = (v) => {
  const raw = v == null ? '' : String(v);
  const s = RUNS_IN_A_SPREADSHEET.test(raw) ? `'${raw}` : raw;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export function recordsToCsv(records) {
  const lines = [HEADERS.map(cell).join(',')];
  for (const r of records) lines.push(COLUMNS.map(c => cell(r[c])).join(','));
  return '﻿' + lines.join('\r\n') + '\r\n';
}
