import { test } from 'node:test';
import assert from 'node:assert';
import { parseEventTime } from '../lib/time.js';

// Every value below is a real cell from the timeline workbook or
// the investigation records export. This parser decides where every mark on the
// timeline lands, so the cases are the actual mess, not a tidied version of it.
const cases = [
  ['2026-08-13 17:59:02Z',                 'exact',       '2026-08-13T17:59:02.000Z'],
  ['2026-08-17 22:02:35.446Z',             'exact',       '2026-08-17T22:02:35.446Z'],
  ['2026-08-17 22:02:35.493Z',             'exact',       '2026-08-17T22:02:35.493Z'],
  ['2026-08-13 23:04:43Z',                 'exact',       '2026-08-13T23:04:43.000Z'],
  ['2026-08-19 ~11:59 (discovered; removal reported)', 'approximate', '2026-08-19T11:59:00.000Z'],
  ['2026-08-19 ~15:26',                    'approximate', '2026-08-19T15:26:00.000Z'],
  ['Scheduled: 0 18 * * 3 = Wednesday 18:00 - TODAY (2026-08-19)', 'approximate', '2026-08-19T18:00:00.000Z'],
  ['2026-08-19',                           'approximate', '2026-08-19T00:00:00.000Z'],
  ['N/A (host forensics - cron)',          'unplaceable', null],
  ['N/A',                                  'unplaceable', null],
  ['N/A (staged, not observed executing)', 'unplaceable', null],
  ['N/A (crontab)',                        'unplaceable', null],
  ['N/A (procdump / string analysis)',     'unplaceable', null],
  ['',                                     'unplaceable', null],
  ['   ',                                  'unplaceable', null],
  [null,                                   'unplaceable', null],
  [undefined,                              'unplaceable', null],
];

for (const [raw, tier, iso] of cases) {
  test(`parseEventTime ${JSON.stringify(raw)} -> ${tier}`, () => {
    const got = parseEventTime(raw);
    assert.equal(got.tier, tier, `tier for ${JSON.stringify(raw)}`);
    assert.equal(got.iso, iso, `iso for ${JSON.stringify(raw)}`);
  });
}

test('impossible dates are unplaceable, not silently rolled over', () => {
  assert.equal(parseEventTime('2026-02-31').tier, 'unplaceable');
  assert.equal(parseEventTime('2026-13-01').tier, 'unplaceable');
});

test('out-of-range clock values fall back rather than corrupting position', () => {
  // 99:99 is not a time; the date still anchors the mark.
  const got = parseEventTime('2026-08-19 ~99:99');
  assert.equal(got.tier, 'approximate');
  assert.equal(got.iso, '2026-08-19T00:00:00.000Z');
});

test('never throws on arbitrary input', () => {
  const junk = ['???', '0 18 * * 3', 'Wednesday', '99-99-99', '::::', '2026-', {}, [], 0, NaN];
  for (const j of junk) {
    assert.doesNotThrow(() => parseEventTime(j), `threw on ${JSON.stringify(j)}`);
  }
});

/*
  A bare date placed at the moment it was written.

  Midnight is the obvious anchor and the wrong one: it sorts a live
  observation made at six in the evening ahead of everything that actually
  happened that day, so the timeline reads backwards. Three live-observation
  records sat at 00:00 for exactly that reason.
*/
test('a bare date recorded the same day is placed at the moment it was written', () => {
  const out = parseEventTime('2026-08-25 (live observation; exact time not recorded)',
    { recordedAt: '2026-08-25T18:06:21.625Z' });
  assert.equal(out.iso, '2026-08-25T18:06:21.625Z');
  assert.equal(out.tier, 'approximate', 'a better position is not more precision');
});

test('a bare date for an earlier day stays at midnight', () => {
  // The write-up time says nothing about an event a week and a half earlier,
  // and midnight at least stays inside the right day.
  const out = parseEventTime('2026-08-14 (noticed later)',
    { recordedAt: '2026-08-25T18:06:21.625Z' });
  assert.equal(out.iso, '2026-08-14T00:00:00.000Z');
  assert.equal(out.tier, 'approximate');
});

test('a time the analyst did record always wins over the write time', () => {
  const out = parseEventTime('2026-08-25 ~17:43 (nmap scan start)',
    { recordedAt: '2026-08-25T18:54:28.913Z' });
  assert.equal(out.iso, '2026-08-25T17:43:00.000Z');
});

test('a full timestamp is untouched by the write time', () => {
  const out = parseEventTime('2026-08-25T04:31:07Z', { recordedAt: '2026-08-25T17:12:56.331Z' });
  assert.equal(out.iso, '2026-08-25T04:31:07.000Z');
  assert.equal(out.tier, 'exact');
});

test('N/A stays unplaceable even when the record was written that day', () => {
  // The analyst said there is no time. A date inside the note is context, not
  // a position, and the write time must not manufacture one.
  const out = parseEventTime('N/A (file recovered via host forensics 2026-08-25)',
    { recordedAt: '2026-08-25T19:07:26.360Z' });
  assert.equal(out.iso, null);
  assert.equal(out.tier, 'unplaceable');
});

test('without a write time the old behaviour is unchanged', () => {
  assert.equal(parseEventTime('2026-08-25 (live observation)').iso, '2026-08-25T00:00:00.000Z');
});

test('a nonsense write time is ignored rather than throwing', () => {
  for (const bad of ['not a date', '', null, '2026-13-45T99:99:99Z']) {
    const out = parseEventTime('2026-08-25 (live)', { recordedAt: bad });
    assert.equal(out.iso, '2026-08-25T00:00:00.000Z', `recordedAt=${JSON.stringify(bad)}`);
  }
});
