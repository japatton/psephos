import { test, before } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { stageSnapshot } from '../store/characterization.js';

/*
  Whether an identity came out of the source or out of the model.

  #4 is an upload whose usernames were derived from the position of the row
  rather than read from a field. Nothing already in this file catches that: the
  rows arrived with their username column populated, so the existing unnamed-row
  guard never fires — that one only sees an identity that is *absent*, and this
  one is present and wrong, which is worse, because it looks like data.

  A store cannot tell a correct username from a mis-assigned one. It can tell
  one that is not in the source at all, and that is the half worth catching: an
  identity the extraction invented appears nowhere in the text it claims to have
  read. Mis-pairing two real values is still invisible here and this does not
  pretend otherwise.

  Flagged, never dropped, in line with everything else in this path. A row that
  cannot be trusted is still evidence of something, and an upload that quietly
  discards it is the failure the whole file exists to prevent.
*/

let db;
before(() => { db = openDb(':memory:'); initSchema(db); });

const SOURCE = `
Name              Enabled  LastLogon
svc_sql           True     2026-03-01
svc_backup        True     2026-02-11
jdoe              False    2025-12-30
`;

test('an upload whose identities all appear in the source is accepted', () => {
  const out = stageSnapshot(db, {
    repo: 'domain-accounts', host: 'range.example', sourceText: SOURCE,
    entities: [
      { username: 'svc_sql', enabled: true },
      { username: 'svc_backup', enabled: true },
      { username: 'jdoe', enabled: false },
    ],
  });
  assert.equal(out.extracted_rows, 3);
  assert.equal(out.status, 'ok', `unexpectedly flagged: ${out.note}`);
});

/*
  The shape of #4: the count is right, the column is populated, every row looks
  like an account — and one of the names was never in the file.
*/
test('an identity that is not in the source is flagged, and the note says which', () => {
  const out = stageSnapshot(db, {
    repo: 'domain-accounts', host: 'range.example', sourceText: SOURCE,
    entities: [
      { username: 'svc_sql', enabled: true },
      { username: 'administrator', enabled: true },   // never appears above
    ],
  });
  assert.equal(out.status, 'incomplete');
  assert.match(out.note, /source/i);
  assert.match(out.note, /administrator/,
    'the note has to name the value, or nobody can check it');
});

test('the row is still stored, because an untrustworthy row is still evidence', () => {
  const n = db.prepare(
    "select count(*) n from char_entities where repo = 'domain-accounts'").get().n;
  assert.ok(n >= 5, 'a flagged row was dropped rather than kept');
});

test('matching ignores case and surrounding whitespace, as the source formats vary', () => {
  const out = stageSnapshot(db, {
    repo: 'domain-accounts', host: 'range.example', sourceText: SOURCE,
    entities: [{ username: '  SVC_SQL  ' }],
  });
  assert.equal(out.status, 'ok', `case or padding was treated as absence: ${out.note}`);
});

/*
  Without a source there is nothing to check against, and a check that cannot
  run must not invent a verdict. Every existing caller omits it.
*/
test('an upload with no source text is judged exactly as before', () => {
  const out = stageSnapshot(db, {
    repo: 'domain-accounts', host: 'range.example',
    entities: [{ username: 'nobody_checked_this' }],
  });
  assert.equal(out.status, 'ok');
});

/*
  The guard must not fire on an identity built from several fields where the
  parts are in the source but the joined string is not — that is every
  multi-field repository in the file.
*/
test('a composite identity is checked by its parts, not as one string', () => {
  const out = stageSnapshot(db, {
    repo: 'spns', host: 'range.example',
    sourceText: 'account: svc_web\nspn: HTTP/www.range.example\n',
    entities: [{ account: 'svc_web', spn: 'HTTP/www.range.example' }],
  });
  assert.equal(out.status, 'ok', `composite identity misjudged: ${out.note}`);
});

test('and a composite whose parts are invented is still caught', () => {
  const out = stageSnapshot(db, {
    repo: 'spns', host: 'range.example',
    sourceText: 'account: svc_web\nspn: HTTP/www.range.example\n',
    entities: [{ account: 'svc_web', spn: 'LDAP/dc-01.range.example' }],
  });
  assert.equal(out.status, 'incomplete');
  assert.match(out.note, /LDAP\/dc-01/);
});
