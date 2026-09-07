import { test, before } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { createSession, appendMessage } from '../store/sessions.js';
import { usageBySession, usageByMember, usageTotal } from '../store/usage.js';

/*
  Four people on a roster spend one shared quota. When it runs low the question
  is where it went, and the answer used to be discarded: the runner surfaced
  Claude's own rate-limit percentage as a warning and wrote nothing down.
*/

let db, a, b;

before(() => {
  db = openDb(':memory:');
  initSchema(db);
  a = createSession(db, { title: 'Reyes', analyst: 'Reyes' });
  b = createSession(db, { title: 'Okafor', analyst: 'Okafor' });

  appendMessage(db, a.id, 'user', 'look at this', 'evidence');
  appendMessage(db, a.id, 'assistant', 'a finding', 'evidence',
    { inputTokens: 1000, outputTokens: 200, costUsd: 0.03, durationMs: 4200, model: 'claude-opus-5' });
  appendMessage(db, a.id, 'assistant', 'another', 'evidence',
    { inputTokens: 500, outputTokens: 100, costUsd: 0.01, durationMs: 1800, model: 'claude-opus-5' });
  appendMessage(db, b.id, 'assistant', 'theirs', 'evidence',
    { inputTokens: 300, outputTokens: 50, costUsd: 0.005, durationMs: 900, model: 'claude-opus-5' });
});

test('a turn records what it cost alongside what it said', () => {
  const rows = db.prepare(
    "select * from messages where role='assistant' and session_id = ? order by ts, rowid").all(a.id);
  assert.equal(rows[0].input_tokens, 1000);
  assert.equal(rows[0].output_tokens, 200);
  assert.equal(rows[0].model, 'claude-opus-5');
});

test('a turn with no usage reported is stored without inventing zeroes', () => {
  const user = db.prepare("select * from messages where role='user'").get();
  assert.equal(user.input_tokens, null, 'a missing measurement is not the same as none');
});

test('spend rolls up per session', () => {
  const by = Object.fromEntries(usageBySession(db).map(r => [r.session_id, r]));
  assert.equal(by[a.id].input_tokens, 1500);
  assert.equal(by[a.id].output_tokens, 300);
  assert.equal(by[a.id].turns, 2, 'only the turns that cost anything are counted');
  assert.ok(Math.abs(by[a.id].cost_usd - 0.04) < 1e-9);
});

test('spend rolls up per analyst, which is who the quota belongs to', () => {
  const by = Object.fromEntries(usageByMember(db).map(r => [r.analyst, r]));
  assert.equal(by.Reyes.input_tokens, 1500);
  assert.equal(by.Okafor.input_tokens, 300);
});

test('the total is the number that answers "how much is left"', () => {
  const t = usageTotal(db);
  assert.equal(t.input_tokens, 1800);
  assert.equal(t.output_tokens, 350);
  assert.equal(t.turns, 3);
});

test('a store with no turns reports zero rather than null', () => {
  const empty = openDb(':memory:');
  initSchema(empty);
  const t = usageTotal(empty);
  assert.equal(t.turns, 0);
  assert.equal(t.input_tokens, 0, 'null here renders as "null tokens" in the header');
  empty.close();
});
