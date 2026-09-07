import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { seedThreads } from '../store/threads.js';
import { createRecord } from '../store/records.js';
import {
  buildEvidenceCorpus, buildSystemPrompt, promptBudget,
  MAX_PROMPT_CHARS, ARGV_PROMPT_CHARS,
} from '../claude/prompt.js';

const DESC = 'Sudo/su log records recovered from a client host show a domain account escalating '
  + 'to root outside any change window, with the parent process a scheduled task nobody owns.';

function withRecords(n) {
  const db = openDb(':memory:');
  initSchema(db);
  seedThreads(db);
  for (let i = 1; i <= n; i++) {
    createRecord(db, {
      hostname: `HOST-${i}.example.test`, source_ip: `10.20.0.${i % 255}`,
      destination_ip: '10.20.1.10', indicator: 'suspicious.elf', mitre: 'T1548.003',
      event_time: '2026-08-19 11:59', description: DESC,
    }, { analyst: 'm' });
  }
  return db;
}

const idsIn = (corpus) => (corpus.match(/\[[0-9a-f]{8}\]/g) ?? []).length;

test('an empty case file says so rather than pretending', () => {
  assert.match(buildEvidenceCorpus(withRecords(0)), /empty/);
});

test('a case file that fits is shown in full, descriptions and all', () => {
  const corpus = buildEvidenceCorpus(withRecords(20), { maxChars: 60_000 });
  assert.match(corpus, /all shown/);
  assert.equal(idsIn(corpus), 20);
  assert.match(corpus, /scheduled task nobody owns/, 'the description survives');
});

/*
  The behaviour this whole change exists for. A record the model is not told
  about is a duplicate waiting to be proposed, so when it will not all fit,
  detail is given up before coverage is: every record still appears, just
  without its description, and search_records fetches the rest.

  Before this, the corpus filled to the budget with full lines and stopped. At
  ninety-two records of this size the model stopped being shown the rest, and
  at four hundred it saw eighty.
*/
test('when full detail will not fit, every record is still listed', () => {
  const db = withRecords(300);
  const corpus = buildEvidenceCorpus(db, { maxChars: 60_000 });
  assert.match(corpus, /all listed in short form/);
  assert.equal(idsIn(corpus), 300, 'not one record is dropped');
  assert.doesNotMatch(corpus, /scheduled task nobody owns/, 'descriptions are what was given up');
  assert.match(corpus, /search_records/, 'and it says where the detail is');
});

test('short form still carries what recognition needs', () => {
  const corpus = buildEvidenceCorpus(withRecords(300), { maxChars: 60_000 });
  assert.match(corpus, /HOST-7\.example\.test/, 'the host');
  assert.match(corpus, /suspicious\.elf/, 'the indicator');
  assert.match(corpus, /T1548\.003/, 'the technique');
  assert.match(corpus, /2026-08-19 11:59/, 'the time');
});

test('only when even short form overflows are records withheld, and it says how many', () => {
  const corpus = buildEvidenceCorpus(withRecords(400), { maxChars: 6_000 });
  const m = /showing the first (\d+) in short form\. (\d+) MORE EXIST/.exec(corpus);
  assert.ok(m, `expected an explicit shortfall, got: ${corpus.slice(0, 200)}`);
  assert.equal(Number(m[1]) + Number(m[2]), 400, 'the arithmetic accounts for every record');
  assert.equal(idsIn(corpus), Number(m[1]));
});

test('a denied record is not in the case file at all', () => {
  const db = withRecords(3);
  const id = db.prepare('select id from records limit 1').get().id;
  db.prepare("update records set state = 'denied' where id = ?").run(id);
  assert.equal(idsIn(buildEvidenceCorpus(db, { maxChars: 60_000 })), 2);
});

// --- the budget ------------------------------------------------------------

/*
  The ceiling used to be a hard constraint: the prompt was an argv value and
  CreateProcessW caps a command line at 32,767 characters. With
  --append-system-prompt-file it is a cost decision instead, so the two paths
  get different budgets and the older one keeps the limit that is real for it.
*/
test('the budget depends on how the prompt reaches the model', () => {
  assert.equal(promptBudget(true), MAX_PROMPT_CHARS);
  assert.equal(promptBudget(false), ARGV_PROMPT_CHARS);
  assert.ok(ARGV_PROMPT_CHARS < 32_767, 'the argv path must stay under the Windows ceiling');
  assert.ok(MAX_PROMPT_CHARS > ARGV_PROMPT_CHARS);
});

test('the argv fallback stays inside the Windows command-line limit', () => {
  const prompt = buildSystemPrompt(withRecords(500), {
    mode: 'evidence', maxChars: ARGV_PROMPT_CHARS,
  });
  assert.ok(prompt.length <= ARGV_PROMPT_CHARS,
    `${prompt.length} chars would be spawned as one argv value`);
  // Room for the denylist, the MCP config path and the rest of the argv.
  assert.ok(prompt.length + 3_000 < 32_767);
});

test('a large case file does not blow the budget on the file path either', () => {
  const prompt = buildSystemPrompt(withRecords(800), {
    mode: 'evidence', maxChars: MAX_PROMPT_CHARS,
  });
  assert.ok(prompt.length <= MAX_PROMPT_CHARS, `${prompt.length} > ${MAX_PROMPT_CHARS}`);
});

test('research and characterization modes carry no case file', () => {
  const db = withRecords(50);
  for (const mode of ['research', 'characterization']) {
    assert.doesNotMatch(buildSystemPrompt(db, { mode }), /CASE FILE/, `${mode} leaked the corpus`);
  }
});

test('building the corpus at scale is not slow enough to notice', () => {
  const db = withRecords(1_000);
  const t0 = performance.now();
  buildEvidenceCorpus(db, { maxChars: MAX_PROMPT_CHARS });
  const ms = performance.now() - t0;
  assert.ok(ms < 500, `took ${Math.round(ms)}ms; it runs on every turn`);
});
