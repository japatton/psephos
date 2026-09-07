import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DIR = mkdtempSync(join(tmpdir(), 'huntapi-'));
process.env.HUNT_MODEL_CONFIG = join(DIR, 'model.json');
// Low enough to exhaust deliberately; every other test here settles in one or
// two steps, so it costs them nothing.
process.env.HUNT_MAX_TOOL_STEPS = '3';
// Short, so the stall test ends in a second rather than five minutes. Every
// other test here answers immediately.
process.env.HUNT_TURN_TIMEOUT_MS = '1500';

const { openDb, initSchema } = await import('../store/db.js');
const { seedHosts } = await import('../store/hosts.js');
const { seedThreads } = await import('../store/threads.js');
const { createSession, listMessages, getSession } = await import('../store/sessions.js');
const { listRecords } = await import('../store/records.js');
const { setModelConfig } = await import('../store/model-config.js');
const { runTurn, toolsFor, parseArgs } = await import('../claude/api-provider.js');

process.on('exit', () => rmSync(DIR, { recursive: true, force: true }));

const fresh = () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedThreads(db);
  seedHosts(db);
  return db;
};

// --- tool exposure -------------------------------------------------------------

test('each mode is offered exactly the tools it is allowed', () => {
  const names = (mode) => toolsFor(mode).map(t => t.name).sort();

  // Evidence files findings but must not rewrite what "normal" means, or a
  // pasted log could quietly move the baseline it is being judged against.
  assert.ok(names('evidence').includes('propose_finding'));
  assert.equal(names('evidence').includes('stage_entities'), false);

  // Research reads and reasons; it records nothing.
  assert.equal(names('research').includes('propose_finding'), false);
  assert.equal(names('research').includes('propose_edge'), false);

  // Characterization builds baselines and, by the same argument, files nothing.
  assert.ok(names('characterization').includes('stage_entities'));
  assert.equal(names('characterization').includes('propose_finding'), false);
});

test('every offered tool carries a schema the API can send', () => {
  for (const mode of ['evidence', 'research', 'characterization']) {
    for (const t of toolsFor(mode)) {
      assert.equal(t.inputSchema.type, 'object', `${t.name} needs an object schema`);
      assert.ok(t.description.length > 40, `${t.name} needs a usable description`);
    }
  }
});

test('streamed argument fragments that never completed do not throw', () => {
  assert.deepEqual(parseArgs('{"a":1}'), { a: 1 });
  assert.deepEqual(parseArgs('{"a":'), {}, 'a truncated stream is empty args, not a crash');
  assert.deepEqual(parseArgs(''), {});
});

// --- the turn loop -------------------------------------------------------------

/**
 * A fake endpoint speaking the OpenAI streaming shape.
 *
 * The turn loop is the part worth testing and the part that cannot be checked
 * against a real API in CI, so the transport is stubbed and the loop is real:
 * the tool call really reaches handleToolCall, and its result really goes back
 * in as the next request's input.
 */
let server;
let seen = [];
let script = [];
// From this request number on, the endpoint accepts and never answers, so the
// turn's own timeout ends it. Counted rather than a flag because the case worth
// testing is a turn that streamed something and *then* stalled — stalling the
// first request means nothing was ever shown to preserve.
let stallFrom = Infinity;

const sse = (chunks) => chunks.map(c => `data: ${JSON.stringify(c)}\n\n`).join('') + 'data: [DONE]\n\n';

before(async () => {
  const { createServer } = await import('node:http');
  server = createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      seen.push(JSON.parse(body));
      if (seen.length >= stallFrom) { res.writeHead(200, { 'content-type': 'text/event-stream' }); return; }
      const next = script.shift() ?? [{ choices: [{ delta: { content: '' } }] }];
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.end(sse(next));
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  setModelConfig({
    provider: 'openai', model: 'test-model',
    baseUrl: `http://127.0.0.1:${server.address().port}/v1`, key: 'test-key',
  });
});

after(() => server?.close());

const text = (s) => ({ choices: [{ delta: { content: s } }] });
const call = (id, name, args) => ({
  choices: [{ delta: { tool_calls: [{ index: 0, id, function: { name, arguments: args } }] } }],
});

test('a plain answer is streamed and stored', async () => {
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  seen = [];
  script = [[text('The DC '), text('answered.')]];

  const out = await runTurn(db, s.id, 'what happened', { analyst: 'Lindqvist', mode: 'research' });
  assert.equal(out.text, 'The DC answered.');
  assert.equal(listMessages(db, s.id).at(-1).content, 'The DC answered.');
  assert.equal(getSession(db, s.id).state, 'open');
});

test('a tool call reaches the store and its result goes back to the model', async () => {
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  seen = [];
  script = [
    [call('c1', 'propose_finding', JSON.stringify({ description: 'cron job masquerading as log-sync' }))],
    [text('Filed it.')],
  ];

  const out = await runTurn(db, s.id, 'look at this', { analyst: 'Lindqvist', mode: 'evidence' });

  const recs = listRecords(db);
  assert.equal(recs.length, 1, 'the tool actually wrote to the store');
  assert.match(recs[0].description, /log-sync/);
  assert.equal(out.text, 'Filed it.');

  // Second request carries the assistant turn and the tool result, in order.
  assert.equal(seen.length, 2);
  const followUp = seen[1].messages;
  const toolMsg = followUp.find(m => m.role === 'tool');
  assert.ok(toolMsg, 'the tool result was sent back');
  assert.equal(toolMsg.tool_call_id, 'c1');
  assert.ok(followUp.some(m => m.role === 'assistant' && m.tool_calls?.length),
    'and the assistant turn that made the call went back with it');
});

/*
  A tool that refuses is information — "that snapshot never collected this
  host" is something the model should read and react to. Killing the turn would
  also throw away whatever it had already written.
*/
test('a tool that throws comes back as text rather than ending the turn', async () => {
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  seen = [];
  script = [
    [call('c1', 'propose_finding', JSON.stringify({}))],   // description is required
    [text('Understood, I need a description.')],
  ];

  const out = await runTurn(db, s.id, 'file something', { analyst: 'Lindqvist', mode: 'evidence' });
  assert.equal(out.text, 'Understood, I need a description.');
  const toolMsg = seen[1].messages.find(m => m.role === 'tool');
  assert.match(toolMsg.content, /description|error|required/i);
});

test('the system prompt and the mode tools are sent with every request', async () => {
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  seen = [];
  script = [[text('ok')]];

  await runTurn(db, s.id, 'hello', { analyst: 'Lindqvist', mode: 'evidence' });
  const req = seen[0];
  assert.equal(req.messages[0].role, 'system');
  assert.match(req.messages[0].content, /threat-hunt analyst working/);
  assert.ok(req.tools.length > 0);
  assert.ok(req.tools.every(t => t.type === 'function' && t.function.parameters));
  assert.equal(req.tools.some(t => t.function.name === 'stage_entities'), false,
    'evidence mode must not be handed the baseline writer');
});

/*
  The caller stores the user's message before starting a turn. Sending it again
  would show the model the same question twice.
*/
test('the current question is not duplicated in the history', async () => {
  const { appendMessage } = await import('../store/sessions.js');
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  appendMessage(db, s.id, 'user', 'the only question', 'evidence');
  seen = [];
  script = [[text('ok')]];

  await runTurn(db, s.id, 'the only question', { analyst: 'Lindqvist', mode: 'evidence' });
  const users = seen[0].messages.filter(m => m.role === 'user' && m.content === 'the only question');
  assert.equal(users.length, 1);
});

test('a refused request surfaces the status rather than a blank turn', async () => {
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  const bad = await import('node:http').then(({ createServer }) => new Promise(r => {
    const srv = createServer((_q, res) => { res.writeHead(401); res.end('no such key'); });
    srv.listen(0, '127.0.0.1', () => r(srv));
  }));
  setModelConfig({
    provider: 'openai', model: 'm',
    baseUrl: `http://127.0.0.1:${bad.address().port}/v1`, key: 'wrong',
  });
  try {
    await assert.rejects(
      () => runTurn(db, s.id, 'hi', { analyst: 'Lindqvist', mode: 'research' }),
      /401/);
    assert.equal(getSession(db, s.id).state, 'error', 'and the session says so');
  } finally {
    bad.close();
    setModelConfig({
      provider: 'openai', model: 'test-model',
      baseUrl: `http://127.0.0.1:${server.address().port}/v1`, key: 'test-key',
    });
  }
});

/*
  Provider parity.

  handleToolCall reads the characterization context at the top level of ctx.
  The MCP path gets it from environment variables and hands it over flat; this
  path assembled it nested under `char`, so stage_entities saw no repository,
  no host, and no staged flag — an import through an API provider committed
  straight into a baseline instead of being held for review, which is the one
  safety net the whole flow rests on.
*/
test('an import through an API provider is held for review, not committed', async () => {
  const { stagedPreview, repoView } = await import('../store/characterization.js');
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  seen = [];
  script = [
    [call('c1', 'stage_entities', JSON.stringify({
      repo: 'unclassified',            // what the model asked for
      entities: [{ UserName: 'root', UserId: '0' }],
    }))],
    [text('Staged.')],
  ];

  await runTurn(db, s.id, 'here are the accounts', {
    analyst: 'Lindqvist',
    mode: 'characterization',
    char: { repo: 'accounts', host: 'RL-01', staged: true, countedRows: 1 },
  });

  const held = stagedPreview(db);
  assert.equal(held.length, 1, 'the upload is waiting for review');
  assert.equal(held[0].repo, 'accounts', 'the tab pinned the repository, not the model');
  assert.equal(held[0].host, 'RL-01', 'and the host the analyst named');
  assert.equal(repoView(db, 'accounts').rows.length, 0, 'nothing reached the baseline yet');
  assert.equal(repoView(db, 'unclassified').rows.length, 0, 'and nothing went where the model asked');
});

// --- the Anthropic wire format ---------------------------------------------------

/*
  Everything above drives the OpenAI shape, which is the one an operator pointing
  at a local vLLM or an OpenAI-compatible gateway will use. anthropicTurn is a
  second, entirely separate wire format — content blocks arriving as
  content_block_start / _delta events, tool arguments streamed as
  input_json_delta fragments, usage split across message_start and message_delta
  — and until this it had no test at all. A format nobody exercises is a format
  that works until the day somebody selects it.

  The same fake-endpoint trick, speaking Anthropic instead. The turn loop is the
  real one; only the transport is stubbed.
*/
let aServer;
let aSeen = [];
let aScript = [];

const aSse = (events) => events
  .map(e => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join('');

before(async () => {
  const { createServer } = await import('node:http');
  aServer = createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      aSeen.push({ url: req.url, headers: req.headers, body: JSON.parse(body) });
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.end(aSse(aScript.shift() ?? [{ type: 'message_stop' }]));
    });
  });
  await new Promise(r => aServer.listen(0, '127.0.0.1', r));
});

after(() => aServer?.close());

/*
  Point the configuration back at the OpenAI fake.

  setModelConfig is global, so the Anthropic block above leaves every later test
  talking to the wrong endpoint — which is exactly how the two tests below first
  failed, with the OpenAI server recording no requests at all.
*/
const useOpenAi = () => setModelConfig({
  provider: 'openai', model: 'test-model',
  baseUrl: `http://127.0.0.1:${server.address().port}/v1`, key: 'test-key',
});

const useAnthropic = () => setModelConfig({
  provider: 'anthropic', model: 'claude-test',
  baseUrl: `http://127.0.0.1:${aServer.address().port}`, key: 'sk-ant-test',
});

/** The events a real stream emits around one text block. */
const aText = (...parts) => [
  { type: 'message_start', message: { usage: { input_tokens: 11 } } },
  { type: 'content_block_start', index: 0, content_block: { type: 'text' } },
  ...parts.map(t => ({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: t } })),
  { type: 'message_delta', usage: { output_tokens: 7 } },
];

/** A tool_use block whose arguments arrive in fragments, as they really do. */
const aCall = (id, name, ...jsonParts) => [
  { type: 'message_start', message: { usage: { input_tokens: 12 } } },
  { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id, name } },
  ...jsonParts.map(p => ({
    type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: p },
  })),
  { type: 'message_delta', usage: { output_tokens: 3 } },
];

test('an Anthropic answer is assembled from its content blocks and stored', async () => {
  useAnthropic();
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  aSeen = [];
  aScript = [aText('The jump host ', 'answered.')];

  const out = await runTurn(db, s.id, 'what happened', { analyst: 'Lindqvist', mode: 'research' });
  assert.equal(out.text, 'The jump host answered.');
  assert.equal(listMessages(db, s.id).at(-1).content, 'The jump host answered.');

  // The request has to look like Anthropic's, not OpenAI's: its own path, its
  // own auth header, the system prompt as a field rather than a first message.
  const req = aSeen[0];
  assert.match(req.url, /\/v1\/messages$/);
  assert.equal(req.headers['x-api-key'], 'sk-ant-test');
  assert.equal(req.headers['anthropic-version'], '2023-06-01');
  assert.equal(typeof req.body.system, 'string');
  assert.ok(req.body.system.length > 0, 'the system prompt was not sent');
  assert.equal(req.body.messages[0].role, 'user');
  assert.ok(req.body.tools.every(t => t.input_schema),
    'tools must carry input_schema on this format, not parameters');
});

/*
  The fragment reassembly is the part most likely to break, because a real
  stream splits the JSON at arbitrary points and a naive parse of any single
  fragment throws.
*/
test('Anthropic tool arguments split across fragments still reach the tool', async () => {
  useAnthropic();
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  const before = listRecords(db).length;
  aSeen = [];
  aScript = [
    aCall('t1', 'propose_finding', '{"description":"cron job mas', 'querading as log-sync"}'),
    aText('Filed it.'),
  ];

  const out = await runTurn(db, s.id, 'look at this', { analyst: 'Lindqvist', mode: 'evidence' });
  assert.equal(out.text, 'Filed it.');

  const added = listRecords(db).slice(before.length ?? 0);
  assert.equal(listRecords(db).length, before + 1, 'the tool call did not reach the store');
  assert.ok(listRecords(db).some(r => /log-sync/.test(r.description ?? '')),
    'the description was not reassembled from its fragments');

  // And the result goes back in the shape this API expects.
  const second = aSeen[1].body.messages;
  const result = second.at(-1);
  assert.equal(result.role, 'user');
  assert.equal(result.content[0].type, 'tool_result');
  assert.equal(result.content[0].tool_use_id, 't1');
  void added;
});

/*
  Points at a port with nothing on it rather than closing the shared stub.

  Closing it, sleeping 50ms and rebinding a REPLACEMENT server on the same port
  left every later Anthropic test talking to a stand-in that answers 200 with
  an empty body: appending a copy of this file's own first Anthropic test after
  this one failed with '' == 'The jump host answered.'. The file already
  documents setModelConfig as global and works around it; this was the same
  hazard in the fixture rather than the configuration — and a same-port rebind
  races EADDRINUSE on a loaded machine besides.
*/
test('an Anthropic refusal surfaces its status rather than a blank turn', async () => {
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });

  const { createServer } = await import('node:http');
  const dead = createServer(() => {});
  await new Promise(r => dead.listen(0, '127.0.0.1', r));
  const port = dead.address().port;
  await new Promise(r => dead.close(r));       // a port with nothing behind it

  setModelConfig({
    provider: 'anthropic', model: 'claude-test',
    baseUrl: `http://127.0.0.1:${port}`, key: 'sk-ant-test',
  });
  await assert.rejects(
    () => runTurn(db, s.id, 'hello', { analyst: 'Lindqvist', mode: 'research' }),
    (e) => e instanceof Error);
  useAnthropic();                              // the shared stub, untouched
});

/*
  The guard on the fixture above. It is a copy of this file's first Anthropic
  test, placed after it: when the refusal test closed and replaced the shared
  server, this is the assertion that failed.
*/
test('an Anthropic turn still works after the refusal test has run', async () => {
  useAnthropic();
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  aSeen = [];
  aScript = [aText('The jump host answered.')];

  await runTurn(db, s.id, 'hello', { analyst: 'Lindqvist', mode: 'research' });
  const last = listMessages(db, s.id).at(-1);
  assert.equal(last.role, 'assistant');
  assert.equal(last.content, 'The jump host answered.',
    'a later Anthropic test was talking to a stand-in left behind by an earlier one');
});


/*
  A model that will not stop calling tools.

  The loop runs at most HUNT_MAX_TOOL_STEPS times and had no branch for running
  out. It fell out of the bottom into the ordinary completion path: no text, so
  the `if (assistantText.trim())` guard appended no message, and the state went
  to 'open' exactly as a clean turn would. The analyst's composer unlocked with
  no reply and no error — indistinguishable from the request having vanished —
  while whatever the model filed along the way was already committed.
*/
test('a turn that exhausts its tool budget says so instead of going quiet', async () => {
  useOpenAi();
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  seen = [];
  // Always a tool call, never a final answer.
  script = Array.from({ length: 6 }, () => [call('c1', 'search_records', '{"q":"x"}')]);

  const out = await runTurn(db, s.id, 'go', { analyst: 'Lindqvist', mode: 'evidence' });

  assert.equal(seen.length, 3, 'the step cap must still hold');
  const last = listMessages(db, s.id).at(-1);
  assert.equal(last.role, 'assistant', 'the analyst was left with nothing to read');
  assert.match(last.content, /tool/i, 'the message must say what happened');
  assert.match(out.text, /tool/i);
  assert.equal(getSession(db, s.id).state, 'open', 'the composer must still unlock');
});

/*
  And the partial answer is not thrown away.

  Text streams to the browser as it arrives, so an analyst watching a turn has
  already read whatever the model wrote before it stalled. Aborting threw
  without appending any of it, so the transcript lost what the screen had shown
  and a reload made it vanish.
*/
test('a turn stopped part-way keeps the text the analyst already saw', async () => {
  useOpenAi();
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  seen = [];
  script = [[text('The DC answered at 02:14 and then '), call('c1', 'search_records', '{"q":"x"}')]];
  // The first request answers and calls a tool; the follow-up never comes.
  stallFrom = 2;

  await assert.rejects(
    () => runTurn(db, s.id, 'go', { analyst: 'Lindqvist', mode: 'evidence' }),
    /stopped|no reply/i);
  stallFrom = Infinity;

  const last = listMessages(db, s.id).at(-1);
  assert.equal(last.role, 'assistant', 'the partial answer was discarded');
  assert.match(last.content, /The DC answered at 02:14/, 'the streamed text was lost');
});

/*
  A turn on this backend is a loop over fetch, not a subprocess — and shutdown
  could only see subprocesses. killAllTurns reported "0 turns still running"
  while the loop went on calling handleToolCall, so the operator was told
  nothing was in flight and the shutdown snapshot was taken around writes that
  were still arriving.
*/
test('an API turn is in flight for shutdown to find, and stops when told', async () => {
  const { killAllTurns, liveTurnCount } = await import('../claude/runner.js');
  useOpenAi();
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });
  seen = [];
  script = [[text('working on it'), call('c1', 'search_records', '{"q":"x"}')]];
  stallFrom = 2;                       // the follow-up never answers

  const turn = runTurn(db, s.id, 'go', { analyst: 'Lindqvist', mode: 'evidence' });
  const rejected = assert.rejects(() => turn, /stopped|no reply/i);
  await new Promise(r => setTimeout(r, 250));

  assert.equal(liveTurnCount(), 1, 'a turn against an API backend was invisible to shutdown');
  assert.equal(killAllTurns(), 1, 'and shutdown must be able to stop it');
  await rejected;
  stallFrom = Infinity;
  assert.equal(liveTurnCount(), 0, 'a finished turn must stop being counted');
});
