import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { probe, judge, SCENARIOS } from '../tools/probe-model.mjs';
import { toolsFor } from '../claude/api-provider.js';

/*
  The probe is the thing an operator trusts when deciding whether a local model
  can run an engagement, so a probe that reports success wrongly is worse than
  no probe. What is checked here is the judging: that a well-formed call passes,
  and that each way a smaller model actually fails is caught and named.

  Those failure kinds are not hypothetical. A model that returns a paragraph
  instead of calling anything, one that reaches for the tool it saw in another
  mode, one whose arguments are almost-JSON, one that calls propose_finding with
  an empty description — each is a real thing small models do, and each looks
  like a working hunt right up until somebody reads the case file.
*/

const offered = (mode) => toolsFor(mode);
const scenario = (id) => SCENARIOS.find(s => s.id === id);
const call = (name, args) => ({ text: '', calls: [{ name, raw: JSON.stringify(args) }] });

// --- judging ------------------------------------------------------------------------

test('a well-formed call to the right tool passes', () => {
  const v = judge(scenario('propose_finding'), offered('evidence'),
    call('propose_finding', { description: 'Word spawned encoded PowerShell', hostname: 'WKS-07' }));
  assert.equal(v.verdict, 'ok');
});

test('a paragraph instead of a call is a failure, and the text is quoted back', () => {
  const v = judge(scenario('propose_finding'), offered('evidence'),
    { text: 'That certainly looks suspicious! You should investigate it.', calls: [] });
  assert.equal(v.verdict, 'no-call');
  assert.match(v.note, /looks suspicious/);
});

test('arguments that are not JSON are caught rather than parsed leniently', () => {
  const v = judge(scenario('propose_finding'), offered('evidence'),
    { text: '', calls: [{ name: 'propose_finding', raw: '{"description": "unterminated' }] });
  assert.equal(v.verdict, 'bad-json');
});

/*
  The one most likely to be mistaken for success: the call is well-formed, the
  tool is right, and the field that carries the entire meaning is blank.
*/
test('a required field present but empty does not count as a call', () => {
  const v = judge(scenario('propose_finding'), offered('evidence'),
    call('propose_finding', { description: '', hostname: 'WKS-07' }));
  assert.equal(v.verdict, 'missing-required');
  assert.match(v.note, /description/);
});

test('an empty entities array is missing, not merely falsy', () => {
  const v = judge(scenario('stage_entities'), offered('characterization'),
    call('stage_entities', { repo: 'accounts', entities: [] }));
  assert.equal(v.verdict, 'missing-required');
  assert.match(v.note, /entities/);
});

test('reaching for a real tool the mode did not offer is a wrong-tool failure', () => {
  // query_terrain is a real tool; research mode is where it belongs.
  const v = judge(scenario('propose_finding'), offered('evidence'),
    call('query_terrain', { hostname: 'WKS-07' }));
  assert.equal(v.verdict, 'wrong-tool');
});

test('a tool that does not exist is called invention, not a wrong choice', () => {
  const v = judge(scenario('propose_finding'), offered('evidence'),
    call('create_incident_ticket', { title: 'x' }));
  assert.equal(v.verdict, 'unknown-tool');
  assert.match(v.note, /create_incident_ticket/);
});

/*
  Restraint is scored like the rest. A model that files a record because
  somebody said good morning fills the case file with work an analyst has to
  adjudicate, and it does it in the mode where the tool is armed.
*/
test('filing a record in answer to small talk is a failure', () => {
  const v = judge(scenario('restraint'), offered('evidence'),
    call('propose_finding', { description: 'The analyst said good morning' }));
  assert.equal(v.verdict, 'spurious-call');
});

test('answering small talk with prose is what restraint looks like', () => {
  const v = judge(scenario('restraint'), offered('evidence'),
    { text: 'New, Investigating, Corroborated or Ruled Out.', calls: [] });
  assert.equal(v.verdict, 'ok');
});

test('a field outside the schema is reported but does not fail the run', () => {
  const v = judge(scenario('propose_finding'), offered('evidence'),
    call('propose_finding', { description: 'real', severity: 'critical' }));
  assert.equal(v.verdict, 'ok');
  assert.match(v.note, /severity/);
});

// --- end to end against a scripted endpoint -------------------------------------------

/*
  Two fake models. The first does what a capable one does; the second is the
  shape of the problem — it answers the easy scenarios and returns prose for the
  one that matters. The probe has to tell them apart, and has to say which
  scenario failed rather than only that something did.
*/
let server;
let behaviour = 'good';

const reply = (toolName, args) => ({
  choices: [{
    message: toolName
      ? { content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: toolName, arguments: JSON.stringify(args) } }] }
      : { content: 'Certainly — that looks worth a closer look.' },
  }],
});

before(async () => {
  const { createServer } = await import('node:http');
  server = createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      const sent = JSON.parse(body);
      const asked = sent.messages.at(-1).content;
      const names = new Set((sent.tools ?? []).map(t => t.function.name));
      let out;
      if (/Put it in the case file/.test(asked)) {
        out = behaviour === 'good'
          ? reply('propose_finding', { description: 'Word spawned encoded PowerShell on WKS-07' })
          : reply(null);                       // the flaky one just talks
      } else if (/already been filed/.test(asked)) {
        out = reply('search_records', { hostname: 'WKS-07' });
      } else if (/terrain/.test(asked)) {
        out = reply('query_terrain', {});
      } else if (/baseline/.test(asked)) {
        out = reply('query_baseline', { repo: 'scheduled-tasks' });
      } else if (/Stage those/.test(asked)) {
        out = reply('stage_entities', { repo: 'accounts', entities: [{ username: 'svc_sql' }] });
      } else {
        out = reply(null);                      // small talk: no call is correct
      }
      // Every scripted call must be one the mode actually offered, or the
      // fixture is testing something the application would never see.
      const called = out.choices[0].message.tool_calls?.[0]?.function?.name;
      if (called) assert.ok(names.has(called), `fixture called ${called}, not offered in this mode`);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out));
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
});

after(() => server?.close());

const cfg = () => ({
  provider: 'openai', model: 'fake',
  baseUrl: `http://127.0.0.1:${server.address().port}/v1`, key: 'k',
});

test('a compliant endpoint is reported reliable', async () => {
  behaviour = 'good';
  const out = await probe(cfg(), { runs: 2 });
  assert.equal(out.reliable, true, JSON.stringify(out.rows.filter(r => r.ok < r.runs)));
  assert.equal(out.passed, out.total);
  assert.equal(out.rows.length, SCENARIOS.length);
});

/*
  The failure this whole tool exists to surface: everything works except the one
  call that puts evidence in the case file.
*/
test('an endpoint that will not file a record is reported unreliable, and named', async () => {
  behaviour = 'flaky';
  const out = await probe(cfg(), { runs: 2 });
  assert.equal(out.reliable, false);
  const weak = out.rows.filter(r => r.ok < r.runs).map(r => r.id);
  assert.deepEqual(weak, ['propose_finding'],
    'only the scenario that actually failed should be reported weak');
  assert.ok(out.rows.find(r => r.id === 'propose_finding').verdicts.every(v => v.verdict === 'no-call'));
});

test('an unreachable endpoint fails loudly rather than scoring zero silently', async () => {
  const out = await probe(
    { provider: 'openai', model: 'fake', baseUrl: 'http://127.0.0.1:1/v1', key: 'k' },
    { runs: 1, timeoutMs: 3000 });
  assert.equal(out.reliable, false);
  assert.ok(out.rows.every(r => r.verdicts.every(v => ['error', 'timeout'].includes(v.verdict))),
    'a dead endpoint must read as an error, not as a model that declined to call');
});
