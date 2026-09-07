/**
 * Find out whether a model can actually drive the six hunt tools, before an
 * engagement depends on it.
 *
 *   node tools/probe-model.mjs --base-url http://10.0.0.5:8000/v1 --model qwen2.5-32b-instruct --key sk-local
 *   node tools/probe-model.mjs --provider anthropic --model claude-opus-4-6 --key sk-ant-...
 *   node tools/probe-model.mjs                      # whatever data/model.json already says
 *
 * The question is not whether a model is clever. It is whether, shown these
 * schemas and a piece of evidence, it emits a well-formed call to the right
 * tool — reliably. A large model does this without thinking about it; a small
 * local one often gets it right once and then returns prose, or invents a
 * field, or calls search_records when it meant propose_finding. That failure
 * mode is invisible until an analyst is mid-hunt and the record they were
 * promised never arrives.
 *
 * So every scenario runs several times and the score is a fraction. One pass
 * proves nothing: what matters is whether it passes every time.
 *
 * Reads nothing and writes nothing. No store, no session, no saved credential:
 * the key is given on the command line, used for the requests and never
 * persisted, so trialling an endpoint cannot disturb a working setup — and the
 * one function that can read a stored credential stays confined to the two
 * provider files, where test/invariants.test.js keeps it.
 *
 * The schemas and the per-mode tool lists come from the application itself, not
 * from a copy here, so a probe that passes is a statement about the tools the
 * model will really be offered.
 */
import { TOOLS } from '../claude/mcp-server.js';
import { toolsFor } from '../claude/api-provider.js';
import { modelConfig } from '../store/model-config.js';

// --- what a good answer looks like ------------------------------------------------

/*
  One scenario per tool, in the mode that actually offers it, phrased the way an
  analyst would phrase it rather than as an instruction to call a function. A
  prompt that says "call propose_finding" measures nothing: the model that needs
  telling is the one that will fail in use.

  `want` is the tool that should be called. `must` are argument fields that have
  to be present and non-empty for the call to be worth anything — a
  propose_finding with an empty description is a failure wearing a success.
*/
export const SCENARIOS = [
  {
    id: 'propose_finding', mode: 'evidence', want: 'propose_finding', must: ['description'],
    prompt:
      'On WKS-07 at 2026-03-11 02:14Z, Sysmon event 1 shows powershell.exe launched by '
      + 'winword.exe, command line "powershell -nop -w hidden -enc SQBFAFgA", user r.chen. '
      + 'That is Word spawning an encoded PowerShell one-liner in the middle of the night. '
      + 'Put it in the case file.',
  },
  {
    id: 'search_records', mode: 'evidence', want: 'search_records', must: [],
    prompt:
      'Before I write anything up — has anything already been filed against WKS-07? '
      + 'Check what is on file for that host.',
  },
  {
    id: 'query_terrain', mode: 'research', want: 'query_terrain', must: [],
    prompt: 'What do we know about the hosts on this engagement? Look up the terrain.',
  },
  {
    id: 'query_baseline', mode: 'characterization', want: 'query_baseline', must: [],
    prompt:
      'Is a scheduled task called "LogSync" normal on this estate, and on how many hosts '
      + 'does it appear? Check the baseline.',
  },
  {
    id: 'stage_entities', mode: 'characterization', want: 'stage_entities', must: ['repo', 'entities'],
    prompt:
      'Here is the output of Get-LocalUser from RL-03:\n'
      + 'Name      Enabled  LastLogon\n'
      + 'svc_sql   True     2026-03-01\n'
      + 'jdoe      False    2025-12-30\n'
      + 'Stage those into the accounts repository.',
  },
  /*
    Restraint. A model that files a record because somebody said hello is worse
    than one that never files at all: the first fills the case file with noise
    an analyst has to adjudicate, and it does it in evidence mode where the tool
    is armed. Scored the same as the others, because it is the same property.
  */
  {
    id: 'restraint', mode: 'evidence', want: null, must: [],
    prompt: 'Morning. Before we start — remind me what the three record verdicts are called?',
  },
];

// --- the wire -----------------------------------------------------------------------

const schemaFor = (name) => TOOLS.find(t => t.name === name)?.inputSchema ?? { properties: {} };

async function askOpenAi(cfg, tools, prompt, signal) {
  const res = await fetch(`${cfg.baseUrl.replace(/\/$/, '')}/chat/completions`, {
    method: 'POST',
    signal,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.key}` },
    body: JSON.stringify({
      model: cfg.model,
      messages: [{ role: 'user', content: prompt }],
      tools: tools.map(t => ({
        type: 'function',
        function: { name: t.name, description: t.description, parameters: t.inputSchema },
      })),
    }),
  });
  if (!res.ok) throw new Error(`${res.status} ${(await res.text()).slice(0, 200)}`);
  const body = await res.json();
  const msg = body.choices?.[0]?.message ?? {};
  return {
    text: msg.content ?? '',
    calls: (msg.tool_calls ?? []).map(c => ({
      name: c.function?.name, raw: c.function?.arguments ?? '',
    })),
  };
}

async function askAnthropic(cfg, tools, prompt, signal) {
  const res = await fetch(`${(cfg.baseUrl || 'https://api.anthropic.com').replace(/\/$/, '')}/v1/messages`, {
    method: 'POST',
    signal,
    headers: {
      'content-type': 'application/json',
      'x-api-key': cfg.key,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: cfg.model, max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
      tools: tools.map(t => ({
        name: t.name, description: t.description, input_schema: t.inputSchema,
      })),
    }),
  });
  if (!res.ok) throw new Error(`${res.status} ${(await res.text()).slice(0, 200)}`);
  const body = await res.json();
  const blocks = body.content ?? [];
  return {
    text: blocks.filter(b => b.type === 'text').map(b => b.text).join(''),
    // Anthropic hands back a parsed object; stringify so both paths are judged
    // by the same JSON check rather than one getting a free pass.
    calls: blocks.filter(b => b.type === 'tool_use')
      .map(b => ({ name: b.name, raw: JSON.stringify(b.input ?? {}) })),
  };
}

// --- judging one answer -------------------------------------------------------------

/**
 * @returns {{verdict: string, note: string}} verdict is 'ok' or a failure kind.
 */
export function judge(scenario, offered, out) {
  const names = new Set(offered.map(t => t.name));

  if (scenario.want === null) {
    return out.calls.length
      ? { verdict: 'spurious-call', note: out.calls.map(c => c.name).join(', ') }
      : { verdict: 'ok', note: '' };
  }

  if (!out.calls.length) {
    return { verdict: 'no-call', note: (out.text || '').slice(0, 60).replace(/\s+/g, ' ') };
  }

  const call = out.calls[0];
  if (!names.has(call.name)) {
    // Either a tool from another mode, or one that does not exist at all. Worth
    // separating: the first is a scoping failure, the second is invention.
    const known = TOOLS.some(t => t.name === call.name);
    return { verdict: known ? 'wrong-tool' : 'unknown-tool', note: String(call.name) };
  }
  if (call.name !== scenario.want) return { verdict: 'wrong-tool', note: call.name };

  let args;
  try { args = JSON.parse(call.raw); } catch {
    return { verdict: 'bad-json', note: String(call.raw).slice(0, 60) };
  }
  if (args === null || typeof args !== 'object' || Array.isArray(args)) {
    return { verdict: 'bad-json', note: 'arguments were not an object' };
  }

  const empty = (v) => v == null || v === ''
    || (Array.isArray(v) && v.length === 0);
  const missing = scenario.must.filter(f => empty(args[f]));
  if (missing.length) return { verdict: 'missing-required', note: missing.join(', ') };

  const allowed = new Set(Object.keys(schemaFor(call.name).properties ?? {}));
  const invented = Object.keys(args).filter(k => !allowed.has(k));
  // Not a failure. The application ignores unknown keys, and a model adding one
  // is noise rather than breakage — but it is worth seeing, because a model
  // that invents fields here tends to invent values elsewhere.
  return { verdict: 'ok', note: invented.length ? `extra: ${invented.join(', ')}` : '' };
}

// --- run ------------------------------------------------------------------------------

/**
 * Probe an endpoint. Exported so a test can drive it against a scripted server
 * rather than a real model.
 *
 * @returns {Promise<{rows: object[], passed: number, total: number, reliable: boolean}>}
 */
export async function probe(cfg, { runs = 3, timeoutMs = 120_000, log = () => {} } = {}) {
  const ask = cfg.provider === 'anthropic' ? askAnthropic : askOpenAi;

  log(`\n  ${cfg.provider}${cfg.baseUrl ? ` ${cfg.baseUrl}` : ''}`);
  log(`  ${cfg.model} · ${runs} run${runs === 1 ? '' : 's'} per scenario\n`);

  const rows = [];
  let total = 0;
  let passed = 0;

  for (const sc of SCENARIOS) {
    const offered = toolsFor(sc.mode);
    const verdicts = [];
    for (let i = 0; i < runs; i++) {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      try {
        verdicts.push(judge(sc, offered, await ask(cfg, offered, sc.prompt, ac.signal)));
      } catch (err) {
        verdicts.push({
          verdict: ac.signal.aborted ? 'timeout' : 'error',
          note: String(err?.message ?? err).slice(0, 70),
        });
      } finally { clearTimeout(timer); }
    }
    const ok = verdicts.filter(v => v.verdict === 'ok').length;
    total += runs;
    passed += ok;
    rows.push({ id: sc.id, ok, runs, verdicts });

    const mark = ok === runs ? '\u2713' : ok === 0 ? '\u2717' : '~';
    const fails = [...new Set(verdicts.filter(v => v.verdict !== 'ok')
      .map(v => `${v.verdict}${v.note ? ` (${v.note})` : ''}`))];
    const notes = [...new Set(verdicts.filter(v => v.verdict === 'ok' && v.note).map(v => v.note))];
    log(`  ${mark} ${sc.id.padEnd(17)} ${String(ok).padStart(2)}/${runs}  ${
      [...fails, ...notes].join(' \u00b7 ')}`);
  }

  const weak = rows.filter(r => r.ok < r.runs);
  log(`\n  ${passed}/${total} (${total ? Math.round((passed / total) * 100) : 0}%)\n`);

  /*
    A judgement rather than a number, because a percentage invites the wrong
    reading. Anything short of every scenario passing every run means an analyst
    meets the failure during a hunt — and the useful question then is which
    scenario, because a model that cannot stage entities is still fine for
    research.
  */
  if (!weak.length) {
    log('  Every scenario passed every run. This endpoint can drive the hunt tools.\n');
  } else {
    log(`  Not reliable on: ${weak.map(r => r.id).join(', ')}`);
    log('  A tool that fails one run in three fails during a hunt, and the analyst sees');
    log('  a plausible paragraph where a record should be. Either use a stronger model');
    log('  for the modes needing those tools, or expect to file them by hand.\n');
  }

  return { rows, passed, total, reliable: weak.length === 0 };
}

const USAGE = `
  node tools/probe-model.mjs [options]

    --base-url URL   OpenAI-compatible endpoint, e.g. http://10.0.0.5:8000/v1
    --model NAME     model to ask for (required)
    --key KEY        credential (required); never read from or written to disk
    --provider P     openai (default) or anthropic
    --runs N         attempts per scenario (default 3) — reliability is the point
    --timeout MS     per request (default 120000)

  With no options it probes whatever data/model.json already holds.
  Exits non-zero unless every scenario passes every run.
`;

if (process.argv[1]?.endsWith('probe-model.mjs')) {
  const arg = (name, fallback = null) => {
    const i = process.argv.indexOf(`--${name}`);
    return i > -1 ? process.argv[i + 1] : fallback;
  };

  if (process.argv.includes('--help')) { console.log(USAGE); process.exit(0); }

  const saved = modelConfig();
  const cfg = {
    // The saved provider may be 'cli', which has nothing to probe over HTTP;
    // default to openai so `--base-url` alone is enough to trial an endpoint.
    provider: arg('provider', saved.provider === 'cli' ? 'openai' : saved.provider),
    model: arg('model', saved.model),
    baseUrl: arg('base-url', saved.baseUrl),
    /*
      Always given on the command line, never read from data/model.json.
      An invariant holds the credential-reading function to the two provider
      files, and a probe is a convenience — not a reason to widen where a key
      can be reached from. Probing is usually a new endpoint anyway, whose key
      you have in hand. (Named without its call parentheses on purpose: the
      invariant greps for the call and a comment would trip it, which is the
      right trade for a blunt rule about a credential.)
    */
    key: arg('key'),
  };

  const fail = (msg) => { console.error(`  ${msg}\n${USAGE}`); process.exit(2); };
  if (cfg.provider === 'cli') fail('the CLI authenticates itself and is not probed here');
  if (!cfg.model) fail('--model is required');
  if (cfg.provider === 'openai' && !cfg.baseUrl) fail('--base-url is required for an OpenAI-compatible endpoint');
  if (!cfg.key) fail('--key is required; the probe never reads the saved credential');

  const { reliable } = await probe(cfg, {
    runs: Number(arg('runs', 3)),
    timeoutMs: Number(arg('timeout', 120_000)),
    log: (l) => console.log(l),
  });
  process.exit(reliable ? 0 : 1);
}
