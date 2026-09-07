import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import {
  parseStream, TOOL_DENYLIST, HUNT_TOOLS, RESEARCH_TOOLS, CHARACTERIZATION_TOOLS,
  toolsForMode, deniedHuntTools,
} from '../claude/runner.js';

// Lines below are real output from `claude -p --output-format stream-json`,
// trimmed. Parsing is tested against the actual shape, with no subprocess.

test('the init line yields the session id', () => {
  const [d] = parseStream(JSON.stringify({
    type: 'system', subtype: 'init', session_id: 'a4261e10-c5c3-4c40-89de-0cce13799a9c', tools: [],
  }));
  assert.equal(d.kind, 'init');
  assert.equal(d.claudeSessionId, 'a4261e10-c5c3-4c40-89de-0cce13799a9c');
});

test('SessionStart hook chatter is discarded', () => {
  for (const subtype of ['hook_started', 'hook_progress', 'hook_response']) {
    assert.deepEqual(parseStream(JSON.stringify({ type: 'system', subtype, stderr: 'ParserError' })), []);
  }
});

test('assistant text blocks become text deltas', () => {
  const deltas = parseStream(JSON.stringify({
    type: 'assistant',
    message: { content: [{ type: 'text', text: 'PROBE_OK' }] },
  }));
  assert.deepEqual(deltas, [{ kind: 'text', text: 'PROBE_OK' }]);
});

test('a single line carrying text and a tool call yields both, in order', () => {
  const deltas = parseStream(JSON.stringify({
    type: 'assistant',
    message: {
      content: [
        { type: 'text', text: 'Filing that now.' },
        { type: 'tool_use', name: 'mcp__hunt__propose_finding', input: {} },
      ],
    },
  }));
  assert.deepEqual(deltas.map(d => d.kind), ['text', 'tool_use']);
  assert.equal(deltas[1].name, 'mcp__hunt__propose_finding');
});

test('rate limit events surface rather than being swallowed', () => {
  const [d] = parseStream(JSON.stringify({
    type: 'rate_limit_event',
    rate_limit_info: { status: 'allowed_warning', utilization: 0.85, rateLimitType: 'seven_day' },
  }));
  assert.equal(d.kind, 'rate_limit');
  assert.equal(d.info.utilization, 0.85);
});

test('the result line reports completion and error state', () => {
  const [ok] = parseStream(JSON.stringify({ type: 'result', subtype: 'success', result: 'done', is_error: false }));
  assert.equal(ok.kind, 'result');
  assert.equal(ok.isError, false);
  const [bad] = parseStream(JSON.stringify({ type: 'result', subtype: 'error', result: 'boom', is_error: true }));
  assert.equal(bad.isError, true);
});

test('malformed and irrelevant lines yield nothing and never throw', () => {
  for (const line of ['', '{', 'null', '[]', '{"type":"user"}', 'not json at all']) {
    assert.doesNotThrow(() => parseStream(line));
    assert.deepEqual(parseStream(line), []);
  }
});

// --- the security contract -------------------------------------------------

test('the denylist covers every dangerous built-in, including the Windows shell', () => {
  // PowerShell, not Bash, is the shell tool on Windows. Denying only Bash
  // would leave shell execution open on this host.
  for (const t of ['Bash', 'PowerShell', 'Write', 'Edit', 'Read', 'Glob', 'Grep',
    'WebFetch', 'WebSearch', 'Task', 'ToolSearch', 'Workflow', 'Skill',
    'SlashCommand', 'CronCreate', 'RemoteTrigger', 'SendMessage']) {
    assert.ok(TOOL_DENYLIST.includes(t), `denylist is missing ${t}`);
  }
});

test('only hunt tools are ever allowed', () => {
  assert.ok(HUNT_TOOLS.every(t => t.startsWith('mcp__hunt__')));
  assert.ok(CHARACTERIZATION_TOOLS.every(t => t.startsWith('mcp__hunt__')));
  assert.ok(RESEARCH_TOOLS.every(t => t.startsWith('mcp__hunt__')));
});

test('no hunt tool is also on the denylist', () => {
  for (const t of HUNT_TOOLS) assert.ok(!TOOL_DENYLIST.includes(t));
});

// --- evidence vs research --------------------------------------------------

test('research mode is given only the read-only tools', () => {
  assert.deepEqual(toolsForMode('research').sort(),
    ['mcp__hunt__query_terrain', 'mcp__hunt__search_records']);
});

test('evidence mode can read the baseline but not write to it', () => {
  const t = toolsForMode('evidence');
  assert.ok(t.includes('mcp__hunt__propose_finding'));
  // "Is this normal here" is what turns a suspicion into a finding or kills
  // it; without this the characterization repositories are write-only.
  assert.ok(t.includes('mcp__hunt__query_baseline'));
  // But a pasted log must not be able to quietly redefine what normal is.
  assert.ok(!t.includes('mcp__hunt__stage_entities'));
  assert.ok(deniedHuntTools('evidence').includes('mcp__hunt__stage_entities'));
  assert.deepEqual(toolsForMode(undefined), t, 'evidence is the default');
});

test('characterization mode observes and cannot accuse', () => {
  const t = toolsForMode('characterization');
  assert.ok(t.includes('mcp__hunt__stage_entities'));
  assert.ok(t.includes('mcp__hunt__query_baseline'), 'it must be able to say what changed');
  // Four hundred processes are a baseline, not four hundred findings. The
  // tool list is the guarantee; the prompt is only the request.
  assert.ok(!t.includes('mcp__hunt__propose_finding'));
  assert.ok(!t.includes('mcp__hunt__propose_edge'));
  for (const denied of ['mcp__hunt__propose_finding', 'mcp__hunt__propose_edge']) {
    assert.ok(deniedHuntTools('characterization').includes(denied),
      `${denied} must be denied outright, not merely left out of the allowlist`);
  }
});

test('every mode denies outright what it does not allow', () => {
  // --allowedTools is additive, so leaving a tool out grants nothing but
  // removes nothing either. Anything a mode must not reach has to be denied.
  for (const mode of ['evidence', 'research', 'characterization']) {
    const allowed = new Set(toolsForMode(mode));
    for (const denied of deniedHuntTools(mode)) {
      assert.ok(!allowed.has(denied), `${mode}: ${denied} is both allowed and denied`);
    }
  }
});

test('research mode cannot write to the case file', () => {
  // A prompt asking the model not to file something is a request. Denying the
  // tool is the guarantee, and --allowedTools alone would not remove it.
  const src = readFileSync(new URL('../claude/runner.js', import.meta.url), 'utf8');
  assert.match(src, /mode === 'research' \? \[\s*'mcp__hunt__propose_finding',\s*'mcp__hunt__propose_edge'\s*\]/,
    'research turns must deny the writing tools outright');
});
