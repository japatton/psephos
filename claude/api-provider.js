/**
 * Running a turn against an HTTP model API, Anthropic or OpenAI-compatible.
 *
 * The six hunt tools are not reimplemented here. `claude/mcp-server.js`
 * already exports `TOOLS` (name, description, JSON Schema) and
 * `handleToolCall`, and the MCP server is a thin JSON-RPC wrapper over both,
 * so this module borrows them and supplies only the turn loop: send the prompt
 * with the schemas attached, stream text, execute whatever the model calls,
 * feed the results back, repeat until it stops.
 *
 * Where the CLI path needs an elaborate denylist because the CLI arrives with
 * a hundred capabilities that have to be taken away, this path offers exactly
 * the tools the mode allows and nothing else. There is no filesystem, no
 * shell, and no ambient MCP server to inherit.
 */
import { StringDecoder } from 'node:string_decoder';
import { TOOLS, handleToolCall } from './mcp-server.js';
import { buildSystemPrompt } from './prompt.js';
import { toolsForMode, deniedHuntTools, trackTurnAbort } from './runner.js';
import { modelConfig, modelSecret } from '../store/model-config.js';
import { getSession, setState, appendMessage, listMessages } from '../store/sessions.js';
import { broadcast } from '../server/sse.js';
import { summary as charSummary } from '../store/characterization.js';
import { listRecords, derivedConnections } from '../store/records.js';
import { listHosts } from '../store/hosts.js';
import { listEdges } from '../store/edges.js';

/** A turn that runs longer than this is stuck, not thinking. */
const TURN_TIMEOUT_MS = Number(process.env.HUNT_TURN_TIMEOUT_MS || 300_000);
/** Tool calls per turn. A model looping on a failing tool must not run forever. */
const MAX_STEPS = Number(process.env.HUNT_MAX_TOOL_STEPS || 12);
/** How much conversation to resend. There is no server-side session to resume. */
const HISTORY_TURNS = Number(process.env.HUNT_HISTORY_TURNS || 20);

/**
 * The mode's tool list, as bare hunt-tool names.
 *
 * `toolsForMode` returns MCP-qualified names (`mcp__hunt__propose_finding`)
 * because that is what the CLI's allowlist takes. An HTTP API wants the bare
 * name, and the denial list has to be applied by hand — there is no additive
 * allowlist to work around here, so a denied tool is simply not offered.
 */
export function toolsFor(mode) {
  const bare = (n) => n.replace(/^mcp__hunt__/, '');
  const allowed = new Set(toolsForMode(mode).filter(n => n.startsWith('mcp__hunt__')).map(bare));
  const denied = new Set(deniedHuntTools(mode).map(bare));
  return TOOLS.filter(t => allowed.has(t.name) && !denied.has(t.name));
}

// --- wire formats -------------------------------------------------------------

const toAnthropicTools = (tools) => tools.map(t => ({
  name: t.name, description: t.description, input_schema: t.inputSchema,
}));

const toOpenAiTools = (tools) => tools.map(t => ({
  type: 'function',
  function: { name: t.name, description: t.description, parameters: t.inputSchema },
}));

/**
 * The conversation to send, oldest first.
 *
 * There is no server-side session to resume on an HTTP API, so the history is
 * resent every turn. System messages are the server talking to the analyst —
 * rate-limit notices and the like — and are dropped rather than replayed as if
 * the model had said them.
 *
 * The caller appends the user's message before invoking a turn, so the current
 * text is normally already the last entry. Appending it again would show the
 * model the same question twice; not appending it at all, if a future caller
 * stops storing first, would lose the question entirely. So: add it only when
 * it is not already there.
 */
function conversation(db, sessionId, text) {
  const msgs = listMessages(db, sessionId)
    .filter(m => m.role === 'user' || m.role === 'assistant')
    .slice(-HISTORY_TURNS)
    .map(m => ({ role: m.role, content: m.content }));
  const last = msgs[msgs.length - 1];
  if (!last || last.role !== 'user' || last.content !== text) {
    msgs.push({ role: 'user', content: text });
  }
  return msgs;
}

// --- the turn -----------------------------------------------------------------

function broadcastStoreRefresh(db) {
  broadcast('characterization.changed', charSummary(db));
  // A signal, not the case file: every view that draws records re-asks.
  broadcast('records.changed', null);
  broadcast('hosts.changed', listHosts(db));
  broadcast('edges.changed', listEdges(db));
  broadcast('connections.changed', derivedConnections(db));
}

export async function runTurn(db, sessionId, text, { analyst, mode = 'evidence', char = null } = {}) {
  const session = getSession(db, sessionId);
  if (!session) throw new Error(`no such session: ${sessionId}`);

  const cfg = modelConfig();
  const key = modelSecret();
  if (!key) throw new Error(`${cfg.provider} has no API key configured; run setup`);

  const tools = toolsFor(mode);
  /*
    Flat, because handleToolCall reads these at the top level.

    The MCP path gets them from environment variables and hands them over flat;
    here they arrived nested under `char`, so stage_entities saw no repository,
    no host and — worst of it — no staged flag. An import through this provider
    committed straight into a baseline instead of being held for review, which
    is the one safety net the whole characterization flow is built on.
  */
  const ctx = {
    analyst,
    sessionId,
    repo: char?.repo ?? null,
    host: char?.host ?? null,
    countedRows: char?.countedRows ?? null,
    fileId: char?.fileId ?? null,
    snapshotId: char?.snapshotId ?? null,
    staged: Boolean(char?.staged),
  };
  // The repository the analyst is standing in decides what the model is told
  // to extract, the same as on the CLI path.
  const system = buildSystemPrompt(db, { mode, repo: ctx.repo });
  const messages = conversation(db, sessionId, text);

  broadcast('session.state', setState(db, sessionId, 'running'));

  /*
    Whether the loop ended because the model had something to say, or because it
    ran out of steps. Without the distinction the second case fell into the
    ordinary completion path with no text, appended no message, and set the
    state to open exactly as a clean turn would — so the composer unlocked with
    no reply and no error, which reads as the request having vanished.

    Declared out here because the completion path below the catch reads it.
  */
  let answered = false;

  const ac = new AbortController();
  // Registered so shutdown can reach it. A turn on this backend is a loop over
  // fetch rather than a subprocess, and killAllTurns could only see processes.
  const untrack = trackTurnAbort(ac);
  const timer = setTimeout(() => ac.abort(), TURN_TIMEOUT_MS);
  let assistantText = '';
  let usedTool = false;
  /*
    Summed across the agentic loop: one analyst turn can be several requests
    once tools are involved, and the cost the team cares about is the turn's,
    not each step's. Stays null when the provider reports nothing, so an
    unmeasured turn is not folded in as a free one.
  */
  const spend = { inputTokens: null, outputTokens: null };
  const addSpend = (u) => {
    if (!u) return;
    for (const k of ['inputTokens', 'outputTokens']) {
      if (u[k] != null) spend[k] = (spend[k] ?? 0) + u[k];
    }
  };

  try {
    const call = cfg.provider === 'anthropic' ? anthropicTurn : openAiTurn;
    for (let step = 0; step < MAX_STEPS; step++) {
      const out = await call({
        cfg, key, system, messages, tools, signal: ac.signal,
        onText: (t) => {
          assistantText += t;
          broadcast('session.delta', { sessionId, text: t, mode });
        },
      });
      // Before the break: the step that produces the final answer costs as much
      // as the ones that called tools.
      addSpend(out.usage);

      if (!out.toolCalls.length) { answered = true; break; }

      usedTool = true;
      for (const tc of out.toolCalls) {
        broadcast('session.tool', { sessionId, name: tc.name });
      }
      // The assistant's own turn has to go back in before its tool results, or
      // the next request has results answering nothing.
      messages.push(out.assistantMessage);
      messages.push(...out.toolCalls.map(tc => toolResult(cfg.provider, tc, runTool(db, tc, ctx))));
    }
  } catch (err) {
    clearTimeout(timer);
    untrack();
    /*
      Keep whatever was already streamed.

      Text reaches the browser as it arrives, so an analyst watching a stalled
      turn has read what the model wrote before it stopped. Throwing without
      appending it lost exactly what the screen had shown, and a reload made it
      disappear — the analyst is then told nothing happened, having watched
      something happen.
    */
    if (assistantText.trim()) {
      const partial = appendMessage(db, sessionId, 'assistant',
        `${assistantText}\n\n_(the turn stopped here)_`, mode, null);
      broadcast('session.message', { sessionId, message: partial });
    }
    if (usedTool) broadcastStoreRefresh(db);
    broadcast('session.state', setState(db, sessionId, 'error'));
    if (ac.signal.aborted) {
      throw new Error(
        `no reply within ${Math.round(TURN_TIMEOUT_MS / 1000)}s, so the turn was stopped.`);
    }
    throw err;
  }
  clearTimeout(timer);
  untrack();

  if (!answered) {
    /*
      Said in the transcript rather than thrown. The tool calls it made along
      the way have already committed, so this is not a failed turn — it is a
      turn that did not finish, and the analyst needs to know which.
    */
    assistantText += `${assistantText.trim() ? '\n\n' : ''}_(stopped after ${MAX_STEPS} tool `
      + 'calls without reaching an answer. Whatever it filed along the way is in the case '
      + 'file; ask again, more narrowly, to carry on.)_';
  }

  if (assistantText.trim()) {
    const measured = spend.inputTokens != null || spend.outputTokens != null;
    const msg = appendMessage(db, sessionId, 'assistant', assistantText, mode,
      measured ? { ...spend, model: cfg.model } : null);
    broadcast('session.message', { sessionId, message: msg });
  }
  if (usedTool) broadcastStoreRefresh(db);
  broadcast('session.state', setState(db, sessionId, 'open'));
  return { text: assistantText, claudeSessionId: null };
}

/**
 * Execute one tool call.
 *
 * A throwing tool comes back as text the model can read and react to. Letting
 * it kill the turn would lose whatever the model had already written, and a
 * tool that refused for a good reason — "that snapshot never collected this
 * host" — is information, not a failure.
 */
function runTool(db, tc, ctx) {
  try {
    const res = handleToolCall(db, tc.name, tc.args, ctx);
    return (res?.content ?? []).map(c => c.text ?? '').join('\n') || '(no output)';
  } catch (err) {
    return `Tool error: ${err.message}`;
  }
}

const toolResult = (provider, tc, text) => (provider === 'anthropic'
  ? { role: 'user', content: [{ type: 'tool_result', tool_use_id: tc.id, content: text }] }
  : { role: 'tool', tool_call_id: tc.id, content: text });

// --- Anthropic ----------------------------------------------------------------

async function anthropicTurn({ cfg, key, system, messages, tools, signal, onText }) {
  const res = await fetch(`${cfg.baseUrl || 'https://api.anthropic.com'}/v1/messages`, {
    method: 'POST',
    signal,
    headers: {
      'content-type': 'application/json',
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: cfg.model, max_tokens: 8192, system, messages,
      tools: toAnthropicTools(tools), stream: true,
    }),
  });
  if (!res.ok) throw new Error(`anthropic ${res.status}: ${(await res.text()).slice(0, 300)}`);

  const blocks = [];
  // Reported by the API across two events: the input count once the request is
  // accepted, the output count as the turn closes.
  const usage = { inputTokens: null, outputTokens: null };
  await readSse(res, (evt) => {
    if (evt.type === 'message_start') {
      usage.inputTokens = evt.message?.usage?.input_tokens ?? usage.inputTokens;
    } else if (evt.type === 'message_delta' && evt.usage) {
      usage.outputTokens = evt.usage.output_tokens ?? usage.outputTokens;
    }
    if (evt.type === 'content_block_start') {
      blocks[evt.index] = evt.content_block.type === 'tool_use'
        ? { type: 'tool_use', id: evt.content_block.id, name: evt.content_block.name, json: '' }
        : { type: 'text', text: '' };
    } else if (evt.type === 'content_block_delta') {
      const b = blocks[evt.index];
      if (!b) return;
      if (evt.delta.type === 'text_delta') { b.text += evt.delta.text; onText(evt.delta.text); }
      else if (evt.delta.type === 'input_json_delta') b.json += evt.delta.partial_json;
    }
  });

  const content = blocks.filter(Boolean).map(b => (b.type === 'tool_use'
    ? { type: 'tool_use', id: b.id, name: b.name, input: parseArgs(b.json) }
    : { type: 'text', text: b.text }));
  return {
    assistantMessage: { role: 'assistant', content },
    toolCalls: blocks.filter(b => b?.type === 'tool_use')
      .map(b => ({ id: b.id, name: b.name, args: parseArgs(b.json) })),
    usage,
  };
}

// --- OpenAI-compatible ---------------------------------------------------------

async function openAiTurn({ cfg, key, system, messages, tools, signal, onText }) {
  const res = await fetch(`${cfg.baseUrl.replace(/\/$/, '')}/chat/completions`, {
    method: 'POST',
    signal,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
    body: JSON.stringify({
      model: cfg.model,
      messages: [{ role: 'system', content: system }, ...messages],
      tools: toOpenAiTools(tools),
      stream: true,
    }),
  });
  if (!res.ok) throw new Error(`openai ${res.status}: ${(await res.text()).slice(0, 300)}`);

  let text = '';
  const calls = [];   // index-keyed, because arguments arrive in fragments
  await readSse(res, (evt) => {
    const d = evt.choices?.[0]?.delta;
    if (!d) return;
    if (d.content) { text += d.content; onText(d.content); }
    for (const tc of d.tool_calls ?? []) {
      const slot = calls[tc.index] ??= { id: '', name: '', json: '' };
      if (tc.id) slot.id = tc.id;
      if (tc.function?.name) slot.name = tc.function.name;
      if (tc.function?.arguments) slot.json += tc.function.arguments;
    }
  });

  const toolCalls = calls.filter(Boolean).map(c => ({ id: c.id, name: c.name, args: parseArgs(c.json) }));
  return {
    assistantMessage: {
      role: 'assistant',
      content: text || null,
      ...(toolCalls.length && {
        tool_calls: toolCalls.map(c => ({
          id: c.id, type: 'function',
          function: { name: c.name, arguments: JSON.stringify(c.args) },
        })),
      }),
    },
    toolCalls,
  };
}

// --- shared plumbing -----------------------------------------------------------

/**
 * Read a text/event-stream body, one JSON payload per `data:` line.
 *
 * StringDecoder rather than concatenating chunks: a multi-byte character split
 * across a read arrives as U+FFFD otherwise, which is the same corruption the
 * CLI stream reader had to fix. Every em dash is a candidate.
 */
async function readSse(res, onEvent) {
  const decoder = new StringDecoder('utf8');
  let buf = '';
  for await (const chunk of res.body) {
    buf += decoder.write(chunk);
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line.startsWith('data:')) continue;
      const payload = line.slice(5).trim();
      if (!payload || payload === '[DONE]') continue;
      try { onEvent(JSON.parse(payload)); } catch { /* keepalive or partial */ }
    }
  }
}

/** Arguments arrive as streamed fragments; an incomplete one is not fatal. */
export function parseArgs(json) {
  if (!json || !json.trim()) return {};
  try { return JSON.parse(json); } catch { return {}; }
}

/**
 * One prompt, one answer, no session and no tools.
 *
 * The wizard needs this before a store exists to hold a conversation, and
 * structuring an inventory is a single question with a single answer. It lives
 * here rather than in the dispatcher so the credential stays readable in
 * exactly two files, which is what `test/invariants.test.js` asserts.
 */
export async function complete(prompt, { system = '', maxTokens = 16_000 } = {}) {
  const cfg = modelConfig();
  const key = modelSecret();
  if (!key) throw new Error(`${cfg.provider} has no API key configured`);

  if (cfg.provider === 'anthropic') {
    const res = await fetch(`${cfg.baseUrl || 'https://api.anthropic.com'}/v1/messages`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': key,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: cfg.model, max_tokens: maxTokens, system,
        messages: [{ role: 'user', content: prompt }],
      }),
    });
    if (!res.ok) throw new Error(`anthropic ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const body = await res.json();
    return (body.content ?? []).filter(c => c.type === 'text').map(c => c.text).join('');
  }

  const res = await fetch(`${cfg.baseUrl.replace(/\/$/, '')}/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
    body: JSON.stringify({
      model: cfg.model, max_tokens: maxTokens,
      messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }],
    }),
  });
  if (!res.ok) throw new Error(`openai ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const body = await res.json();
  return body.choices?.[0]?.message?.content ?? '';
}
