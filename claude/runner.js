import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { StringDecoder } from 'node:string_decoder';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildSystemPrompt, promptBudget } from './prompt.js';
import { activeMissionName } from '../store/mission.js';
import { getSession, setState, setClaudeSessionId, appendMessage } from '../store/sessions.js';
import { listRecords, derivedConnections } from '../store/records.js';
import { listHosts } from '../store/hosts.js';
import { listEdges } from '../store/edges.js';
import { summary as charSummary } from '../store/characterization.js';
import { broadcast } from '../server/sse.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const MCP_SERVER = resolve(HERE, 'mcp-server.js');
/**
 * Read at call time, not at import.
 *
 * Captured in a const, the value was fixed by whatever the environment held
 * when the module first loaded, so pointing the server at a different binary
 * needed a restart — and a test could not point it anywhere at all, which is
 * how the scratch-file leak went unnoticed: the only test that could have
 * caught it silently ran the real CLI instead.
 */
export const claudeBin = () => process.env.HUNT_CLAUDE_BIN || 'claude';
// Five minutes, not ten. A turn that is being throttled shows the analyst a
// spinner and nothing else, and ten minutes of that is indistinguishable from
// a hung server.
const TURN_TIMEOUT_MS = Number(process.env.HUNT_TURN_TIMEOUT_MS || 5 * 60 * 1000);
/** Empty scratch dir the subprocess runs in. See the spawn call for why. */
const SESSION_CWD = resolve(process.env.HUNT_SESSION_CWD || 'data/session-cwd');

/**
 * Exhaustive tool denylist.
 *
 * --allowedTools is ADDITIVE, not exclusive: it grants permission but does not
 * remove anything. Verified empirically against claude 2.1.236 — passing only
 * an allowlist still left Read, Glob, Grep and ToolSearch enabled, which on a
 * LAN-exposed server is arbitrary file read as the host user.
 *
 * Note PowerShell, not Bash, is the shell tool on Windows. Denying Bash alone
 * would have left shell execution wide open.
 *
 * With this list plus --strict-mcp-config, the subprocess starts with zero
 * tools; the only capabilities it gains are the four hunt tools from our own
 * MCP server. Asserted in test/invariants.test.js.
 */
export const TOOL_DENYLIST = [
  'Bash', 'BashOutput', 'KillShell', 'PowerShell',
  'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'NotebookRead',
  'Read', 'Glob', 'Grep',
  'WebFetch', 'WebSearch',
  'Task', 'Agent', 'Artifact', 'Workflow', 'Skill', 'SlashCommand', 'ToolSearch',
  'CronCreate', 'CronDelete', 'CronList', 'RemoteTrigger', 'ScheduleWakeup',
  'SendMessage', 'ListAgents', 'TaskOutput', 'TaskStop', 'PushNotification',
  'DesignSync', 'EnterWorktree', 'ExitWorktree', 'EnterPlanMode', 'ExitPlanMode',
  'Monitor', 'SearchSkills', 'ListSkills', 'SearchPlugins', 'ListPlugins',
  'SuggestPluginInstall', 'ReportFindings', 'TodoWrite', 'AskUserQuestion', 'SendUserFile',
];

export const HUNT_TOOLS = [
  'mcp__hunt__propose_finding', 'mcp__hunt__propose_edge',
  'mcp__hunt__query_terrain', 'mcp__hunt__search_records',
  // Evidence mode gets the baseline lookup. "Is this normal here" is the
  // question that turns a suspicion into a finding or kills it, and without
  // this the characterization repositories are a write-only museum.
  'mcp__hunt__query_baseline',
];

/**
 * Research mode gets the read-only pair and nothing else.
 *
 * The prompt tells it not to file anything, but a prompt is a request and the
 * tool list is a guarantee. Research turns must not be able to write to the
 * case file even if the model decides the analyst really wanted a finding.
 */
export const RESEARCH_TOOLS = [
  'mcp__hunt__query_terrain', 'mcp__hunt__search_records',
];

/**
 * Characterization observes; it does not accuse.
 *
 * No propose_finding and no propose_edge. Four hundred running processes are a
 * baseline, not four hundred findings, and a mode that can file them would
 * bury the adjudication rail. Where something looks wrong Claude says so in
 * prose and the analyst promotes that row by hand. As with research mode, the
 * tool list is the guarantee and the prompt is only the request.
 */
export const CHARACTERIZATION_TOOLS = [
  'mcp__hunt__stage_entities', 'mcp__hunt__query_baseline',
  'mcp__hunt__query_terrain',
];

export const toolsForMode = (mode) =>
  mode === 'research' ? RESEARCH_TOOLS
    : mode === 'characterization' ? CHARACTERIZATION_TOOLS
      : HUNT_TOOLS;

/** Hunt tools a mode must not be able to reach, denied outright rather than merely unlisted. */
export const deniedHuntTools = (mode) =>
  mode === 'research' ? ['mcp__hunt__propose_finding', 'mcp__hunt__propose_edge']
    : mode === 'characterization' ? ['mcp__hunt__propose_finding', 'mcp__hunt__propose_edge']
      : ['mcp__hunt__stage_entities'];

let dbPath = process.env.HUNT_DB || 'data/hunt.db';
export const setDbPath = (p) => { dbPath = resolve(p); };

/*
  Every turn subprocess currently running.

  A turn spawns the CLI, which spawns its own MCP server, and that grandchild
  holds an independent connection to the case file. Nothing tracked either, so
  shutdown closed the HTTP server and the event hub and left them running — the
  operator sees the process exit while a model still holds a writable handle on
  the evidence. Tracking them is the only way shutdown can be told to wait.
*/
const liveTurns = new Set();

/*
  And every API-backed turn, which has no subprocess at all.

  A turn against Anthropic or an OpenAI-compatible endpoint is an agentic loop
  over fetch, held open by an AbortController that was registered nowhere. On
  those backends shutdown reported "0 turns still running" and then closed the
  server while the loop went on calling handleToolCall — writing findings into
  a case file the operator had been told was shut.
*/
const liveAborts = new Set();

/** Register a turn that is a request rather than a process. @returns its undo */
export function trackTurnAbort(ac) {
  liveAborts.add(ac);
  return () => liveAborts.delete(ac);
}

/**
 * Stop every turn in flight.
 *
 * SIGTERM first, because a CLI given the chance will tell its own children to
 * stop; SIGKILL after a grace period for the ones that will not. Returns how
 * many it signalled, so a caller can say so rather than guess.
 */
export function killAllTurns({ graceMs = 1500 } = {}) {
  const doomed = [...liveTurns];
  const aborting = [...liveAborts];
  for (const child of doomed) { try { child.kill('SIGTERM'); } catch { /* already gone */ } }
  for (const ac of aborting) { try { ac.abort(); } catch { /* already settled */ } }
  liveAborts.clear();
  if (doomed.length) {
    const t = setTimeout(() => {
      for (const child of doomed) {
        if (liveTurns.has(child)) { try { child.kill('SIGKILL'); } catch { /* gone */ } }
      }
    }, graceMs);
    // Never hold the event loop open on the way out; this is a shutdown path.
    t.unref?.();
  }
  return doomed.length + aborting.length;
}

/**
 * Wait for the signalled turns to actually be gone.
 *
 * killAllTurns escalates to SIGKILL after a grace period, and nothing ever
 * reached that: serve.js exits from server.close()'s callback, which fires in
 * about a millisecond, so the escalation timer — unref'd, because a shutdown
 * path must not hold the loop open by itself — never got to run. A child that
 * ignores SIGTERM outlived the process every time, still holding its MCP
 * grandchild's writable handle on the case file, which is the whole state the
 * tracking exists to prevent.
 *
 * This interval is deliberately NOT unref'd: for as long as it is pending the
 * escalation can fire. @returns how many were still alive when it gave up.
 */
export function awaitTurnsExit({ timeoutMs = 4000 } = {}) {
  if (!liveTurns.size) return Promise.resolve(0);
  return new Promise((resolve) => {
    const started = Date.now();
    const tick = setInterval(() => {
      if (liveTurns.size && Date.now() - started < timeoutMs) return;
      clearInterval(tick);
      resolve(liveTurns.size);
    }, 25);
  });
}

/** How many turns are in flight. Exported for the test, and for the banner. */
export const liveTurnCount = () => liveTurns.size + liveAborts.size;

/**
 * Turn one line of `--output-format stream-json` into zero or more deltas.
 * Pure, so the parser is testable against a recorded fixture with no
 * subprocess and no network.
 */
export function parseStream(line) {
  let d;
  try { d = JSON.parse(line); } catch { return []; }
  if (!d || typeof d !== 'object') return [];

  // SessionStart hooks emit their own chatter before the model says anything.
  if (typeof d.subtype === 'string' && d.subtype.startsWith('hook_')) return [];

  if (d.type === 'system' && d.subtype === 'init') {
    return [{ kind: 'init', claudeSessionId: d.session_id, tools: d.tools ?? [], model: d.model ?? null }];
  }
  if (d.type === 'rate_limit_event') {
    return [{ kind: 'rate_limit', info: d.rate_limit_info ?? null }];
  }
  if (d.type === 'assistant' && Array.isArray(d.message?.content)) {
    const out = [];
    for (const block of d.message.content) {
      if (block.type === 'text' && block.text) out.push({ kind: 'text', text: block.text });
      else if (block.type === 'tool_use') out.push({ kind: 'tool_use', name: block.name });
    }
    return out;
  }
  if (d.type === 'result') {
    /*
      The turn's own account of what it cost. Passed through rather than
      derived: the CLI is the only thing that knows about cache reads, and a
      token count this server computed would be a guess dressed as a receipt.
    */
    return [{
      kind: 'result',
      text: d.result ?? '',
      isError: Boolean(d.is_error),
      subtype: d.subtype,
      usage: d.usage || d.total_cost_usd != null ? {
        inputTokens: d.usage?.input_tokens ?? null,
        outputTokens: d.usage?.output_tokens ?? null,
        costUsd: d.total_cost_usd ?? null,
        durationMs: d.duration_ms ?? null,
      } : null,
    }];
  }
  return [];
}

/**
 * Whether this CLI accepts the system prompt as a file rather than an argv
 * value. Probed once, for free: point the flag at a file that does not exist
 * and the error names either the missing file (supported) or the unknown
 * option (not). No API call, no tokens, instant either way.
 *
 * It matters because argv is where the ceiling was. Windows caps a command
 * line at 32,767 characters, so the case file handed to the model had to be
 * truncated — at about ninety records the model stopped being told the rest
 * existed. A file has no such limit.
 */
let promptFileSupported = null;

export async function supportsPromptFile() {
  if (promptFileSupported !== null) return promptFileSupported;
  if (process.env.HUNT_NO_PROMPT_FILE === '1') { promptFileSupported = false; return false; }

  promptFileSupported = await new Promise((resolve) => {
    let err = '';
    let child;
    try {
      child = spawn(claudeBin(),
        ['-p', '--append-system-prompt-file', join(tmpdir(), 'hunt-probe-absent.txt'), 'x'],
        { stdio: ['ignore', 'ignore', 'pipe'] });
    } catch { return resolve(false); }
    const timer = setTimeout(() => { child.kill(); resolve(false); }, 15_000);
    child.on('error', () => { clearTimeout(timer); resolve(false); });
    child.stderr.on('data', c => { err += c; });
    child.on('close', () => {
      clearTimeout(timer);
      resolve(!/unknown option/i.test(err));
    });
  });
  return promptFileSupported;
}

/**
 * Scratch files the subprocess needs for the length of one turn.
 *
 * Both are removed when the child exits. They were not, and two directories
 * accumulated per turn — which is untidy for the MCP config and worse for the
 * prompt, because in evidence mode that file holds the entire case file. A
 * week of hunting left the findings scattered through the temp directory of a
 * machine other people use.
 */
/*
  Where a turn's scratch files go. The override exists so a test can watch its
  own directory rather than the machine's: scratch-cleanup.test.js attributed
  anything new in os.tmpdir() to itself and deleted it, so two suites running
  at once — or a real server taking a turn on the same machine — failed the
  test AND pulled the live MCP config out from under the other process.
*/
const scratchRoot = () => process.env.HUNT_SCRATCH_DIR || tmpdir();

const scratch = (prefix, name, body) => {
  const dir = mkdtempSync(join(scratchRoot(), prefix));
  const path = join(dir, name);
  writeFileSync(path, body, 'utf8');
  return path;
};

const discard = (path) => {
  if (!path) return;
  try { rmSync(dirname(path), { recursive: true, force: true }); } catch { /* already gone */ }
};

const writePromptFile = (prompt) => scratch('hunt-sys-', 'system.txt', prompt);

function writeMcpConfig(sessionId, analyst, char = null) {
  return scratch('hunt-mcp-', 'mcp.json', JSON.stringify({
    mcpServers: {
      hunt: {
        command: process.execPath,
        args: [MCP_SERVER],
        env: {
          HUNT_MCP_STDIO: '1',
          HUNT_DB: dbPath,
          // Named explicitly rather than left to be inferred from the working
          // directory, the same way the database path is. A tool that cannot
          // resolve the mission reports the estate as missing.
          ...(activeMissionName() ? { HUNT_MISSION: activeMissionName() } : {}),
          HUNT_SESSION: sessionId,
          HUNT_ANALYST: analyst ?? 'claude',
          // Characterization context, so a staged snapshot can be reconciled
          // against the upload it was extracted from.
          ...(char?.repo ? { HUNT_CHAR_REPO: String(char.repo) } : {}),
          ...(char?.host ? { HUNT_CHAR_HOST: String(char.host) } : {}),
          ...(char?.countedRows != null ? { HUNT_CHAR_ROWS: String(char.countedRows) } : {}),
          ...(char?.fileId ? { HUNT_CHAR_FILE: String(char.fileId) } : {}),
          ...(char?.snapshotId ? { HUNT_CHAR_SNAPSHOT: String(char.snapshotId) } : {}),
          // Imports through the review panel stage rather than commit, so a
          // bad extraction is caught before it becomes a baseline.
          ...(char?.staged ? { HUNT_CHAR_STAGED: '1' } : {}),
        },
      },
    },
  }));
}

/** Push the derived views so the map, timeline and pending rail catch up. */
function broadcastStoreRefresh(db) {
  broadcast('characterization.changed', charSummary(db));
  // A signal, not the case file: every view that draws records re-asks.
  broadcast('records.changed', null);
  broadcast('hosts.changed', listHosts(db));
  broadcast('edges.changed', listEdges(db));
  broadcast('connections.changed', derivedConnections(db));
}

/**
 * The flags every turn is spawned with.
 *
 * Extracted so the hardening can be asserted against the array the spawn
 * actually receives. The invariant used to be a grep for the flag over this
 * file's text, and a doc comment mentioning it satisfied that on its own:
 * deleting --strict-mcp-config from the spawn left the test passing green
 * while the subprocess inherited every MCP server on the operator's machine.
 */
export function turnArgs({ mcpConfig, mode }) {
  return [
    '-p',
    '--output-format', 'stream-json',
    '--verbose',
    // Not --bare, despite it being tempting: it skips hooks and auto-memory,
    // but it also skips keychain reads, so Anthropic auth becomes strictly
    // ANTHROPIC_API_KEY. That defeats the entire point of shelling out to the
    // CLI. Tried it; every turn came back "Not logged in · Please run /login".
    '--mcp-config', mcpConfig,
    '--strict-mcp-config',
    // Writing tools a mode must not use are denied outright, not merely left
    // out of the allowlist — --allowedTools is additive and would not remove
    // them. Evidence mode is likewise blocked from staging baselines, so a
    // pasted log cannot quietly rewrite what "normal" means.
    '--disallowedTools', TOOL_DENYLIST.concat(deniedHuntTools(mode)).join(','),
    '--allowedTools', toolsForMode(mode).join(','),
  ];
}

/**
 * The empty directory a turn runs in, resolved.
 *
 * Exported for the same reason as turnArgs: CLAUDE.md discovery and the
 * auto-memory namespace are both keyed to the working directory, and the
 * invariant that this is NOT the server's own directory was a grep for the
 * string "cwd: SESSION_CWD" — which pointing SESSION_CWD at '.' left intact.
 */
export const sessionCwd = () => SESSION_CWD;

/**
 * Run one conversational turn. A fresh process per turn, resumed by session
 * id — nothing long-lived to supervise, and a crashed turn cannot corrupt the
 * conversation.
 */
export async function runTurn(db, sessionId, text, { analyst, mode = 'evidence', char = null } = {}) {
  const session = getSession(db, sessionId);
  if (!session) throw new Error(`no such session: ${sessionId}`);

  broadcast('session.state', setState(db, sessionId, 'running'));
  const mcpConfig = writeMcpConfig(sessionId, analyst, char);

  const args = turnArgs({ mcpConfig, mode });

  /*
    The system prompt goes in a file where the CLI supports it, which is what
    lifts the case-file ceiling: as an argv value it had to fit inside the
    32,767-character Windows command line, and past about ninety records the
    model simply stopped being shown the rest. An older CLI without the flag
    still works, on the capped argv path it always used.
  */
  const viaFile = await supportsPromptFile();
  const prompt = buildSystemPrompt(db, { mode, repo: char?.repo ?? null, maxChars: promptBudget(viaFile) });
  const promptFile = viaFile ? writePromptFile(prompt) : null;
  args.push(...(promptFile
    ? ['--append-system-prompt-file', promptFile]
    : ['--append-system-prompt', prompt]));

  // One place that removes both, whichever way the turn ends.
  const cleanUp = () => { discard(mcpConfig); discard(promptFile); };
  if (session.claude_session_id) args.push('--resume', session.claude_session_id);

  // Run in a dedicated empty directory. Both CLAUDE.md auto-discovery and the
  // auto-memory namespace are keyed to the working directory, so inheriting
  // the server's cwd would pull the operator's project instructions and
  // personal memory files into a session any LAN teammate can start.
  mkdirSync(SESSION_CWD, { recursive: true });

  const child = spawn(claudeBin(), args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: SESSION_CWD,
    env: {
      ...process.env,
      HUNT_DB: dbPath,
      // Suppress the superpowers SessionStart preamble. It costs ~1.5k tokens
      // on every turn and instructs the model to invoke skills this subprocess
      // is not permitted to call. Harmless if the plugin is absent.
      SUPERPOWERS_SKIP_SESSION_START: '1',
    },
  });

  liveTurns.add(child);
  child.on('exit', () => liveTurns.delete(child));

  const stderr = [];
  let assistantText = '';
  let turnUsage = null;
  let turnModel = null;
  let usedTool = false;
  let ratePosted = false;
  let buf = '';
  let finished = false;
  // Decode across chunk boundaries. `buf += chunk` decoded each Buffer alone,
  // so a multi-byte character split by a 64k read (every em dash and ellipsis
  // Claude writes is a candidate) arrived as U+FFFD in the transcript and in
  // the stored message. The decoder holds the partial sequence instead.
  const decoder = new StringDecoder('utf8');

  let timedOut = false;
  const timer = setTimeout(() => {
    if (finished) return;
    timedOut = true;
    /*
      SIGTERM, then SIGKILL if it is still there. kill() alone was enough for a
      CLI that stops when asked, and a stuck turn is by definition the case
      where it did not — the grandchild MCP server holds the case file open, so
      "asked politely and moved on" leaves something writing to it.
    */
    child.kill('SIGTERM');
    const hard = setTimeout(() => {
      if (liveTurns.has(child)) { try { child.kill('SIGKILL'); } catch { /* gone */ } }
    }, 2000);
    hard.unref?.();
  }, TURN_TIMEOUT_MS);

  /*
    A write to a child that has already gone raises EPIPE, and an unhandled
    'error' on a stream ends the process — so a CLI that exits on an unknown
    flag or a rejected --resume id, a turn killed by its own timeout, or
    shutdown itself, took the whole server down with it whenever the prompt was
    larger than the pipe buffer. The exit path below already reports what
    actually happened; this only stops the write from being fatal.
  */
  child.stdin.on('error', () => { /* reported by the exit path */ });
  child.stdin.write(text);
  child.stdin.end();

  child.stderr.on('data', c => { stderr.push(String(c)); });

  child.stdout.on('data', (chunk) => {
    buf += decoder.write(chunk);
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (!line.trim()) continue;

      for (const delta of parseStream(line)) {
        switch (delta.kind) {
          case 'init':
            turnModel = delta.model ?? turnModel;
            if (!session.claude_session_id) setClaudeSessionId(db, sessionId, delta.claudeSessionId);
            break;
          case 'text':
            assistantText += delta.text;
            broadcast('session.delta', { sessionId, text: delta.text, mode });
            break;
          case 'tool_use':
            usedTool = true;
            broadcast('session.tool', { sessionId, name: delta.name });
            break;
          case 'rate_limit': {
            broadcast('rate_limit', delta.info);
            // Say so in the transcript rather than only in a toast. A quota
            // warning is the most likely reason a turn takes minutes, and the
            // analyst should not have to guess whether the server is broken.
            const st = delta.info?.status;
            if (st && st !== 'allowed' && !ratePosted) {
              ratePosted = true;
              const pct = Math.round((delta.info.utilization ?? 0) * 100);
              const msg = appendMessage(db, sessionId, 'system',
                `Claude usage is at ${pct}% of the ${delta.info.rateLimitType ?? ''} limit ` +
                `(${st}). This turn may be slow or may not complete.`, mode);
              broadcast('session.message', { sessionId, message: msg });
            }
            break;
          }
          case 'result':
            if (delta.isError && !assistantText) assistantText = delta.text;
            if (delta.usage) turnUsage = { ...delta.usage, model: turnModel };
            break;
        }
      }
    }
  });

  return new Promise((resolvePromise, reject) => {
    child.on('error', (err) => {
      finished = true; clearTimeout(timer); cleanUp();
      reject(new Error(`could not start ${claudeBin()}: ${err.message}`));
    });

    child.on('close', (code) => {
      finished = true; clearTimeout(timer); cleanUp();

      if (assistantText.trim()) {
        const msg = appendMessage(db, sessionId, 'assistant', assistantText, mode, turnUsage);
        broadcast('session.message', { sessionId, message: msg });
      }
      // Tool calls land in SQLite from a separate process; refresh regardless
      // so the pending rail and map pick them up.
      if (usedTool || code === 0) broadcastStoreRefresh(db);

      if (code !== 0) {
        broadcast('session.state', setState(db, sessionId, 'error'));
        // Say "timed out", not "exited with code null". Being throttled is the
        // likeliest reason to hit the bound, and that is exactly the case the
        // analyst cannot diagnose from an exit code.
        if (timedOut) {
          return reject(new Error(
            `no reply within ${Math.round(TURN_TIMEOUT_MS / 1000)}s, so the turn was stopped. ` +
            'Claude may be throttled — check the usage warning above and try again.'));
        }
        const tail = stderr.join('').trim().split('\n').slice(-8).join('\n');
        return reject(new Error(tail || `claude exited with code ${code}`));
      }

      broadcast('session.state', setState(db, sessionId, 'open'));
      resolvePromise({ text: assistantText, claudeSessionId: getSession(db, sessionId).claude_session_id });
    });
  });
}
