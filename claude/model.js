/**
 * One entry point for running a turn, whichever backend is configured.
 *
 * Callers pass the same arguments they always did. The CLI path is unchanged
 * and remains the default, so a server with no model configuration behaves
 * exactly as it did before any of this existed — which is what keeps a running
 * exercise unaffected by the change.
 */
import { modelConfig } from '../store/model-config.js';
import { runTurn as cliTurn } from './runner.js';
import { runTurn as apiTurn, complete as completeApi } from './api-provider.js';

export async function runTurn(db, sessionId, text, opts = {}) {
  const { provider } = modelConfig();
  return provider === 'cli'
    ? cliTurn(db, sessionId, text, opts)
    : apiTurn(db, sessionId, text, opts);
}

/**
 * One prompt, one answer, no session and no tools.
 *
 * The wizard needs this before a store exists to hold a conversation, and
 * structuring an inventory is a single question with a single answer. Kept
 * separate from runTurn rather than folded into it, because a turn carries a
 * transcript, a mode and a tool loop and none of that applies here.
 */
export async function complete(prompt, opts = {}) {
  return modelConfig().provider === 'cli'
    ? completeCli(prompt, opts.system ?? '')
    : completeApi(prompt, opts);
}

/**
 * The CLI, with everything switched off.
 *
 * No MCP config, an empty allowlist and the full denylist: this is a text
 * transformation, so a model that decided to read a file would be a bug and a
 * hazard rather than a convenience.
 */
async function completeCli(prompt, system) {
  const { spawn } = await import('node:child_process');
  const { TOOL_DENYLIST, claudeBin } = await import('./runner.js');
  const bin = claudeBin();
  const args = [
    '-p', '--output-format', 'text', '--strict-mcp-config',
    '--disallowedTools', TOOL_DENYLIST.join(','),
  ];
  if (system) args.push('--append-system-prompt', system);

  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, SUPERPOWERS_SKIP_SESSION_START: '1' },
    });
    let out = '';
    let err = '';
    /*
      Escalate, and settle.

      This sent SIGTERM and then waited for 'close' — so a CLI that traps the
      signal left the wizard's request hanging with no bound at all, and the
      child orphaned. These spawns are not in liveTurns either, so shutdown
      cannot reach them; the promise settling is what ends the wait.
    */
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } }, 2000).unref?.();
      reject(new Error('the CLI did not answer within five minutes'));
    }, 300_000);
    child.on('error', e => { clearTimeout(timer); reject(e); });
    child.stdout.on('data', c => { out += c; });
    child.stderr.on('data', c => { err += c; });
    // EPIPE on a child that has already exited must not be fatal; the close
    // handler below reports why it exited.
    child.stdin.on('error', () => { /* reported by the close path */ });
    child.stdin.write(prompt);
    child.stdin.end();
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        return reject(new Error(
          err.trim().split('\n').slice(-4).join('\n') || `claude exited ${code}`));
      }
      resolve(out);
    });
  });
}

/**
 * Ask a backend whether it actually works, before an analyst finds out the
 * hard way at the first evidence turn.
 *
 * Deliberately cheap: a version check and a one-token completion. A backend
 * that answers this can stream, authenticate and reach its endpoint, which is
 * everything the wizard needs to know.
 */
export async function probeProvider({ provider, model, baseUrl, key }) {
  if (provider === 'cli') return probeCli();
  if (provider === 'anthropic') return probeAnthropic({ model, baseUrl, key });
  if (provider === 'openai') return probeOpenAi({ model, baseUrl, key });
  return { ok: false, detail: `unknown provider: ${provider}` };
}

async function probeCli() {
  const { spawn } = await import('node:child_process');
  const { claudeBin } = await import('./runner.js');
  const bin = claudeBin();
  const run = (args, input) => new Promise((resolve) => {
    let out = '';
    let err = '';
    let child;
    try {
      child = spawn(bin, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (e) {
      return resolve({ code: -1, out: '', err: e.message });
    }
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } }, 2000).unref?.();
      resolve({ code: -1, out, err: 'the CLI did not answer within 60s' });
    }, 60_000);
    child.on('error', e => { clearTimeout(timer); resolve({ code: -1, out, err: e.message }); });
    child.stdout.on('data', c => { out += c; });
    child.stderr.on('data', c => { err += c; });
    child.stdin.on('error', () => { /* reported by the close path */ });
    if (input != null) { child.stdin.write(input); child.stdin.end(); }
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err }); });
  });

  const v = await run(['--version']);
  if (v.code !== 0) {
    return {
      ok: false,
      detail: `\`${bin} --version\` failed: ${(v.err || v.out).trim().slice(0, 200) || 'not found on PATH'}`,
    };
  }

  // Installed is not the same as logged in, and being logged out is the
  // failure that looks like a working setup until the first real turn.
  const t = await run(['-p', '--output-format', 'text'], 'Reply with the single word: ready');
  if (t.code !== 0 || /not logged in|\/login|authentication/i.test(t.out + t.err)) {
    return {
      ok: false,
      version: v.out.trim(),
      detail: 'The CLI is installed but not authenticated. Run `claude` once in a terminal on '
        + 'this machine and sign in, then probe again.',
    };
  }
  return { ok: true, version: v.out.trim(), detail: `${v.out.trim()} · authenticated` };
}

async function probeAnthropic({ model, baseUrl, key }) {
  if (!key) return { ok: false, detail: 'no API key given' };
  try {
    const res = await fetch(`${baseUrl || 'https://api.anthropic.com'}/v1/messages`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': key,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: model || 'claude-opus-4-6', max_tokens: 4,
        messages: [{ role: 'user', content: 'ready' }],
      }),
    });
    if (!res.ok) return { ok: false, detail: `HTTP ${res.status}: ${(await res.text()).slice(0, 200)}` };
    return { ok: true, detail: `${model || 'claude-opus-4-6'} answered` };
  } catch (e) {
    return { ok: false, detail: e.message };
  }
}

async function probeOpenAi({ model, baseUrl, key }) {
  if (!baseUrl) return { ok: false, detail: 'no base URL given' };
  if (!key) return { ok: false, detail: 'no API key given' };
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
      body: JSON.stringify({
        model: model || 'gpt-4o', max_tokens: 4,
        messages: [{ role: 'user', content: 'ready' }],
      }),
    });
    if (!res.ok) return { ok: false, detail: `HTTP ${res.status}: ${(await res.text()).slice(0, 200)}` };
    const body = await res.json();
    const name = body.model || model;
    return { ok: true, detail: `${name} answered` };
  } catch (e) {
    // A local endpoint that is not running is the common case here, and the
    // raw fetch error ("fetch failed") says nothing useful on its own.
    return { ok: false, detail: `${e.message} — is ${baseUrl} reachable from this machine?` };
  }
}
