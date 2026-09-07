/**
 * Which model runs the turns, and how it authenticates.
 *
 * The Claude CLI authenticates itself and the application never sees a
 * credential. That is still the default and still the recommended path. The
 * other two providers need a key, which means this module is the only place in
 * the tree that holds one, and the rules around it are narrow on purpose:
 *
 *   - the file lives under data/, already gitignored, written 0600
 *   - `modelConfig()` never returns the key; `modelSecret()` is what providers
 *     call, and no route calls it
 *   - nothing logs it, including the startup banner
 *
 * The property being protected is that a LAN-exposed origin cannot hand out a
 * credential, not that the string never exists. test/invariants.test.js is
 * what holds it: modelSecret() may be referenced by this file and by
 * claude/api-provider.js, and by nothing else.
 */
import {
  readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, renameSync,
} from 'node:fs';
import { dirname, resolve } from 'node:path';

export const CONFIG_PATH = resolve(process.env.HUNT_MODEL_CONFIG || 'data/model.json');

export const PROVIDERS = ['cli', 'anthropic', 'openai'];

/** Sensible model per provider when the operator does not name one. */
export const DEFAULT_MODEL = {
  cli: null,                        // the CLI picks; we do not second-guess it
  anthropic: 'claude-opus-4-6',
  openai: 'gpt-4o',
};

const BLANK = { provider: 'cli', model: null, baseUrl: null, key: null };

function readRaw() {
  if (!existsSync(CONFIG_PATH)) return { ...BLANK };
  try {
    const d = JSON.parse(readFileSync(CONFIG_PATH, 'utf8').replace(/^﻿/, ''));
    return {
      provider: PROVIDERS.includes(d.provider) ? d.provider : 'cli',
      model: d.model || null,
      baseUrl: d.baseUrl || null,
      key: d.key || null,
    };
  } catch {
    // A corrupt config must not take the server down mid-exercise. The CLI
    // path needs no configuration at all, so falling back to it is safe.
    return { ...BLANK };
  }
}

/**
 * The configuration, minus the credential. Safe to return over an API, log, or
 * hand to a template.
 */
export function modelConfig() {
  const { key, ...rest } = readRaw();
  return { ...rest, hasKey: Boolean(key), configured: existsSync(CONFIG_PATH) };
}

/**
 * The credential itself. Providers only. Nothing that can reach a response
 * body may call this, and `test/invariants.test.js` checks that.
 */
export function modelSecret() {
  return readRaw().key;
}

/**
 * Write the configuration.
 *
 * An omitted key keeps whatever is already stored, so re-saving a base URL
 * does not silently blank the credential and leave a server that authenticates
 * against nothing until the first turn fails.
 */
export function setModelConfig({ provider, model, baseUrl, key }) {
  if (!PROVIDERS.includes(provider)) {
    throw new Error(`provider must be one of: ${PROVIDERS.join(', ')}`);
  }
  const prev = readRaw();
  const next = {
    provider,
    model: model === undefined ? prev.model : (model || null),
    baseUrl: baseUrl === undefined ? prev.baseUrl : (baseUrl || null),
    key: key === undefined ? prev.key : (key || null),
  };
  if (provider !== 'cli') {
    if (!next.key) throw new Error(`${provider} needs an API key`);
    if (!next.model) next.model = DEFAULT_MODEL[provider];
  }
  if (provider === 'openai' && !next.baseUrl) {
    throw new Error('an OpenAI-compatible provider needs a base URL');
  }

  mkdirSync(dirname(CONFIG_PATH), { recursive: true });
  /*
    Written to one side and renamed into place, so a crash or a full disk
    leaves the previous configuration rather than half of one. The plan file
    already does this; this one holds a credential, so it matters more.

    The temporary file is created 0600 and chmodded before the rename, never
    after: the rename is what makes it the real file, and the key must already
    be unreadable by anyone else at that moment.
  */
  const tmp = `${CONFIG_PATH}.tmp`;
  writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n', { mode: 0o600 });
  // writeFileSync only applies mode when it creates the file, so a temporary
  // left behind by an earlier run keeps what it had. Set it every time.
  try { chmodSync(tmp, 0o600); } catch { /* not POSIX; NTFS ACLs apply */ }
  renameSync(tmp, CONFIG_PATH);
  try { chmodSync(CONFIG_PATH, 0o600); } catch { /* not POSIX; NTFS ACLs apply */ }
  return modelConfig();
}

/** One line for the startup banner. Names the provider, never the credential. */
export function modelBanner() {
  const c = modelConfig();
  if (c.provider === 'cli') return 'Claude CLI on this host (the CLI holds its own auth)';
  const where = c.baseUrl ? ` at ${c.baseUrl}` : '';
  return `${c.provider}${where} · ${c.model} · key configured`;
}
