import { test } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync, statSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Set before the import: the module resolves its path once, at load.
const DIR = mkdtempSync(join(tmpdir(), 'huntcfg-'));
process.env.HUNT_MODEL_CONFIG = join(DIR, 'model.json');
const {
  modelConfig, modelSecret, setModelConfig, modelBanner, CONFIG_PATH, PROVIDERS,
} = await import('../store/model-config.js');

process.on('exit', () => rmSync(DIR, { recursive: true, force: true }));

test('with nothing configured the CLI is the default', () => {
  assert.equal(modelConfig().provider, 'cli');
  assert.equal(modelConfig().hasKey, false);
  assert.equal(modelSecret(), null);
});

test('the key round-trips to modelSecret and never to modelConfig', () => {
  setModelConfig({ provider: 'anthropic', model: 'claude-opus-4-6', key: 'sk-ant-test-123' });

  const shown = modelConfig();
  assert.equal(shown.provider, 'anthropic');
  assert.equal(shown.model, 'claude-opus-4-6');
  assert.equal(shown.hasKey, true);
  assert.equal('key' in shown, false, 'the key must not be in the object callers see');
  assert.equal(JSON.stringify(shown).includes('sk-ant-test-123'), false);

  assert.equal(modelSecret(), 'sk-ant-test-123', 'but a provider can still get it');
});

test('the banner names the provider and not the credential', () => {
  setModelConfig({ provider: 'anthropic', model: 'claude-opus-4-6', key: 'sk-ant-test-123' });
  const line = modelBanner();
  assert.match(line, /anthropic/);
  assert.equal(line.includes('sk-ant-test-123'), false);
});

/*
  Saving a base URL must not blank the key. Otherwise correcting a typo in the
  endpoint leaves a server that authenticates against nothing and does not find
  out until an analyst's first turn fails.
*/
test('re-saving without a key keeps the one already stored', () => {
  setModelConfig({ provider: 'openai', baseUrl: 'http://10.0.0.5:8000/v1', model: 'qwen', key: 'k1' });
  setModelConfig({ provider: 'openai', baseUrl: 'http://10.0.0.6:8000/v1', model: 'qwen' });
  assert.equal(modelSecret(), 'k1');
  assert.equal(modelConfig().baseUrl, 'http://10.0.0.6:8000/v1');
});

test('an API provider without a key is refused', () => {
  writeFileSync(CONFIG_PATH, JSON.stringify({ provider: 'cli' }), 'utf8');
  assert.throws(() => setModelConfig({ provider: 'anthropic', key: '' }), /needs an API key/);
});

test('an OpenAI-compatible provider needs somewhere to send the request', () => {
  assert.throws(() => setModelConfig({ provider: 'openai', key: 'k', baseUrl: '' }),
    /needs a base URL/);
});

test('an unknown provider is refused rather than silently ignored', () => {
  assert.throws(() => setModelConfig({ provider: 'ollama-direct', key: 'k' }), /must be one of/);
  assert.deepEqual(PROVIDERS, ['cli', 'anthropic', 'openai']);
});

test('the file is not world-readable', { skip: process.platform === 'win32'
  ? 'POSIX modes do not apply on NTFS' : false }, () => {
  setModelConfig({ provider: 'anthropic', key: 'k', model: 'm' });
  assert.equal(statSync(CONFIG_PATH).mode & 0o077, 0, 'group and other must have no access');
});

/*
  A config the server cannot parse must not take it down mid-exercise. The CLI
  path needs no configuration at all, so falling back to it is always safe.
*/
test('a corrupt config falls back to the CLI rather than throwing', () => {
  writeFileSync(CONFIG_PATH, '{ not json', 'utf8');
  assert.equal(modelConfig().provider, 'cli');
  assert.equal(modelSecret(), null);
});

test('an unknown provider in the file is read as the CLI', () => {
  writeFileSync(CONFIG_PATH, JSON.stringify({ provider: 'something-else', key: 'k' }), 'utf8');
  assert.equal(modelConfig().provider, 'cli');
});

test('the stored file holds the key, which is why it is under data/', () => {
  setModelConfig({ provider: 'anthropic', key: 'sk-on-disk', model: 'm' });
  assert.match(readFileSync(CONFIG_PATH, 'utf8'), /sk-on-disk/,
    'it is on disk by design; the protection is the location and the mode, not obscurity');
});

/*
  The configuration holds an API key, so it is written to one side and renamed
  into place rather than over itself: a crash or a full disk should leave the
  previous configuration, not half of one.

  The permissions have to be right on the temporary file, before the rename,
  because the rename is what makes it the real file — setting them afterwards
  leaves a window where the key is readable.
*/
test('the configuration is written atomically and leaves no readable temporary', () => {
  // The module resolved its path once, at load, from the env set at the top.
  const path = process.env.HUNT_MODEL_CONFIG;

  setModelConfig({ provider: 'anthropic', key: 'sk-not-a-real-key', model: 'claude-opus-5' });
  assert.equal(existsSync(path), true);
  assert.equal(existsSync(`${path}.tmp`), false, 'the temporary is renamed, not left behind');
  if (process.platform !== 'win32') assert.equal(statSync(path).mode & 0o777, 0o600);

  // A second write replaces it whole rather than appending or truncating.
  setModelConfig({ provider: 'anthropic', key: 'sk-also-not-real', model: 'claude-opus-5' });
  const body = readFileSync(path, 'utf8');
  assert.doesNotThrow(() => JSON.parse(body), `not valid on its own: ${body.slice(-60)}`);
  assert.equal(existsSync(`${path}.tmp`), false);
});
