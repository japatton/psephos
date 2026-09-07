import { test } from 'node:test';
import assert from 'node:assert';
import { readFile, readdir } from 'node:fs/promises';
import { join, extname, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SKIP = new Set(['node_modules', '.git', 'docs', 'test', 'data', 'web']);

async function* sourceFiles(dir = ROOT) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') || SKIP.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) yield* sourceFiles(full);
    else if (['.js', '.mjs'].includes(extname(entry.name))) yield full;
  }
}

/**
 * The application authenticates by shelling out to the CLI, which handles its
 * own credentials. If any module ever reads the credential file directly, the
 * whole security argument in the design collapses — so it is asserted, not
 * merely intended.
 */
test('no source file reads the Claude credential store', async () => {
  const needle = ['.credentials', 'json'].join('.');
  const hits = [];
  for await (const f of sourceFiles()) {
    if ((await readFile(f, 'utf8')).includes(needle)) hits.push(f.slice(ROOT.length + 1));
  }
  assert.deepEqual(hits, [], 'these files reference the credential store');
});

/*
  Asserted against the values the spawn receives, not against the text of the
  file that builds them.

  This used to grep runner.js for '--strict-mcp-config'. Deleting the flag from
  the args array left one occurrence behind — in a doc comment explaining what
  the flag does — so the test that exists to stop a LAN-spawned subprocess
  inheriting the operator's Gmail and Drive MCP servers passed with the flag
  gone. The same shape, and the same hole, for 'cwd: SESSION_CWD': pointing the
  session at '.' does not change that string.
*/
test('every Claude invocation is hardened', async () => {
  const { turnArgs, sessionCwd, TOOL_DENYLIST, toolsForMode } =
    await import('../claude/runner.js');

  for (const mode of ['evidence', 'research', 'characterization']) {
    const args = turnArgs({ mcpConfig: '/tmp/mcp.json', mode });

    assert.ok(args.includes('--strict-mcp-config'),
      `${mode} would inherit every MCP server on the operator's machine`);
    assert.ok(args.includes('--mcp-config'), 'our own MCP server must be configured');
    assert.ok(!args.includes('--bare'), '--bare breaks OAuth; see the comment in runner.js');

    // The denylist must reach the subprocess, not merely exist in the module.
    const denied = args[args.indexOf('--disallowedTools') + 1]?.split(',') ?? [];
    for (const tool of TOOL_DENYLIST) {
      assert.ok(denied.includes(tool), `${mode} left ${tool} enabled`);
    }
    const allowed = args[args.indexOf('--allowedTools') + 1]?.split(',') ?? [];
    assert.deepEqual(allowed, toolsForMode(mode), `${mode} was offered the wrong tools`);
  }

  /*
    CLAUDE.md discovery and the auto-memory namespace are both keyed to the
    working directory, so running in the server's own directory would pull the
    operator's project instructions and personal memory into a session any
    teammate on the LAN can start.
  */
  const cwd = sessionCwd();
  assert.notEqual(cwd, ROOT, 'the subprocess would inherit this repository as its project');
  assert.notEqual(cwd, process.cwd(), 'the subprocess must not run in the server directory');
  assert.match(cwd, /session-cwd$/, `a turn runs in ${cwd}`);
});

/**
 * The API-key backends exist for ranges with no Claude CLI and no route out,
 * so the application does now hold a credential. What that cost had to be
 * bounded to is written down in the design; these three tests are the bound.
 *
 * The ambient environment is not one of the ways in. Inheriting a key from
 * process.env would mean an operator's shell decides what a LAN-exposed server
 * authenticates as, with nothing in the UI to say so.
 */
test('no source file reads an API key from the environment', async () => {
  const access =
    /(process\.env\s*(\.|\[\s*['"])\s*(ANTHROPIC_API_KEY|OPENAI_API_KEY)|(ANTHROPIC|OPENAI)_API_KEY\s*[:=][^=])/;
  for await (const f of sourceFiles()) {
    const src = await readFile(f, 'utf8');
    assert.doesNotMatch(src, access, `${f.slice(ROOT.length + 1)} must not read an API key`);
  }
});

/**
 * Only the providers ask for the credential. Anything that can reach a
 * response body must use modelConfig(), which does not carry it.
 */
test('the credential is read in exactly the files that need it', async () => {
  const allowed = new Set(['store/model-config.js', 'claude/api-provider.js']);
  const hits = [];
  for await (const f of sourceFiles()) {
    const rel = f.slice(ROOT.length + 1).replaceAll('\\', '/');
    if (allowed.has(rel)) continue;
    if (/modelSecret\s*\(/.test(await readFile(f, 'utf8'))) hits.push(rel);
  }
  assert.deepEqual(hits, [], 'these files reach for the credential and should not');
});

/** The shape every caller gets. Whether it round-trips is model-config's test. */
test('the configuration handed to callers carries no credential', async () => {
  const { modelConfig } = await import('../store/model-config.js');
  assert.equal('key' in modelConfig(), false, 'modelConfig must never carry the key');
});

/** No route may serve the key, however it were to get hold of one. */
test('no route returns a model credential', async () => {
  const src = await readFile(join(ROOT, 'server', 'http.js'), 'utf8');
  assert.doesNotMatch(src, /modelSecret/, 'http.js must never touch the credential');
});


/*
  Brand colour never means a judgement.

  theme.css states the rule and its stakes: --accent and --brand are chrome
  only, "never used inside the map, the records table state column, or anywhere
  else a colour means a judgement", because at low saturation on a dark ground
  --brand at 330° and --bad at 4° are close enough to be misread — and the thing
  being misread is whether a host is compromised.

  It had drifted in one place. .p-alive-named coloured a presence value with
  brand cyan, in the host table one column from the verdict, which is precisely
  where the rule is written to hold. Stated here as a test because a rule that
  lives only in a comment is a rule that drifts again.
*/
test('no presence or verdict class is painted a brand colour', async () => {
  const css = await readFile(join(ROOT, 'web', 'theme.css'), 'utf8');
  const offenders = [];
  // Classes whose colour carries a judgement or an observation about a host.
  const judgement = /^\.(p-|v-|s-|conf-)[\w-]+\s*\{([^}]*)\}/gm;
  for (const [, prefix, body] of css.matchAll(judgement)) {
    if (/var\(--(accent|brand)\)/.test(body)) offenders.push(prefix + body.trim().slice(0, 40));
  }
  assert.deepEqual(offenders, [],
    'these carry a judgement and are painted in a brand hue, which theme.css forbids');
});
