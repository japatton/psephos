/**
 * Standing a new mission up, from a browser, before the server has a mission.
 *
 * Everything here writes as it goes, one file per step, so a closed tab loses
 * at most the step in progress. Nothing takes effect until `finish` names the
 * profile in data/mission: until then the server is still in setup mode and
 * the store has been seeded with nothing.
 *
 * Authentication is the operator token, printed to the console at first start.
 * There is no roster yet, so there are no member tokens, and the console is
 * the out-of-band channel that proves who is at the keyboard.
 */
import { mkdirSync, writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  MISSIONS_DIR, listMissions, setActiveMission, missionPaths, readJson,
} from '../store/mission.js';
import { modelConfig, setModelConfig, PROVIDERS, DEFAULT_MODEL } from '../store/model-config.js';
import { probeProvider, complete } from '../claude/model.js';
import { terrainHosts } from '../terrain/load.js';
import { seedAll } from '../store/seed.js';

/** Directory names have to be safe to join onto a path. */
const SLUG = /^[a-z0-9][a-z0-9-]{1,40}$/;

export const slugify = (s) => String(s ?? '').toLowerCase()
  .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);

function dirFor(code) {
  if (!SLUG.test(code)) {
    // Naming the length matters: "x" is lower-case letters and digits and is
    // still refused, so a message that only lists the character classes reads
    // as a lie to whoever typed a one-letter name.
    throw new Error(
      'a mission code must be two or more lower-case letters, digits and dashes, '
      + 'starting with a letter or digit');
  }
  const dir = join(MISSIONS_DIR, code);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** The four files finish() insists on. A profile with all of them is somebody's
 *  finished engagement rather than a setup still in progress. */
const PROFILE_FILES = ['mission.json', 'roster.json', 'terrain.json', 'plan.json'];
const isFinished = (dir) => PROFILE_FILES.every(f => existsSync(join(dir, f)));

const write = (dir, file, obj) =>
  writeFileSync(join(dir, file), JSON.stringify(obj, null, 2) + '\n', 'utf8');

/**
 * What the wizard has so far.
 *
 * Returns the saved steps as well as which are done, so a reopened tab picks
 * up where it left off with the fields filled rather than showing blanks over
 * files that already exist. Setup happens once, often on a bad morning, and
 * losing four steps to a closed tab is how it gets abandoned half finished.
 */
export function setupState(code) {
  const cfg = modelConfig();
  const dir = code && SLUG.test(code) ? join(MISSIONS_DIR, code) : null;
  const at = (f) => (dir ? join(dir, f) : null);
  const has = (f) => Boolean(at(f) && existsSync(at(f)));
  const load = (f) => { try { return has(f) ? readJson(at(f)) : null; } catch { return null; } };

  return {
    model: cfg,
    providers: PROVIDERS,
    defaultModels: DEFAULT_MODEL,
    missions: listMissions(),
    code: code ?? null,
    mission: load('mission.json'),
    roster: load('roster.json'),
    done: {
      model: cfg.provider === 'cli' || cfg.hasKey,
      mission: has('mission.json'),
      roster: has('roster.json'),
      terrain: has('terrain.json'),
      plan: has('plan.json'),
    },
  };
}

// --- steps --------------------------------------------------------------------

export async function saveModel(body) {
  // Probe before saving. A backend that cannot answer is not accepted, because
  // finding out at the first evidence turn wastes an analyst's time.
  const probe = await probeProvider(body);
  if (!probe.ok) return { ok: false, probe };
  setModelConfig(body);
  return { ok: true, probe, model: modelConfig() };
}

export function saveMission({ code, name, week, briefing }) {
  const slug = slugify(code || name);
  const dir = dirFor(slug);
  /*
    Two engagements whose names slugify the same land on one directory, and
    writing mission.json over a finished profile renames somebody else's
    engagement in place. The next server started against it then seeds terrain
    the operator did not choose, which is the failure the mission pointer
    exists to prevent — so it is refused here rather than merged.

    Unfinished profiles are still writable: that is the operator's own half-done
    setup, and going back a step to fix a typo has to keep working.
  */
  if (isFinished(dir)) {
    throw new Error(
      `there is already a finished mission called ${slug}. Creating this one would `
      + 'overwrite it — pick a different name, or a different code.');
  }
  write(dir, 'mission.json', {
    name: String(name ?? '').trim() || slug,
    code: slug,
    week: String(week ?? '').trim(),
    briefing: (Array.isArray(briefing) ? briefing : String(briefing ?? '').split('\n'))
      .map(s => String(s).trim()).filter(Boolean),
  });
  return { code: slug };
}

export function saveRoster({ code, members }) {
  const dir = dirFor(code);
  const clean = (Array.isArray(members) ? members : [])
    .map(m => ({
      name: String(m.name ?? '').trim(),
      role: String(m.role ?? '').trim(),
      team: String(m.team ?? '').trim(),
    }))
    .filter(m => m.name);
  if (!clean.length) throw new Error('the roster needs at least one person');

  const seen = new Set();
  for (const m of clean) {
    const k = m.name.toLowerCase();
    // Members are keyed by name and chat attribution is by name, so two people
    // called the same thing would share a window.
    if (seen.has(k)) throw new Error(`two people called ${m.name}; names must be distinct`);
    seen.add(k);
  }
  write(dir, 'roster.json', { members: clean });
  return { members: clean.length };
}

/**
 * Write terrain, having checked it is terrain.
 *
 * `terrainHosts` is the same flattener the server uses, so anything that
 * survives this will survive boot. Validating here rather than at first start
 * means a malformed paste is a message in the wizard, not a server that will
 * not come up.
 */
export function saveTerrain({ code, terrain }) {
  const dir = dirFor(code);
  if (!terrain || !Array.isArray(terrain.enclaves)) {
    throw new Error('terrain needs an enclaves array');
  }
  let hosts;
  try {
    hosts = terrainHosts(terrain);
  } catch (e) {
    throw new Error(`that is not usable terrain: ${e.message}`);
  }
  write(dir, 'terrain.json', terrain);
  return { enclaves: terrain.enclaves.length, hosts: hosts.length };
}

/** An estate with no inventory at all. The map then grows from evidence alone. */
export function saveEmptyTerrain({ code }) {
  return saveTerrain({
    code,
    terrain: {
      source: 'No inventory supplied at setup. Hosts appear as evidence names them.',
      vantages: [],
      enclaves: [{
        key: 'unmapped', name: 'Unmapped', cidr: '',
        description: 'Hosts discovered from evidence',
        segments: [{ name: 'discovered', cidr: '', note: '', hosts: [] }],
      }],
    },
  });
}

export async function savePlan({ code, plan, from }) {
  const dir = dirFor(code);

  /*
    The CPT doctrinal frame: M0 preparation, M1 network/host/vulnerability
    characterisation, M2 hunting, M3 response, M4 handover, with tactical
    objectives and MOEs on each phase. Imported lazily because it is 900 lines
    that only this branch needs.
  */
  if (from === 'doctrine') {
    const { addMissionPhases } = await import('../plans/mission-phases.mjs');
    const built = addMissionPhases({
      plan: {
        name: 'Hunt plan',
        intent: 'Doctrinal frame. Phases and tactical tasks are the starting structure; '
          + 'the terrain each task names is a category to fill in with your own hosts.',
      },
      phases: [],
    });
    write(dir, 'plan.json', built);
    return { tasks: built.phases.flatMap(x => x.tasks ?? []).length };
  }

  if (from === 'example') {
    copyFileSync(join(MISSIONS_DIR, 'example', 'plan.json'), join(dir, 'plan.json'));
    const p = readJson(join(dir, 'plan.json'));
    return { tasks: p.phases.flatMap(x => x.tasks ?? []).length };
  }
  if (from === 'empty') {
    write(dir, 'plan.json', { plan: { name: 'Hunt plan', intent: '' }, phases: [] });
    return { tasks: 0 };
  }
  if (!plan || !Array.isArray(plan.phases)) throw new Error('a plan needs a phases array');
  write(dir, 'plan.json', plan);
  return { tasks: plan.phases.flatMap(x => x.tasks ?? []).length };
}

/**
 * Select the profile and seed the store, in this process.
 *
 * Checks every file is present first. Half a profile would take the server
 * down on the next restart, and the wizard is the last place that has enough
 * context to say which piece is missing.
 */
export function finish({ code, db }) {
  const dir = dirFor(code);
  for (const f of ['mission.json', 'roster.json', 'terrain.json', 'plan.json']) {
    if (!existsSync(join(dir, f))) throw new Error(`${code} has no ${f}; that step is not done`);
  }
  setActiveMission(code);
  const out = seedAll(db);
  return { code, members: out.newMembers, tasks: out.plan.imported };
}

// --- model-assisted terrain -----------------------------------------------------

const TERRAIN_SYSTEM = `You convert a network inventory into one JSON object. Reply with JSON only,
no prose and no code fence.

Shape:
{"source":"<where this came from>","vantages":[],"enclaves":[
  {"key":"<lower_snake>","name":"<display>","cidr":"<or empty>","description":"","segments":[
    {"name":"<segment>","cidr":"<or empty>","note":"","hosts":[
      {"name":"<hostname or the address>","ip":"<dotted quad or empty>","os":"","role":"",
       "kind":"win|nix|net|other","source":"inventory"}]}]}]}

Rules:
- Every host in the input appears exactly once in the output. Do not summarise,
  sample, or collapse ranges into one entry. Dropping a host means it is absent
  from the map for the whole engagement.
- Two hosts at the same address are both kept. That is the inventory's own
  ambiguity to show, not yours to resolve.
- Group into enclaves and segments as the input does. If it does not, put
  everything in one enclave and split segments by /24.
- Leave a field empty rather than inventing it. An empty os is honest; a
  guessed one is a fact the team will act on.`;

/**
 * Turn whatever the operator pasted into terrain.
 *
 * A parser per input format is work without end — this mission's inventory was
 * HTML, the next will be a spreadsheet or nmap XML — and reading an arbitrary
 * dump into a known schema is the job characterization already does well. The
 * safeguard is the same: return counts, let the operator reject, write nothing
 * until they accept.
 */
export async function structureTerrain({ text }) {
  const src = String(text ?? '').trim();
  if (!src) throw new Error('nothing to read');

  const reply = await complete(src, { system: TERRAIN_SYSTEM });
  const terrain = parseJsonReply(reply);
  if (!terrain || !Array.isArray(terrain.enclaves)) {
    throw new Error('the model did not return terrain. Try again, or upload a terrain.json.');
  }

  const hosts = terrainHosts(terrain);
  return {
    terrain,
    enclaves: terrain.enclaves.map(e => ({
      name: e.name || e.key,
      segments: (e.segments ?? []).map(s => ({ name: s.name, hosts: (s.hosts ?? []).length })),
    })),
    hosts: hosts.length,
    // The operator is the check on whether anything was dropped, so give them
    // the number to compare against rather than a reassurance.
    sourceLines: src.split('\n').filter(l => l.trim()).length,
  };
}

/** Models wrap JSON in fences and prose however firmly they are told not to. */
export function parseJsonReply(reply) {
  const s = String(reply ?? '');
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(s);
  const body = fenced ? fenced[1] : s;
  const start = body.indexOf('{');
  const end = body.lastIndexOf('}');
  if (start < 0 || end <= start) return null;
  try { return JSON.parse(body.slice(start, end + 1)); } catch { return null; }
}

export { missionPaths };
