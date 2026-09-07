/**
 * Which mission this server is running.
 *
 * A mission profile is a directory holding the four things specific to one
 * engagement and generic to none: the terrain, the plan seed, the roster, and
 * the mission's own name. They sit under missions/ rather than in the source
 * tree because a network map and a team list are not source, and the
 * repository gets pushed.
 *
 * The active profile is named in data/mission — runtime state, chosen once by
 * the setup wizard and never guessed. Guessing is the failure that matters
 * here: a server started against the wrong terrain would re-seed, find that
 * terrain no longer mentions 179 hosts, and take them off the map along with
 * every verdict recorded against them.
 */
import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

export const MISSIONS_DIR = resolve(process.env.HUNT_MISSIONS || join(HERE, '..', 'missions'));

/**
 * Which profile is selected. Runtime state, so it lives beside the store
 * rather than in the tree.
 *
 * Anchored to this module, not to the working directory, because the two are
 * a pair and the asymmetry was a bug: MISSIONS_DIR resolved absolutely while
 * this resolved against wherever the process happened to start. The MCP
 * subprocess runs in data/session-cwd, so it looked for
 * data/session-cwd/data/mission, found nothing, and told operators the server
 * had lost its mission — while still listing the profiles it could see,
 * because that half was absolute.
 */
export const POINTER = resolve(
  process.env.HUNT_MISSION_FILE || join(HERE, '..', 'data', 'mission'));

/** Every profile on disk, whether or not one is selected. */
export function listMissions() {
  if (!existsSync(MISSIONS_DIR)) return [];
  return readdirSync(MISSIONS_DIR, { withFileTypes: true })
    .filter(d => d.isDirectory() && existsSync(join(MISSIONS_DIR, d.name, 'mission.json')))
    .map(d => d.name)
    .sort();
}

/**
 * A profile name has to be safe to join onto a path.
 *
 * setActiveMission only ever writes a name that already exists on disk, and
 * the wizard validates before it creates one — but HUNT_MISSION comes from the
 * environment and data/mission is a plain text file someone can edit, and
 * neither was checked. Two lines here means no path built from a profile name
 * can leave the missions directory however it was set.
 */
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** The selected profile name, or null when nothing has been chosen yet. */
export function activeMissionName() {
  const fromEnv = (process.env.HUNT_MISSION ?? '').trim();
  if (fromEnv) return fromEnv;
  if (!existsSync(POINTER)) return null;
  const name = readFileSync(POINTER, 'utf8').trim();
  return name || null;
}

export function setActiveMission(name) {
  if (!listMissions().includes(name)) {
    throw new Error(`no mission profile called ${name} under ${MISSIONS_DIR}`);
  }
  mkdirSync(dirname(POINTER), { recursive: true });
  writeFileSync(POINTER, name + '\n', 'utf8');
  return name;
}

/**
 * Where the active profile lives.
 *
 * Refuses rather than falling back. A default would silently pick a profile
 * the operator did not choose, and the cost of being wrong is the map.
 */
export function missionDir(name = activeMissionName()) {
  if (!name) {
    const found = listMissions();
    throw new Error(
      'No mission selected. Start the server and follow the setup wizard, or set HUNT_MISSION.' +
      (found.length ? ` Profiles on disk: ${found.join(', ')}.` : ''));
  }
  if (!SAFE_NAME.test(name)) {
    throw new Error(
      `${JSON.stringify(name)} is not a usable mission name: letters, digits, dot, dash and ` +
      'underscore only.');
  }
  const dir = join(MISSIONS_DIR, name);
  if (!existsSync(join(dir, 'mission.json'))) {
    throw new Error(`mission profile ${name} has no mission.json at ${dir}`);
  }
  return dir;
}

/** The four files a profile is made of. Absence is the caller's to handle. */
export function missionPaths(name = activeMissionName()) {
  const dir = missionDir(name);
  return {
    dir,
    meta: join(dir, 'mission.json'),
    terrain: join(dir, 'terrain.json'),
    plan: join(dir, 'plan.json'),
    roster: join(dir, 'roster.json'),
    // Optional: an engagement that has not identified separate operators yet
    // simply has none.
    threads: join(dir, 'threads.json'),
  };
}

/** Strip a BOM: anything PowerShell or Notepad wrote carries one, and
 *  JSON.parse rejects it with a message that never mentions the BOM. */
export const readJson = (path) => JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));

/**
 * The mission's name, or a neutral stand-in.
 *
 * Never throws, because callers include text the model reads, and a tool
 * description is not worth failing a module load over. Anything that needs the
 * profile's files should use missionPaths and let it refuse.
 */
export function missionName() {
  try { return readMission().name; } catch { return 'this engagement'; }
}

export function readMission(name = activeMissionName()) {
  const m = readJson(missionPaths(name).meta);
  return { name: name ?? activeMissionName(), ...m };
}
