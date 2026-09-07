/**
 * Tests run against the committed example profile, never against whatever
 * mission the operator happens to have active. A suite whose result depends on
 * which exercise is loaded is not a suite.
 *
 * Loaded via --import, so it runs before any test module reads the env.
 */
import { mkdtempSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

process.env.HUNT_MISSION = 'example';

/**
 * Same principle, for the live plan: left unset, HUNT_PLAN defaults to
 * data/plan.json at the repo root — the operator's real hunt plan, not a
 * fixture. A suite that depends on the active mission gives a wrong
 * assertion; a suite that writes to the live plan leaves fake tasks in a
 * real engagement's plan the next time someone runs `npm test` during a real
 * hunt. The second failure is strictly worse, and every future
 * plan-mutating route inherits it for free unless the fixture is fixed here
 * rather than in whichever test happens to exercise that route first.
 *
 * The fixture is written by hand with plain fs, not via store/plan-file.js's
 * ensureLivePlan(). That function is reached through store/mission.js, whose
 * own MISSIONS_DIR and POINTER are just as module-level-const-at-import-time
 * as LIVE_PLAN — and test/setup.test.js needs to be the one to set HUNT_MISSIONS
 * and HUNT_MISSION_FILE before mission.js is first loaded, to point setup mode
 * at its own scratch profile directory. Importing plan-file.js from here would
 * load mission.js first, on this file's env, and setup.test.js's later
 * assignment would then be too late to matter. Writing the fixture directly
 * needs nothing from either module, so it can run first without pre-empting
 * anyone else's env.
 *
 * What gets written there is a copy of missions/example/plan.json, not a
 * hand-rolled stub. Tests read HUNT_PLAN long before this file existed as a
 * fixture — it used to resolve to data/plan.json, itself seeded from the
 * example profile — and a suite like views-smoke.test.js seeds the live plan
 * on the assumption that doing so gives every view real phases and tasks to
 * draw. A stub thinner than that (say, one phase with no tasks) still
 * satisfies every assertion keyed on "the seed ran", while silently emptying
 * out everything downstream of it: phase headers, task rows, steps, the
 * add-task affordances. The suite would keep passing and prove less than it
 * did before this fixture existed. Copying the real example plan keeps the
 * fixture's shape identical to what tests already relied on, off the live
 * file.
 */
process.env.HUNT_PLAN = join(mkdtempSync(join(tmpdir(), 'hunt-plan-test-')), 'plan.json');
copyFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'missions', 'example', 'plan.json'),
  process.env.HUNT_PLAN,
);
