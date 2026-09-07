/**
 * Bringing a store up to match the active mission profile.
 *
 * Named seedAll rather than bootstrap because server/http.js already has a
 * `bootstrap` that builds the client's opening state, and one word meaning two
 * things in one codebase is a trap.
 *
 * Extracted from bin/serve.js because the setup wizard has to run exactly the
 * same sequence when it finishes, in the same process. A wizard that wrote the
 * profile and then told the operator to restart would be asking them to
 * remember a step at the one moment they know least about the system.
 *
 * Every part is idempotent: seeding twice changes nothing, existing members
 * keep their tokens, and an existing live plan is never overwritten.
 */
import { seedThreads } from './threads.js';
import { seedHosts } from './hosts.js';
import { seedMembers, listMembers } from './members.js';
import { ensureMemberSessions } from './sessions.js';
import { importPlan } from './plan.js';
import { ensureLivePlan, LIVE_PLAN } from './plan-file.js';
import { ensureTeamChannel } from './chat.js';

export function seedAll(db) {
  seedThreads(db);
  const terrain = seedHosts(db);
  const newMembers = seedMembers(db);
  const newSessions = ensureMemberSessions(db, listMembers(db));
  const seeded = ensureLivePlan();
  const plan = importPlan(db, LIVE_PLAN);
  ensureTeamChannel(db);

  /*
    A turn is a child process, so none survived whatever stopped the last run.
    A session still marked 'running' is a corpse, and the message route refuses
    to start a turn while one is running — leaving it would lock that member
    out of their own window with no way back through the UI.
  */
  const stale = db.prepare("update sessions set state = 'open' where state = 'running'").run();

  return { terrain, newMembers, newSessions, seeded, plan, stale: stale.changes };
}
