import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve, extname, normalize } from 'node:path';

import { checkAuth, sameToken } from './auth.js';
import { addClient, broadcast } from './sse.js';
import { listThreads } from '../store/threads.js';
import {
  listHosts, setVerdict, VERDICTS, setHostOverride, hostOverrides, OVERRIDABLE,
  archiveHost, restoreHost, withdrawnHosts, listArchivedHosts,
  mergeHosts, createHost, removeHost, hostEvidence, getHost,
} from '../store/hosts.js';
import {
  listRecords, getRecord, updateRecord, promoteRecord, denyRecord, derivedConnections, createRecord,
  bindRecordHost, archiveRecord, restoreRecord, listArchivedRecords, searchRecords,
  listRecordSummaries, evidenceByHost, recordsForHost, unplacedRecords,
  recordCounts } from '../store/records.js';
import { listEdges, confirmEdge, denyEdge, proposeEdge } from '../store/edges.js';
import {
  createSession, listSessions, getSession, listMessages, appendMessage, setState,
} from '../store/sessions.js';
import { listAudit } from '../store/audit.js';
import {
  listNotifications, unreadCount, markRead as markNotificationRead, markAllRead,
} from '../store/notifications.js';
import {
  listPlan, getTask, setTaskStatus, setAssignees, listTaskEvents, listRecentEvents, planSummary,
  importPlan, logPlanEvent,
} from '../store/plan.js';
import {
  LIVE_PLAN, readPlan, writePlan, addTask, editTask, addPhase, editPhase, phaseKeyOf, addTaskFromBank,
} from '../store/plan-file.js';
import { listBank, getBankEntry } from '../store/bank.js';
import { planCoverage } from '../store/coverage.js';
import { listMembers, memberByToken, seedMembers } from '../store/members.js';
import {
  ensureTeamChannel, createChannel, listChannels, canSee, isOpenChannel, canReadFile,
  postMessage, listMessages as listChat, markRead, listMentions,
} from '../store/chat.js';
import { saveFile, getFileMeta, getFileBody, fileAsPromptText, MAX_FILE_BYTES } from '../store/files.js';
import { ensureMemberSessions, sessionForMember } from '../store/sessions.js';
import { recordsToCsv } from '../export/csv.js';
import { recordsToNavigatorLayer } from '../export/navigator.js';
import { recordsToMispEvent, recordsToStixBundle, listIndicators } from '../export/iocs.js';
import { usageBySession, usageByMember, usageTotal } from '../store/usage.js';
import { buildReport } from '../export/report.js';
import { readMission } from '../store/mission.js';
import { recordsToXlsx } from '../export/xlsx.js';
import { loadTerrain } from '../terrain/load.js';
import {
  summary as charSummary, repoView, listSnapshots, getEntity, countRows, isRepo,
  listCharSnapshots, createCharSnapshot, setSnapshotComplete, setHostStatus,
  setFieldGaps, fieldGapsFor, allFieldGaps, hostCharacterization,
  stagedPreview, commitStaged, discardStaged, reattributeStaged,
  correctEntity, reattributeEntity, moveEntity,
} from '../store/characterization.js';
import { runTurn } from '../claude/model.js';
import {
  setupState, saveModel, saveMission, saveRoster, saveTerrain, saveEmptyTerrain,
  savePlan, finish as finishSetup, structureTerrain,
} from './setup.js';

const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'web');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  /*
    Added with the logo. Without them these fall to the octet-stream default
    below, and a favicon served as a download is simply not shown — the kind of
    failure that looks like a caching problem for a week.
  */
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
};

const json = (res, status, body) => {
  // 204 means there is no body; declaring four bytes of "null" alongside it is
  // a framing violation a strict intermediary may treat as a bad message.
  if (status === 204) { res.writeHead(204); return res.end(); }
  const s = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(s) });
  res.end(s);
};

/*
  A refusal the store already diagnosed.

  These routes call functions that throw a precise "no such record: …" or
  "unknown status: donezo", and having no catch of their own they fell through
  to the top-level handler — which cannot tell a broken server from a bad id,
  so it answered 500 and logged a stack trace to the operator's console for
  what was an ordinary mistyped request. The message was already right; only
  the status and the noise were wrong.
*/
const storeFault = (res, e) =>
  json(res, /^no such /.test(e.message) ? 404 : 400, { error: e.message });

/** 401 carries no body: an unauthenticated caller learns nothing, not even that a store exists. */
const unauthorized = (res) => { res.writeHead(401, { 'content-length': 0 }); res.end(); };

/**
 * An error that already knows what status it deserves.
 *
 * Without this, "your paste is too big" and "that JSON is malformed" both
 * arrived as a 500, which tells an analyst the server broke when in fact their
 * input was refused — and those are opposite next actions.
 */
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function readJsonBody(req, limit = 1_000_000, advice = 'Attach it as a file instead, or split it.') {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > limit) {
      throw new HttpError(413,
        `that is larger than the ${Math.round(limit / 1_000_000)}MB this endpoint accepts. ${advice}`);
    }
    chunks.push(c);
  }
  if (size === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch (e) {
    throw new HttpError(400, `the request body is not valid JSON: ${e.message}`);
  }
}

async function readBinaryBody(req, limit) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > limit) {
      throw new HttpError(413, `that file is larger than the ${Math.round(limit / 1048576)}MB limit.`);
    }
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

/**
 * Bounds how fast one analyst can spawn Claude turns. The store is LAN-exposed
 * and every turn spends the operator's quota, so this is a cost control as much
 * as an abuse control.
 */
function makeRateLimiter({ windowMs = 60_000, max = 20 } = {}) {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    const recent = (hits.get(key) ?? []).filter(t => now - t < windowMs);
    if (recent.length >= max) return false;
    recent.push(now);
    hits.set(key, recent);
    return true;
  };
}

/**
 * Read-modify-write the live plan, then re-derive the database from it.
 *
 * The mutator runs against the in-memory plan and throws on anything invalid,
 * so a rejected edit never reaches the disk. Node's single thread makes the
 * whole sequence atomic with respect to other requests — two analysts saving
 * at the same instant queue rather than interleave.
 */
function commitPlan(db, mutate) {
  const plan = readPlan(LIVE_PLAN);
  const result = mutate(plan);
  writePlan(plan, LIVE_PLAN);
  importPlan(db, LIVE_PLAN);
  return result;
}

function bootstrap(db) {
  return {
    threads: listThreads(db),
    hosts: listHosts(db),
    /*
      No records at all.

      Every view that draws them now asks for what it needs: the map for one
      count per host, the timeline for a window, the rails for their own queries,
      the drawer for one host or one finding. What is left here is bounded by the
      estate and the roster rather than by the case file, so this payload stops
      growing as the engagement does.

      state.records survives on the client as a cache of what that browser has
      actually seen — deltas upsert into it and the drawer reads it — which is a
      different thing from a copy of the case file and is allowed to be partial.
    */
    edges: listEdges(db),
    connections: derivedConnections(db),
    sessions: listSessions(db),
    // Tokens are never sent to the browser: knowing one is how you become
    // that person, and the roster is visible to everybody.
    members: listMembers(db).map(({ token: _t, ...m }) => m),
  };
}

async function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? '/index.html' : pathname;
  const target = resolve(join(WEB_ROOT, normalize(rel).replace(/^([/\\])+/, '')));
  if (!target.startsWith(WEB_ROOT)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(target);
    res.writeHead(200, {
      'content-type': MIME[extname(target)] ?? 'application/octet-stream',
      'cache-control': 'no-cache',
    });
    res.end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
  }
}

/**
 * @param runtime  mutable, because setup flips it. Once the wizard finishes,
 *                 the same process has to start serving the real application
 *                 without a restart — asking an operator to remember one at
 *                 the moment they know least about the system is how a setup
 *                 gets abandoned half done.
 */
export function createServer({ db, token, runtime = { setup: false } }) {
  const spawnLimit = makeRateLimiter();
  /*
    Sign-in attempts, keyed on the caller rather than on the token they tried.

    A member token is eight characters, and what it gates is posting as that
    person and reading their direct messages. Unlimited guesses also means
    unlimited timing samples against the operator token, which is the thing
    that makes the constant-time comparison below worth having at all.
  */
  const loginLimit = makeRateLimiter({ windowMs: 60_000, max: 10 });

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const { pathname } = url;
    const method = req.method ?? 'GET';

    try {
      // Static assets are behind the token too — the shell reveals structure.
      const auth = checkAuth(req, token, db, memberByToken);

      // The login page is the one unauthenticated route: it takes the token
      // and sets it as a cookie so EventSource can authenticate.
      if (pathname === '/login' && method === 'GET') {
        return serveStatic(req, res, '/login.html');
      }
      /*
        And its stylesheet, because the login page links it and everything else
        unauthenticated is answered with the login page — so the sheet came back
        as HTML, the browser refused it, and the one screen a new analyst sees
        rendered unstyled. It looks like a broken server at the moment they know
        least about this one.

        The same goes for the mark and the icons, which the sign-in page and the
        browser tab both ask for before anyone has a token.

        This list, and not the rest of web/: a palette, a logo and a favicon are
        the things already printed on the outside of the box. The structure the
        rule above protects is the shell and the views, and none of that is
        reachable from here.
      */
      const PUBLIC_ASSETS = new Set([
        '/theme.css', '/mark.png', '/favicon.png', '/apple-touch-icon.png',
      ]);
      if (PUBLIC_ASSETS.has(pathname) && method === 'GET') {
        return serveStatic(req, res, pathname);
      }
      if (pathname === '/api/login' && method === 'POST') {
        // Before reading the body: a rejected attempt should cost the caller
        // more than it costs the server.
        const from = req.socket.remoteAddress ?? 'unknown';
        if (!loginLimit(from)) {
          res.writeHead(429, { 'content-length': 0, 'retry-after': '60' });
          return res.end();
        }
        const body = await readJsonBody(req);
        const supplied = String(body.token ?? '').trim();
        const member = memberByToken(db, supplied);
        /*
          Constant-time, the same as checkAuth. This compared with !== and was
          the one place the operator credential was checked byte by byte with
          an early exit — the careful primitive next door and the careless one
          on the path anybody can reach unauthenticated.
        */
        if (!member && !sameToken(supplied, token)) return unauthorized(res);
        // The token says who you are, so nobody types their own name and
        // nobody mistypes a colleague's. The operator token is always
        // 'operator' — checkAuth no longer trusts this cookie for identity, so
        // letting it carry a member's name here would only mislead the UI.
        body.analyst = member ? member.name : 'operator';
        // Lax, not Strict: Strict withholds the cookie on ordinary top-level
        // navigation (bookmarks, a link from another tool), which locks the
        // analyst out of their own server. Lax still withholds it from
        // cross-site POSTs, which is the CSRF case that actually matters here.
        const cookie = [
          `hunt_token=${encodeURIComponent(supplied)}; Path=/; SameSite=Lax; Max-Age=2592000`,
          `hunt_analyst=${encodeURIComponent(body.analyst || 'unattributed')}; Path=/; SameSite=Lax; Max-Age=2592000`,
        ];
        res.writeHead(204, { 'set-cookie': cookie });
        return res.end();
      }

      if (pathname === '/api/logout' && method === 'POST') {
        // Expire both cookies. Without this there is no way to change identity
        // from the UI at all, which strands anyone who signed in with the
        // operator token and then wonders why every window is read-only.
        res.writeHead(204, {
          'set-cookie': [
            'hunt_token=; Path=/; SameSite=Lax; Max-Age=0',
            'hunt_analyst=; Path=/; SameSite=Lax; Max-Age=0',
          ],
        });
        return res.end();
      }

      if (!auth.ok) {
        if (pathname.startsWith('/api/')) return unauthorized(res);
        return serveStatic(req, res, '/login.html');
      }
      const who = auth.analyst;

      let m;

      /*
        Setup mode. No mission is selected, so the store has been seeded with
        nothing and every ordinary route would answer about an estate that does
        not exist. Serve the wizard and say plainly that the rest is not ready.
      */
      if (runtime.setup) {
        /*
          The operator token, and only it.

          setup.js says so in its header and nothing enforced it: the gate above
          is satisfied by any member token. The reasoning was "there is no
          roster yet, so there are no member tokens" — true of a fresh install,
          and not of the case that matters. Setup mode is keyed on the mission
          pointer while the roster lives in the store, so a database restored
          from a backup, or a lost data/mission, brings the server up in setup
          mode over a full roster and a full case file. An analyst could then
          repoint the model backend at a server of their choosing, after which
          every turn posts the whole case-file prompt to it.
        */
        if (auth.member) {
          return json(res, 403, { error: 'setup needs the operator token, not a team token' });
        }
        if (pathname === '/api/setup/state' && method === 'GET') {
          return json(res, 200, setupState(url.searchParams.get('code')));
        }
        if (pathname.startsWith('/api/setup/') && method === 'POST') {
          /*
            The same ceiling the turn endpoints have, and advice that can be
            taken. The wizard reads the operator's terrain.json in the browser
            and re-posts it as JSON, and the structure step exists to take a
            pasted inventory dump — so this WAS the attach-it-as-a-file path,
            and a large estate dead-ended on a 413 telling the operator to do
            the thing they had just done.
          */
          const b = await readJsonBody(req, 4_000_000,
            'Split the inventory and run the step twice, or import it after setup from the Network Map.');
          try {
            switch (pathname) {
              case '/api/setup/model':     return json(res, 200, await saveModel(b));
              case '/api/setup/mission':   return json(res, 200, saveMission(b));
              case '/api/setup/roster':    return json(res, 200, saveRoster(b));
              case '/api/setup/terrain':   return json(res, 200, saveTerrain(b));
              case '/api/setup/terrain/empty':     return json(res, 200, saveEmptyTerrain(b));
              case '/api/setup/terrain/structure': return json(res, 200, await structureTerrain(b));
              case '/api/setup/plan':      return json(res, 200, await savePlan(b));
              case '/api/setup/finish': {
                const out = finishSetup({ code: b.code, db });
                runtime.setup = false;   // the application is live from here
                return json(res, 200, out);
              }
              default: return json(res, 404, { error: 'no such setup step' });
            }
          } catch (e) { return json(res, 400, { error: e.message }); }
        }
        if (pathname.startsWith('/api/')) {
          return json(res, 503, { error: 'this server has no mission yet', setup: true });
        }
        if (pathname === '/theme.css' || pathname === '/setup.js') {
          return serveStatic(req, res, pathname);
        }
        return serveStatic(req, res, '/setup.html');
      }

      // --- state and stream ------------------------------------------------
      if (pathname === '/api/state' && method === 'GET') return json(res, 200, bootstrap(db));
      if (pathname === '/api/terrain' && method === 'GET') return json(res, 200, loadTerrain());
      if (pathname === '/api/audit' && method === 'GET') {
        return json(res, 200, listAudit(db, { targetId: url.searchParams.get('target') ?? undefined }));
      }
      /*
        Where the quota went. Visible to everyone, deliberately: it is one
        shared allowance and the person who can act on "we are nearly out" is
        whoever is about to start the next turn.
      */
      if (pathname === '/api/usage' && method === 'GET') {
        return json(res, 200, {
          total: usageTotal(db),
          byMember: usageByMember(db),
          bySession: usageBySession(db),
        });
      }
      if (pathname === '/api/events' && method === 'GET') return addClient(res);

      // --- hunt plan ---------------------------------------------------------
      /*
        Recent activity across the whole plan. No view asks for it yet — the
        plan renders per-task history instead — but the store function is
        tested and this is the one endpoint that answers "what has the team
        been doing", so it stays until something either uses it or replaces it.
      */
      if (pathname === '/api/plan/events' && method === 'GET') {
        return json(res, 200, listRecentEvents(db, 200));
      }
      if (pathname === '/api/plan' && method === 'GET') {
        return json(res, 200, { tasks: listPlan(db), summary: planSummary(db) });
      }

      /*
        The catalogue. Read-only: the bank is files in the repository and is not
        edited through the application, which is what keeps a plan's copy of an
        entry stable while somebody improves the original.
      */
      if (pathname === '/api/bank' && method === 'GET') {
        const p = url.searchParams;
        // domain is a raw query parameter; listBank throws UnknownDomainError
        // for anything outside its allow-list rather than handing it to a file
        // read, so this is a 400 naming what is valid, not a 500 leaking a path.
        try {
          return json(res, 200, listBank({
            domain: p.get('domain') || 'enterprise',
            tactic: p.get('tactic') || null,
            q: p.get('q') ?? '',
          }));
        } catch (e) { return json(res, 400, { error: e.message }); }
      }

      /* What the plan intends to hunt, against the matrix. Same domain validation as above. */
      if (pathname === '/api/plan/coverage' && method === 'GET') {
        try {
          return json(res, 200, planCoverage(db, url.searchParams.get('domain') || 'enterprise'));
        } catch (e) { return json(res, 400, { error: e.message }); }
      }

      /*
        Drawing an entry into the plan. Through commitPlan like every other plan
        edit: the file is written and the database re-derived from it, so the
        task survives the next restart.
      */
      if (pathname === '/api/plan/task/from-bank' && method === 'POST') {
        const b = await readJsonBody(req);
        const entry = getBankEntry(String(b.bankId ?? ''));
        if (!entry) return json(res, 404, { error: 'no such bank entry' });
        try {
          const t = commitPlan(db, (plan) =>
            // Not a hardcoded 'P1': a plan built from the example or an upload
            // need not have one, and the client derives the first phase for the
            // same reason (web/views/plan.js's phaseForNewTasks). An empty plan
            // falls through to addTask's own "no such phase" instead of a guess.
            addTaskFromBank(plan, entry, {
              phaseKey: String(b.phaseKey ?? plan.phases[0]?.key ?? ''),
              actor: who,
            }));
          logPlanEvent(db, t.key, who, 'create', JSON.stringify({ title: t.title, bankId: entry.id }));
          broadcast('plan.changed', planSummary(db));
          return json(res, 201, getTask(db, t.key));
        } catch (e) { return json(res, 400, { error: e.message }); }
      }

      if ((m = pathname.match(/^\/api\/plan\/task\/([\w.:-]+)$/)) && method === 'GET') {
        const t = getTask(db, decodeURIComponent(m[1]));
        if (!t) return json(res, 404, { error: 'no such task' });
        return json(res, 200, { ...t, events: listTaskEvents(db, t.taskKey) });
      }
      if ((m = pathname.match(/^\/api\/plan\/task\/([\w.:-]+)\/status$/)) && method === 'PATCH') {
        const { status, note } = await readJsonBody(req);
        // No guard on who may complete or reset. The team asked for that
        // explicitly; the event log is what makes it accountable instead.
        try {
          const t = setTaskStatus(db, decodeURIComponent(m[1]), status, who, note ?? null);
          broadcast('plan.task', t);
          return json(res, 200, t);
        } catch (e) { return storeFault(res, e); }
      }
      if ((m = pathname.match(/^\/api\/plan\/task\/([\w.:-]+)\/assign$/)) && method === 'PATCH') {
        const { assignees } = await readJsonBody(req);
        const roster = new Set(listMembers(db).map(x => x.name));
        const bad = (assignees ?? []).filter(a => !roster.has(a));
        if (bad.length) return json(res, 400, { error: `not on the roster: ${bad.join(', ')}` });
        let t;
        try { t = setAssignees(db, decodeURIComponent(m[1]), assignees ?? [], who); }
        catch (e) { return storeFault(res, e); }
        broadcast('plan.task', t);
        /*
          Deliberately payload-free. Who was notified and what it said stay out
          of the broadcast — a mention inside a DM would otherwise be delivered
          to every open browser on the LAN. Each client re-reads its own inbox.
        */
        broadcast('notification.new', null);
        return json(res, 200, t);
      }


      /*
        Plan authoring. Every mutation is the same shape: read the live plan
        file, change it in memory, write it atomically, then re-derive the
        database from it. The file stays the single authority — the database
        is never written directly, so the two cannot drift, and an edit
        survives the restart that would otherwise wipe it.
      */
      if (pathname === '/api/plan/task' && method === 'POST') {
        const b = await readJsonBody(req);
        try {
          const t = commitPlan(db, (plan) => addTask(plan, { ...b, actor: who }));
          logPlanEvent(db, t.key, who, 'create', JSON.stringify({ title: t.title, phase: b.phaseKey }));
          broadcast('plan.changed', planSummary(db));
          return json(res, 201, getTask(db, t.key));
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      if ((m = pathname.match(/^\/api\/plan\/task\/([\w.:-]+)$/)) && method === 'PATCH') {
        const key = decodeURIComponent(m[1]);
        const b = await readJsonBody(req);
        try {
          const before = getTask(db, key);
          if (!before) return json(res, 404, { error: 'no such task' });
          const t = commitPlan(db, (plan) => editTask(plan, key, { ...b, actor: who }));
          const changed = Object.keys(b).filter(k => k !== 'actor');
          logPlanEvent(db, key, who, 'edit', JSON.stringify({ fields: changed }));
          broadcast('plan.task', getTask(db, t.key));
          broadcast('plan.changed', planSummary(db));
          return json(res, 200, getTask(db, t.key));
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      if (pathname === '/api/plan/phase' && method === 'POST') {
        const b = await readJsonBody(req);
        try {
          const p = commitPlan(db, (plan) => addPhase(plan, { ...b, actor: who }));
          broadcast('plan.changed', planSummary(db));
          return json(res, 201, p);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      if ((m = pathname.match(/^\/api\/plan\/phase\/([\w.:-]+)$/)) && method === 'PATCH') {
        const b = await readJsonBody(req);
        try {
          const p = commitPlan(db, (plan) => editPhase(plan, decodeURIComponent(m[1]), { ...b, actor: who }));
          broadcast('plan.changed', planSummary(db));
          return json(res, 200, p);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }

      // --- characterization ----------------------------------------------------
      if (pathname === '/api/characterization' && method === 'GET') {
        return json(res, 200, charSummary(db));
      }
      // Collection runs. The analyst picks one in the composer; uploads append
      // to it, so a paged collection stays one picture of one moment.
      /*
        Import. The panel posts here, a characterization turn extracts into
        staged uploads, and nothing is visible to a baseline until the analyst
        has seen the preview and committed. All three silent failures this
        replaces would have been caught at that step.
      */
      if (pathname === '/api/characterization/import' && method === 'POST') {
        if (!spawnLimit(who)) return json(res, 429, { error: 'too many turns; wait a moment' });
        const b = await readJsonBody(req, 4_000_000);
        const text = String(b.text ?? '');
        const fileIds = Array.isArray(b.fileIds) ? b.fileIds.slice(0, 5) : [];
        if (!text.trim() && !fileIds.length) return json(res, 400, { error: 'nothing to import' });

        const session = auth.member ? sessionForMember(db, auth.member.id) : null;
        if (!session) {
          return json(res, 403, { error: 'importing needs your own team token, not the operator token' });
        }
        if (getSession(db, session.id).state === 'running') {
          return json(res, 409, { error: 'Claude is still working on your last message.' });
        }

        let body = text;
        const attached = [];
        for (const fid of fileIds) {
          const meta = getFileMeta(db, fid);
          // An id you cannot read is an id you cannot attach: inlining puts the
          // whole text into a transcript, which is a second way to read it.
          if (!meta || !canReadFile(db, fid, who)) continue;
          attached.push(meta);
          body += (body ? '\n\n' : '') + fileAsPromptText(db, fid);
        }

        broadcast('session.state', setState(db, session.id, 'running'));
        const msg = appendMessage(db, session.id, 'user', body, 'characterization');
        broadcast('session.message', { sessionId: session.id, message: msg });
        json(res, 202, { accepted: true, sessionId: session.id });

        runTurn(db, session.id, body, {
          analyst: who, mode: 'characterization',
          char: {
            // Declared by the tab, not inferred by the model.
            repo: String(b.repo ?? '').trim() || null,
            host: String(b.host ?? '').trim() || null,
            countedRows: countRows(body),
            fileId: attached[0]?.id ?? null,
            snapshotId: String(b.snapshotId ?? '').trim() || null,
            staged: true,
          },
        }).catch(err => {
          const m = appendMessage(db, session.id, 'system', `Import failed: ${err.message}`);
          setState(db, session.id, 'error');
          broadcast('session.message', { sessionId: session.id, message: m });
          broadcast('session.state', getSession(db, session.id));
        });
        return;
      }
      // Corrections. Narrow on purpose: a baseline is what was observed, and
      // every one of these keeps the collected value and writes to the audit.
      if ((m = pathname.match(/^\/api\/characterization\/entity\/([\w-]+)\/(correct|reattribute|move)$/))
          && method === 'POST') {
        const b = await readJsonBody(req);
        const fn = { correct: correctEntity, reattribute: reattributeEntity, move: moveEntity }[m[2]];
        try {
          const e = fn(db, m[1], { ...b, actor: who });
          broadcast('characterization.changed', charSummary(db));
          return json(res, 200, e);
        } catch (err2) { return json(res, 400, { error: err2.message }); }
      }
      /*
        Everything collected from one host, for the drawer on the map. A query
        parameter rather than a path segment because a host is often an address
        and sometimes an FQDN, and neither belongs in a route pattern.
      */
      if (pathname === '/api/characterization/host' && method === 'GET') {
        return json(res, 200, hostCharacterization(db, url.searchParams.get('name') ?? ''));
      }
      if (pathname === '/api/characterization/staged' && method === 'GET') {
        return json(res, 200, stagedPreview(db));
      }
      if (pathname === '/api/characterization/staged/commit' && method === 'POST') {
        const b = await readJsonBody(req);
        const n = commitStaged(db, Array.isArray(b.ids) ? b.ids : [], { actor: who });
        broadcast('characterization.changed', charSummary(db));
        return json(res, 200, { committed: n });
      }
      if (pathname === '/api/characterization/staged/discard' && method === 'POST') {
        const b = await readJsonBody(req);
        const n = discardStaged(db, Array.isArray(b.ids) ? b.ids : [], { actor: who });
        broadcast('characterization.changed', charSummary(db));
        return json(res, 200, { discarded: n });
      }
      if ((m = pathname.match(/^\/api\/characterization\/staged\/([\w-]+)\/host$/)) && method === 'PATCH') {
        const b = await readJsonBody(req);
        try { return json(res, 200, reattributeStaged(db, m[1], b.host)); }
        catch (e) { return json(res, 400, { error: e.message }); }
      }

      if (pathname === '/api/characterization/snapshots' && method === 'GET') {
        // Scoped to the tab the analyst is in; unscoped listed all twenty.
        return json(res, 200, listCharSnapshots(db, url.searchParams.get('repo') || null));
      }
      if (pathname === '/api/characterization/snapshots' && method === 'POST') {
        const b = await readJsonBody(req);
        try {
          const snap = createCharSnapshot(db, { repo: b.repo, note: b.note ?? null, createdBy: who });
          broadcast('characterization.changed', charSummary(db));
          return json(res, 201, snap);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      /*
        Acknowledging that a collection did not gather a field. Scoped to the
        run, because one operator running one command across sixteen hosts has
        one answer, and a per-row prompt is an afternoon of clicking.
      */
      if ((m = pathname.match(/^\/api\/characterization\/snapshots\/([\w-]+)\/gaps$/))) {
        if (method === 'GET') return json(res, 200, fieldGapsFor(db, m[1]));
        if (method === 'PUT') {
          const b = await readJsonBody(req);
          try {
            const fields = setFieldGaps(db, m[1], Array.isArray(b.fields) ? b.fields : [],
              { actor: who, note: b.note ?? null });
            broadcast('characterization.changed', charSummary(db));
            return json(res, 200, { fields });
          } catch (e) { return json(res, 400, { error: e.message }); }
        }
      }

      if ((m = pathname.match(/^\/api\/characterization\/([\w-]+)$/)) && method === 'GET') {
        if (!isRepo(m[1])) return json(res, 404, { error: 'no such repository' });
        return json(res, 200, repoView(db, m[1], {
          host: url.searchParams.get('host') ?? undefined,
          q: url.searchParams.get('q') ?? undefined,
          // Both sides explicit means literal for every host, with no
          // fall-back to whatever else happens to hold data.
          snapshot: url.searchParams.get('snapshot') ?? undefined,
          against: url.searchParams.get('against') ?? undefined,
          // col.<field>=text — applied before the display cap, so a filter can
          // never answer "absent" when it means "not in the first 500".
          filters: Object.fromEntries([...url.searchParams]
            .filter(([k]) => k.startsWith('col.'))
            .map(([k, v]) => [k.slice(4), v])),
        }));
      }
      if ((m = pathname.match(/^\/api\/characterization\/snapshots\/([\w-]+)\/complete$/)) && method === 'PATCH') {
        const b = await readJsonBody(req);
        try {
          const snap = setSnapshotComplete(db, m[1], b.complete !== false, who);
          broadcast('characterization.changed', charSummary(db));
          return json(res, 200, snap);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      // Why a host is absent. The store cannot infer the difference between
      // missed, powered off, and an adversary cutting the collection path.
      if ((m = pathname.match(/^\/api\/characterization\/([\w-]+)\/coverage$/)) && method === 'PUT') {
        if (!isRepo(m[1])) return json(res, 404, { error: 'no such repository' });
        const b = await readJsonBody(req);
        if (!b.host) return json(res, 400, { error: 'host is required' });
        try {
          const st = setHostStatus(db, m[1], b.host, { reason: b.reason, note: b.note ?? null, actor: who });
          broadcast('characterization.changed', charSummary(db));
          return json(res, 200, st ?? { cleared: true });
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      if ((m = pathname.match(/^\/api\/characterization\/([\w-]+)\/snapshots$/)) && method === 'GET') {
        if (!isRepo(m[1])) return json(res, 404, { error: 'no such repository' });
        return json(res, 200, listSnapshots(db, { repo: m[1] }));
      }
      /*
        Promote one baseline row to a pending record. This is the bridge
        between the two halves: characterization says what is there, and the
        analyst decides that one row of it is worth investigating. Doing it
        this way rather than letting characterization mode file findings keeps
        the adjudication rail meaningful.
      */
      if ((m = pathname.match(/^\/api\/characterization\/entity\/([\w-]+)\/evidence$/)) && method === 'POST') {
        const e = getEntity(db, m[1]);
        if (!e) return json(res, 404, { error: 'no such entity' });
        const b = await readJsonBody(req);
        const a = e.attrs ?? {};
        const rec = createRecord(db, {
          hostname: e.host ?? null,
          indicator: a.name ?? a.process ?? a.username ?? a.account ?? e.label,
          command: a.commandLine ?? a.action ?? a.binary ?? a.path ?? null,
          user: a.user ?? a.account ?? a.username ?? null,
          source_ip: a.source ?? null,
          destination_ip: a.destination ?? null,
          evidence_source: `Characterization — ${e.repo}`,
          description: b.description
            || `From the ${e.repo} baseline on ${e.host ?? 'an unattributed host'}: ${e.label}`,
          analyst_notes: b.note ?? JSON.stringify(a),
        }, { analyst: who, state: 'pending' });
        broadcast('record.created', rec);
        broadcast('hosts.changed', listHosts(db));
        broadcast('connections.changed', derivedConnections(db));
        return json(res, 201, rec);
      }

      // --- files -------------------------------------------------------------
      if (pathname === '/api/files' && method === 'POST') {
        const name = decodeURIComponent(req.headers['x-file-name'] ?? 'unnamed');
        const buf = await readBinaryBody(req, MAX_FILE_BYTES + 1024);
        try {
          const f = saveFile(db, {
            name, mime: req.headers['content-type'] ?? 'application/octet-stream',
            buffer: buf, uploadedBy: who,
          });
          return json(res, 201, f);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      if ((m = pathname.match(/^\/api\/files\/([\w-]+)$/)) && method === 'GET') {
        const f = getFileBody(db, m[1]);
        if (!f) return json(res, 404, { error: 'no such file' });
        /*
          The only route that hands out bytes, and the only chat route that
          checked nothing. A DM attachment was readable by the whole roster and
          by the operator token the DM itself refuses.
        */
        if (!canReadFile(db, m[1], who)) return json(res, 403, { error: 'not your file' });
        /*
          Never serve an uploaded file with its own content type. A teammate
          uploading an .html or .svg would otherwise get script execution on
          this origin, which is every token and every record in the store.
          Force a download, and forbid sniffing.
        */
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'x-content-type-options': 'nosniff',
          'content-security-policy': "default-src 'none'; sandbox",
          /*
            Both forms. Node's header validator rejects any code point above
            U+00FF, so a file called отчёт-по-хосту.log uploaded fine and then
            threw on every download — a 500, forever, for an artifact sitting
            in the store. The ASCII form is a fallback for old clients; the
            RFC 5987 form is what carries the real name.
          */
          'content-disposition': `attachment; filename="${
            f.name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '')
          }"; filename*=UTF-8''${encodeURIComponent(f.name)}`,
          'content-length': f.size,
        });
        return res.end(Buffer.from(f.body));
      }

      // --- team comms ---------------------------------------------------------
      if (pathname === '/api/chat/channels' && method === 'GET') {
        return json(res, 200, listChannels(db, who));
      }
      if (pathname === '/api/chat/channels' && method === 'POST') {
        const b = await readJsonBody(req);
        const roster = new Set(listMembers(db).map(x => x.name));
        const bad = (b.members ?? []).filter(x => !roster.has(x));
        if (bad.length) return json(res, 400, { error: `not on the roster: ${bad.join(', ')}` });
        try {
          const c = createChannel(db, {
            kind: b.kind, name: b.name, members: b.members ?? [], createdBy: who,
          });
          /*
            A private channel's row carries its title, and a DM's title is both
            participants' names. Broadcasting the row told every browser on the
            LAN that Lindqvist and Okafor had opened a DM, and when — the same
            leak the message broadcast below was narrowed to prevent, one line
            up. Everyone is told something changed; only a member's own
            listChannels can say what.
          */
          broadcast('chat.channel', isOpenChannel(db, c.id) ? c : { id: c.id });
          return json(res, 201, c);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      if (pathname === '/api/chat/mentions' && method === 'GET') {
        return json(res, 200, listMentions(db, who));
      }
      /*
        Marking a channel read without re-reading it.

        The only way to do this was to GET the messages, whose handler marks
        read as a side effect — so watching a busy channel re-downloaded up to
        three hundred messages for every one that arrived, and threw the answer
        away.
      */
      if ((m = pathname.match(/^\/api\/chat\/([\w-]+)\/read$/)) && method === 'POST') {
        if (!canSee(db, m[1], who)) return json(res, 403, { error: 'not your conversation' });
        markRead(db, m[1], who);
        return json(res, 204, null);
      }
      if ((m = pathname.match(/^\/api\/chat\/([\w-]+)\/messages$/)) && method === 'GET') {
        if (!canSee(db, m[1], who)) return json(res, 403, { error: 'not your conversation' });
        markRead(db, m[1], who);
        return json(res, 200, listChat(db, m[1]));
      }
      if ((m = pathname.match(/^\/api\/chat\/([\w-]+)\/messages$/)) && method === 'POST') {
        // A DM is the one place in this tool where reading is not open, so it
        // is the one place a membership check has to hold on read as well.
        if (!canSee(db, m[1], who)) return json(res, 403, { error: 'not your conversation' });
        const b = await readJsonBody(req);
        try {
          const msg = postMessage(db, {
            channelId: m[1], author: who, body: b.body ?? '',
            fileId: b.fileId ?? null, roster: listMembers(db).map(x => x.name),
          });
          /*
            The team channel carries its body on the wire; a DM or a group does
            not.

            Every authenticated browser holds one event stream, and broadcast
            reaches all of them — so putting a private message on it handed the
            plaintext to people the route had just refused with 403. The
            notification broadcast on the next line already knew this and
            carries nothing for the same reason.

            A private channel gets the id alone, and a client that can open it
            re-reads it. That keeps the optimisation where it was actually
            needed — the team channel is the busy one — and costs one fetch on a
            conversation between two people.
          */
          broadcast('chat.message', isOpenChannel(db, m[1])
            ? { channelId: m[1], message: msg }
            : { channelId: m[1] });
          if (msg.mentions?.length) broadcast('notification.new', null);
          return json(res, 201, msg);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }

      /*
        One person's inbox. Scoped to the caller's own roster identity and
        never to a name in the query, because an id is not authority to read
        somebody else's mail.
      */
      if (pathname === '/api/notifications' && method === 'GET') {
        if (!auth.member) return json(res, 200, { items: [], unread: 0, member: null });
        return json(res, 200, {
          member: auth.member.name,
          unread: unreadCount(db, auth.member.name),
          items: listNotifications(db, auth.member.name, {
            limit: Number(url.searchParams.get('limit')) || 50,
            unreadOnly: url.searchParams.get('unread') === '1',
          }),
        });
      }
      if (pathname === '/api/notifications/read' && method === 'POST') {
        if (!auth.member) return json(res, 403, { error: 'the operator token has no inbox' });
        return json(res, 200, { read: markAllRead(db, auth.member.name), unread: 0 });
      }
      if ((m = pathname.match(/^\/api\/notifications\/([\w-]+)\/read$/)) && method === 'POST') {
        if (!auth.member) return json(res, 403, { error: 'the operator token has no inbox' });
        return json(res, 200, { unread: markNotificationRead(db, m[1], auth.member.name) });
      }

      // --- records ---------------------------------------------------------
      if (pathname === '/api/records' && method === 'GET') {
        return json(res, 200, listRecords(db, {
          state: url.searchParams.get('state') ?? undefined,
          hostname: url.searchParams.get('hostname') ?? undefined,
          threadId: url.searchParams.get('threadId') ?? undefined,
          from: url.searchParams.get('from') ?? undefined,
          to: url.searchParams.get('to') ?? undefined,
        }));
      }
      if (pathname === '/api/records' && method === 'POST') {
        const body = await readJsonBody(req);
        const rec = createRecord(db, body, { analyst: who, state: body.state === 'filed' ? 'filed' : 'pending' });
        broadcast('record.created', rec);
        broadcast('hosts.changed', listHosts(db));
        // The nodes are useless without the edge between them, and connections
        // are only ever replaced wholesale by this delta.
        broadcast('connections.changed', derivedConnections(db));
        return json(res, 201, rec);
      }
      if (pathname === '/api/export/records.xlsx' && method === 'GET') {
        const state = url.searchParams.get('state') ?? 'filed';
        const rows = listRecords(db, state === 'all' ? {} : { state });
        const buf = recordsToXlsx(rows, listThreads(db), { generatedAt: new Date().toISOString() });
        res.writeHead(200, {
          'content-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          'content-disposition': 'attachment; filename="hunt-records.xlsx"',
          'content-length': buf.length,
        });
        return res.end(buf);
      }
      if (pathname === '/api/export/records.csv' && method === 'GET') {
        const state = url.searchParams.get('state') ?? 'filed';
        const rows = listRecords(db, state === 'all' ? {} : { state });
        const csv = recordsToCsv(rows);
        res.writeHead(200, {
          'content-type': 'text/csv; charset=utf-8',
          'content-disposition': 'attachment; filename="hunt-records.csv"',
        });
        return res.end(csv);
      }

      /*
        The coverage picture, in the format the rest of the trade reads. Pending
        records are included and scored below adjudicated ones rather than left
        out: a proposal nobody has looked at is not coverage, but it is not
        nothing either, and the gradient is where that distinction lives.
      */
      if (pathname === '/api/export/navigator.json' && method === 'GET') {
        const want = url.searchParams.get('state') ?? 'all';
        const threadId = url.searchParams.get('thread') || undefined;
        const rows = listRecords(db, {
          ...(want === 'all' ? {} : { state: want }),
          ...(threadId ? { threadId } : {}),
        });
        const thread = threadId ? listThreads(db).find(t => t.id === threadId) : null;
        const layer = recordsToNavigatorLayer(rows, {
          name: thread ? `Hunt findings — ${thread.name}` : 'Hunt findings',
        });
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'content-disposition': 'attachment; filename="hunt-navigator-layer.json"',
        });
        return res.end(JSON.stringify(layer, null, 2));
      }

      /*
        Indicators for somebody else's stack. Confirmed by default: everything
        here is written to be acted on elsewhere, and a proposal nobody has
        adjudicated is not a thing to put in another team's detections.
      */
      if (pathname === '/api/export/iocs.json' && method === 'GET') {
        const want = url.searchParams.get('state') ?? 'filed';
        const rows = listRecords(db, want === 'all' ? {} : { state: want });
        const stix = url.searchParams.get('format') === 'stix';
        const body = stix ? recordsToStixBundle(rows) : recordsToMispEvent(rows);
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'content-disposition':
            `attachment; filename="hunt-iocs-${stix ? 'stix' : 'misp'}.json"`,
        });
        return res.end(JSON.stringify(body, null, 2));
      }

      /*
        The deliverable, assembled from what is already recorded. Confirmed
        findings only, with the outstanding proposals counted in the summary so
        a reader cannot mistake the findings for the whole picture.
      */
      if (pathname === '/api/export/report.md' && method === 'GET') {
        const tasks = listPlan(db);
        const phases = new Map();
        for (const t of tasks) {
          if (!phases.has(t.phaseName)) phases.set(t.phaseName, []);
          phases.get(t.phaseName).push({ title: t.title, status: t.status });
        }
        const ps = planSummary(db);
        const records = listRecords(db);
        const md = buildReport({
          mission: runtime.setup ? {} : readMission(),
          threads: listThreads(db),
          records,
          hosts: listHosts(db),
          plan: {
            summary: { total: ps.total, complete: ps.byStatus?.complete ?? 0 },
            phases: [...phases].map(([name, ts]) => ({ name, tasks: ts })),
          },
          gaps: allFieldGaps(db),
          emptyRepos: charSummary(db).filter(r => !r.snapshots).map(r => r.key),
          iocs: listIndicators(records.filter(r => r.state === 'filed')),
        });
        res.writeHead(200, {
          'content-type': 'text/markdown; charset=utf-8',
          'content-disposition': 'attachment; filename="hunt-report.md"',
        });
        return res.end(md);
      }

      /*
        Search on the server, so the answer is computed over every record rather
        than over whatever the browser happens to be holding. total is returned
        beside the page because a page length alone cannot tell an analyst
        whether anything was left out.
      */
      if (pathname === '/api/records/search' && method === 'GET') {
        const p = url.searchParams;
        const limit = Math.min(Number(p.get('limit')) || 200, 1000);
        return json(res, 200, searchRecords(db, {
          q: p.get('q') ?? '',
          state: p.get('state') && p.get('state') !== 'all' ? p.get('state') : null,
          threadId: p.get('thread') || null,
          hostname: p.get('host') || null,
          from: p.get('from') || null,
          to: p.get('to') || null,
          limit,
          offset: Number(p.get('offset')) || 0,
        }));
      }

      /*
        What the map draws a badge from. One number per host that carries
        evidence, rather than every record so the browser can count them — the
        only reason the bootstrap had to carry the whole case file.

        Above the /api/records/:id route on purpose: that pattern would take
        "evidence-by-host" for a record id. route-order.test.js asserts it.
      */
      if (pathname === '/api/records/evidence-by-host' && method === 'GET') {
        const p = url.searchParams;
        return json(res, 200, evidenceByHost(db, listHosts(db), {
          q: p.get('q') ?? '',
          threadId: p.get('thread') || null,
          confidence: p.get('confidence') || null,
          from: p.get('from') || null,
          to: p.get('to') || null,
        }));
      }

      /** Counts the shell shows without the rows behind them. */
      if (pathname === '/api/records/counts' && method === 'GET') {
        return json(res, 200, recordCounts(db));
      }

      /** Findings nothing can place, for the bind-by-hand list. */
      if (pathname === '/api/records/unplaced' && method === 'GET') {
        return json(res, 200, unplacedRecords(db, listHosts(db)));
      }

      if (pathname === '/api/records/archived' && method === 'GET') {
        return json(res, 200, listArchivedRecords(db));
      }
      if (pathname === '/api/records/archive' && method === 'POST') {
        const b = await readJsonBody(req);
        const ids = Array.isArray(b.ids) ? b.ids : [];
        let n = 0;
        for (const id of ids) {
          try { archiveRecord(db, id, { actor: who, reason: b.reason ?? null }); n++; }
          catch { /* already gone; the count tells the truth */ }
        }
        broadcast('records.changed', null);
        broadcast('hosts.changed', listHosts(db));
        broadcast('connections.changed', derivedConnections(db));
        return json(res, 200, { archived: n });
      }

      if ((m = pathname.match(/^\/api\/records\/([\w-]+)$/))) {
        if (method === 'GET') {
          const r = getRecord(db, m[1]);
          return r ? json(res, 200, r) : json(res, 404, { error: 'no such record' });
        }
        if (method === 'PATCH') {
          const patch = await readJsonBody(req);
          try {
            const rec = updateRecord(db, m[1], patch, who);
            broadcast('record.updated', rec);
            broadcast('connections.changed', derivedConnections(db));
            return json(res, 200, rec);
          } catch (e) { return storeFault(res, e); }
        }
      }
      /*
        Retiring a finding, which is a different decision from denying one.
        Denying says the evidence did not show what it appeared to; archiving
        says the team is finished with it and it should stop occupying the map,
        the timeline and the case file the model is shown.
      */
      if ((m = pathname.match(/^\/api\/records\/([\w-]+)\/(archive|restore)$/)) && method === 'POST') {
        const b = await readJsonBody(req).catch(() => ({}));
        try {
          const rec = m[2] === 'archive'
            ? archiveRecord(db, m[1], { actor: who, reason: b.reason ?? null })
            : restoreRecord(db, m[1], { actor: who });
          broadcast('records.changed', null);
          broadcast('hosts.changed', listHosts(db));
          broadcast('connections.changed', derivedConnections(db));
          return json(res, 200, rec);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }

      if ((m = pathname.match(/^\/api\/records\/([\w-]+)\/(promote|deny)$/)) && method === 'POST') {
        try {
          const rec = m[2] === 'promote' ? promoteRecord(db, m[1], who) : denyRecord(db, m[1], who);
          broadcast('record.updated', rec);
          broadcast('connections.changed', derivedConnections(db));
          return json(res, 200, rec);
        } catch (e) { return storeFault(res, e); }
      }

      // --- hosts -----------------------------------------------------------
      /*
        Literal paths first. /api/hosts/:id matches "withdrawn" perfectly well
        and would answer "no such host" to a question about the whole set.
      */
      /* The findings on one host, by the same rule the map counts by. */
      if ((m = pathname.match(/^\/api\/hosts\/([\w-]+)\/records$/)) && method === 'GET') {
        const host = listHosts(db).find(h => h.id === m[1]);
        if (!host) return json(res, 404, { error: 'no such host' });
        return json(res, 200, recordsForHost(db, listHosts(db), host));
      }

      if (pathname === '/api/hosts/withdrawn' && method === 'GET') {
        return json(res, 200, withdrawnHosts(db));
      }
      if (pathname === '/api/hosts/archived' && method === 'GET') {
        return json(res, 200, listArchivedHosts(db));
      }

      if ((m = pathname.match(/^\/api\/hosts\/([\w-]+)\/verdict$/)) && method === 'PATCH') {
        const { verdict } = await readJsonBody(req);
        if (!VERDICTS.has(verdict)) {
          return json(res, 400, { error: `verdict must be one of: ${[...VERDICTS].join(', ')}` });
        }
        try {
          const host = setVerdict(db, m[1], verdict, who);
          broadcast('host.verdict', host);
          return json(res, 200, host);
        } catch (e) { return storeFault(res, e); }
      }

      /*
        Asset editing. Terrain rewrites every seeded host at each re-seed, so a
        hand correction is stored as a per-field override and laid back on top
        rather than written into the row and lost.
      */
      if ((m = pathname.match(/^\/api\/hosts\/([\w-]+)$/)) && method === 'GET') {
        const h = getHost(db, m[1]);
        if (!h) return json(res, 404, { error: 'no such host' });
        return json(res, 200, {
          ...h, overrides: hostOverrides(db, m[1]), evidence: hostEvidence(db, m[1]),
          overridable: OVERRIDABLE,
        });
      }
      if ((m = pathname.match(/^\/api\/hosts\/([\w-]+)$/)) && method === 'PATCH') {
        const b = await readJsonBody(req);
        try {
          let h = null;
          for (const [f, v] of Object.entries(b.fields ?? {})) h = setHostOverride(db, m[1], f, v, who);
          broadcast('hosts.changed', listHosts(db));
          return json(res, 200, h ?? getHost(db, m[1]));
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      if ((m = pathname.match(/^\/api\/hosts\/([\w-]+)\/merge$/)) && method === 'POST') {
        const b = await readJsonBody(req);
        try {
          const out = mergeHosts(db, m[1], b.into, { reason: b.reason ?? null, actor: who });
          broadcast('hosts.changed', listHosts(db));
          broadcast('records.changed', null);
          broadcast('characterization.changed', charSummary(db));
          return json(res, 200, out);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      if (pathname === '/api/hosts' && method === 'POST') {
        const b = await readJsonBody(req);
        try {
          const h = createHost(db, { ...b, actor: who });
          broadcast('hosts.changed', listHosts(db));
          return json(res, 201, h);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      /*
        Archiving, which is what "this finding was denied and the host it
        invented should stop being on the map" actually needs. Deleting is
        refused for these — the denied record still points at the host — and
        deleting would take the reason it existed with it.
      */
      if (pathname === '/api/hosts/archive-withdrawn' && method === 'POST') {
        const b = await readJsonBody(req).catch(() => ({}));
        // Recomputed here rather than taken from the client, so a filtered
        // view can never archive something it was not showing.
        const targets = withdrawnHosts(db);
        for (const h of targets) {
          archiveHost(db, h.id, { actor: who, reason: b.reason ?? 'evidence denied or removed' });
        }
        broadcast('hosts.changed', listHosts(db));
        broadcast('connections.changed', derivedConnections(db));
        return json(res, 200, { archived: targets.length, names: targets.map(h => h.name) });
      }
      if ((m = pathname.match(/^\/api\/hosts\/([\w-]+)\/(archive|restore)$/)) && method === 'POST') {
        const b = await readJsonBody(req).catch(() => ({}));
        try {
          const h = m[2] === 'archive'
            ? archiveHost(db, m[1], { actor: who, reason: b.reason ?? null })
            : restoreHost(db, m[1], { actor: who });
          broadcast('hosts.changed', listHosts(db));
          broadcast('connections.changed', derivedConnections(db));
          return json(res, 200, h);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }

      if ((m = pathname.match(/^\/api\/hosts\/([\w-]+)$/)) && method === 'DELETE') {
        try {
          const out = removeHost(db, m[1], { actor: who });
          broadcast('hosts.changed', listHosts(db));
          return json(res, 200, out);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }
      // Which host a finding belongs to, when the name could not decide.
      if ((m = pathname.match(/^\/api\/records\/([\w-]+)\/bind$/)) && method === 'POST') {
        const b = await readJsonBody(req);
        try {
          const rec = bindRecordHost(db, m[1], b.hostId ?? null, { reason: b.reason ?? null, analyst: who });
          broadcast('record.updated', rec);
          broadcast('hosts.changed', listHosts(db));
          return json(res, 200, rec);
        } catch (e) { return json(res, 400, { error: e.message }); }
      }

      // --- edges -----------------------------------------------------------
      if (pathname === '/api/edges' && method === 'POST') {
        const b = await readJsonBody(req);
        try {
          const edge = proposeEdge(db, b, who);
          broadcast('edge.created', edge);
          return json(res, 201, edge);
        } catch (e) { return storeFault(res, e); }
      }
      if ((m = pathname.match(/^\/api\/edges\/([\w-]+)\/(confirm|deny)$/)) && method === 'POST') {
        try {
          const edge = m[2] === 'confirm' ? confirmEdge(db, m[1], who) : denyEdge(db, m[1], who);
          broadcast('edge.updated', edge);
          return json(res, 200, edge);
        } catch (e) { return storeFault(res, e); }
      }

      // --- sessions --------------------------------------------------------
      if (pathname === '/api/me' && method === 'GET') {
        if (!auth.member) return json(res, 200, { member: null, sessionId: null, analyst: who });
        const mine = sessionForMember(db, auth.member.id);
        const { token: _t, ...safe } = auth.member;
        return json(res, 200, { member: safe, sessionId: mine ? mine.id : null, analyst: who });
      }
      if (pathname === '/api/sessions' && method === 'GET') return json(res, 200, listSessions(db));
      if (pathname === '/api/sessions' && method === 'POST') {
        const b = await readJsonBody(req);
        const s = createSession(db, { title: b.title || 'Untitled hunt', kind: b.kind || 'chat', analyst: who });
        broadcast('session.created', s);
        return json(res, 201, s);
      }
      if ((m = pathname.match(/^\/api\/sessions\/([\w-]+)$/)) && method === 'GET') {
        const s = getSession(db, m[1]);
        if (!s) return json(res, 404, { error: 'no such session' });
        return json(res, 200, { ...s, messages: listMessages(db, m[1]) });
      }
      if ((m = pathname.match(/^\/api\/sessions\/([\w-]+)\/message$/)) && method === 'POST') {
        const sessionId = m[1];
        if (!getSession(db, sessionId)) return json(res, 404, { error: 'no such session' });
        if (!spawnLimit(who)) return json(res, 429, { error: 'too many turns; wait a moment' });

        // Read anyone's window; write only your own. Not authentication, just
        // enough to stop a misdirected paste landing in a colleague's chat.
        const target = getSession(db, sessionId);
        if (!auth.member || target.member_id !== auth.member.id) {
          return json(res, 403, {
            error: 'This is not your chat window. You can read it, but only its owner can post.',
          });
        }

        // Same ceiling as the characterization import. A megabyte was a
        // different limit for no reason anyone could explain to an analyst
        // whose paste was refused.
        const body = await readJsonBody(req, 4_000_000);
        const MODES = new Set(['evidence', 'research', 'characterization']);
        const mode = MODES.has(body.mode) ? body.mode : 'evidence';
        const fileIds = Array.isArray(body.fileIds) ? body.fileIds.slice(0, 5) : [];
        let text = String(body.text ?? '');
        if (!text.trim() && fileIds.length === 0) return json(res, 400, { error: 'empty message' });

        /*
          Attached files become part of the turn. Text is inlined so Claude can
          actually read the log; binary is described by name, size and hash,
          because a megabyte of decoded PNG helps nobody. The file itself stays
          in the store either way, so the record can point at the artifact.
        */
        const attached = [];
        for (const fid of fileIds) {
          const meta = getFileMeta(db, fid);
          // Same rule as the download route: inlining a file into a transcript
          // the team reads is another way of handing over its contents.
          if (!meta || !canReadFile(db, fid, who)) continue;
          attached.push(meta);
          text += (text ? '\n\n' : '') + fileAsPromptText(db, fid);
        }
        if (attached.length) {
          text += `\n\n[${attached.length} file(s) attached and retained in the case store: ` +
            attached.map(a => `${a.name} sha256 ${a.sha256.slice(0, 16)}…`).join('; ') + ']';
        }

        /*
          One turn at a time per session, claimed here rather than in runTurn.
          The client disables the composer while a turn runs, but that flag
          rides a broadcast this route has not sent yet, so a double submit
          would otherwise spawn a second CLI resuming the same conversation id
          — racing the transcript and spending the quota twice. Re-check and
          claim with no await in between, so the pair is atomic on the loop.
        */
        if (getSession(db, sessionId).state === 'running') {
          return json(res, 409, { error: 'Claude is still working on your last message.' });
        }
        broadcast('session.state', setState(db, sessionId, 'running'));

        const userMsg = appendMessage(db, sessionId, 'user', String(text), mode);
        broadcast('session.message', { sessionId, message: userMsg });

        // Reply immediately; the turn streams over SSE.
        json(res, 202, { accepted: true, mode });

        /*
          Characterization context. countedRows is a plain non-blank line count
          of what the analyst actually submitted, and it is the yardstick the
          model's own row count gets checked against — the whole reason a
          short extraction gets flagged instead of silently producing phantom
          deltas on the next upload.
        */
        const char = mode === 'characterization'
          ? {
            repo: String(body.repo ?? '').trim() || null,
            host: String(body.host ?? '').trim() || null,
            countedRows: countRows(text),
            fileId: attached[0]?.id ?? null,
            snapshotId: String(body.snapshotId ?? '').trim() || null,
          }
          : null;

        runTurn(db, sessionId, String(text), { analyst: who, mode, char }).catch(err => {
          const msg = appendMessage(db, sessionId, 'system', `Turn failed: ${err.message}`);
          setState(db, sessionId, 'error');
          broadcast('session.message', { sessionId, message: msg });
          broadcast('session.state', getSession(db, sessionId));
        });
        return;
      }

      if (pathname.startsWith('/api/')) return json(res, 404, { error: 'no such route' });
      return serveStatic(req, res, pathname);
    } catch (err) {
      // A 500 is the server's fault and worth seeing in the log; anything with
      // a status of its own is the request's fault and already explained.
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) console.error(`  ${method} ${pathname} failed:`, err.stack ?? err.message);
      if (!res.headersSent) json(res, status, { error: err.message });
      else try { res.end(); } catch { /* client gone */ }
    }
  });
}
