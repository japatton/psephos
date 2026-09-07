/**
 * Hunt tools, exposed to the Claude subprocess over stdio MCP.
 *
 * Claude never describes a finding in prose and hopes we parse it. It calls a
 * typed tool, the tool validates, and the row lands in SQLite as `pending`.
 * Extraction reliability is the whole value of this application, so it goes
 * through a contract rather than a regex.
 *
 * Spawned by claude/runner.js via --mcp-config. Reads its context from env:
 *   HUNT_DB       path to the SQLite store
 *   HUNT_SESSION  session id to attribute records to
 *   HUNT_ANALYST  display name of the analyst driving the session
 */
import { missionName } from '../store/mission.js';
import { StringDecoder } from 'node:string_decoder';
import { openDb, initSchema } from '../store/db.js';
import { createRecord, listRecords, COLUMNS } from '../store/records.js';
import { proposeEdge } from '../store/edges.js';
import { terrainHosts } from '../terrain/load.js';
import { stageSnapshot, queryBaseline, REPOS, isRepo } from '../store/characterization.js';
import { getFileBody } from '../store/files.js';

const ok = (text) => ({ content: [{ type: 'text', text }], isError: false });
const err = (text) => ({ content: [{ type: 'text', text }], isError: true });

const STRING = (description) => ({ type: 'string', description });

export const TOOLS = [
  {
    name: 'propose_finding',
    description:
      'Propose one investigation record for the analyst to review. Use the analyst 18-column ' +
      'schema. Only `description` is required — supply whatever else the evidence actually ' +
      'supports and leave the rest out rather than guessing. The record lands as PENDING and ' +
      'does not enter the case file until the analyst promotes it. Call search_records first ' +
      'to avoid proposing something already on file.',
    inputSchema: {
      type: 'object',
      required: ['description'],
      properties: {
        event_id: STRING('Event/log identifier, e.g. "Sysmon 1", "zeek.connection", "Security 4624"'),
        event_time: STRING('Time as recorded. Exact ISO is best; "2026-08-19 ~11:59" or "N/A" are acceptable and will be tiered.'),
        hostname: STRING('Host where the evidence was seen'),
        source_ip: STRING('Source address'),
        destination_ip: STRING('Destination address, with port if known'),
        user: STRING('Account involved'),
        indicator: STRING('Process name, executable, or other indicator'),
        command: STRING('Command line or script content'),
        pid: STRING('Process id'),
        sha256: STRING('Hash, or a note on why it was not collected'),
        description: STRING('What this is and why it matters. Required.'),
        misp: STRING('MISP reference, file contents, or extracted artifact'),
        evidence_source: STRING('Where this came from, e.g. "filebeat-zeek-*", "host forensics"'),
        confidence: STRING('High, Medium, or Low'),
        triage_status: STRING('New, Investigating, Corroborated, or Ruled Out'),
        analyst_notes: STRING('Assessment, caveats, and what to check next'),
        mitre: STRING('ATT&CK technique ids, comma separated'),
        reference: STRING('Report or source reference'),
      },
    },
  },
  {
    name: 'propose_edge',
    description:
      'Propose a causal or temporal link between two existing records. The analyst confirms or ' +
      'denies it; confirmed links draw the attack chain on the timeline and map.',
    inputSchema: {
      type: 'object',
      required: ['src_record_id', 'dst_record_id', 'kind'],
      properties: {
        src_record_id: STRING('Id of the earlier/causing record'),
        dst_record_id: STRING('Id of the later/caused record'),
        kind: { type: 'string', enum: ['caused', 'preceded', 'same_actor'] },
        rationale: STRING('Why you believe these are linked'),
      },
    },
  },
  {
    name: 'query_terrain',
    description:
      'Look up known network terrain for this engagement. Use this before asserting that an address is ' +
      'unmapped — an address absent from terrain is itself a finding worth reporting.',
    inputSchema: {
      type: 'object',
      properties: {
        ip: STRING('Address to look up'),
        hostname: STRING('Host name to look up (substring match)'),
        cidr: STRING('Segment prefix to list, e.g. "10.20.20."'),
      },
    },
  },
  {
    name: 'search_records',
    description:
      'Search records already in the store. Call before proposing a finding so you do not file a ' +
      'duplicate, and to find record ids for propose_edge.',
    inputSchema: {
      type: 'object',
      properties: {
        text: STRING('Free text matched against description, host, indicator, command and notes'),
        hostname: STRING('Exact hostname filter'),
        state: { type: 'string', enum: ['pending', 'filed', 'denied'] },
      },
    },
  },
  {
    name: 'stage_entities',
    description:
      'Record a characterization snapshot: the rows you extracted from an upload, filed into one ' +
      'baseline repository. This is NOT a finding — it is what normal looks like, and it is what ' +
      'later findings get judged against. Extract EVERY row; a row you drop becomes a phantom ' +
      '"new" item the next time this host is characterized, and somebody will investigate it. ' +
      'Report claimed_rows honestly as the number of rows you believe the source contained, even ' +
      'when that is more than you returned — the mismatch is checked and flagged, and an honest ' +
      'short count is far more useful than a confident wrong one.',
    inputSchema: {
      type: 'object',
      required: ['repo', 'entities'],
      properties: {
        repo: { type: 'string', enum: Object.keys(REPOS),
          description: 'Which repository these rows belong in. Use unclassified only if none fit.' },
        host: STRING('Host these rows describe. Infer it from the content when the analyst did not say.'),
        source_format: STRING('The format you recognised, e.g. "netstat -ano" or "schtasks /query /fo LIST"'),
        claimed_rows: { type: 'number', description: 'How many rows the source actually contained.' },
        entities: {
          type: 'array',
          description:
            'One object per row. Prefer these field names per repository, though the source\'s own ' +
            'spelling is matched too — task.name, UserName and username all resolve to the same ' +
            'field, so keep the source names rather than inventing new ones:\n' +
            Object.entries(REPOS).map(([k, r]) => `  ${k}: ${r.columns.join(', ')}`).join('\n'),
          items: { type: 'object', additionalProperties: true },
        },
      },
    },
  },
  {
    name: 'query_baseline',
    description:
      'Ask what normal looks like. Returns characterization rows with how many hosts carry each ' +
      'one, which is usually the answer you need: present on 1 of 82 hosts and present on 82 of 82 ' +
      'mean opposite things. Call this before calling a process, task, service or account ' +
      'suspicious — an unfamiliar name that is on every host is inventory, not an intrusion.',
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string', enum: Object.keys(REPOS), description: 'Restrict to one repository.' },
        host: STRING('Restrict to one host.'),
        text: STRING('Free text matched against the row and its attributes.'),
      },
    },
  },
];

export function handleToolCall(db, name, args = {}, ctx = {}) {
  try {
    switch (name) {
      case 'propose_finding': {
        if (!args.description || !String(args.description).trim()) {
          return err('description is required — say what the evidence is and why it matters.');
        }
        const fields = Object.fromEntries(COLUMNS.map(c => [c, args[c]]));
        const rec = createRecord(db, fields, {
          sessionId: ctx.sessionId ?? null,
          analyst: ctx.analyst ?? 'claude',
        });
        return ok(`Proposed record ${rec.id} (pending analyst review). ` +
          `Time tier: ${rec.time_tier}${rec.time_parsed ? ` at ${rec.time_parsed}` : ''}.`);
      }

      case 'propose_edge': {
        const edge = proposeEdge(db, {
          srcRecordId: args.src_record_id,
          dstRecordId: args.dst_record_id,
          kind: args.kind,
          rationale: args.rationale ?? null,
        }, ctx.analyst ?? 'claude');
        return ok(`Proposed ${edge.kind} link ${edge.id} (pending analyst confirmation).`);
      }

      case 'stage_entities': {
        /*
          The repository is the window the analyst is standing in, not a guess
          the model makes. Pinning it here is what stopped a process list being
          filed as unclassified: the catch-all keyed every row on a label that
          was constant per format, and 879 of 912 rows overwrote each other.
        */
        const repo = ctx.repo ?? args.repo;
        if (!isRepo(repo)) return err(`unknown repository: ${repo}`);
        // Worth saying out loud rather than silently correcting, so the
        // analyst finds out their paste was not what the window is for.
        const misread = ctx.repo && args.repo && args.repo !== ctx.repo
          ? `  NOTE: you asked for ${args.repo}; this window is ${ctx.repo}, so it was filed there. `
            + `If the paste really is ${args.repo} data, tell the analyst to import it under that tab.`
          : '';
        const entities = Array.isArray(args.entities) ? args.entities : [];
        if (entities.length === 0) return err('entities was empty — nothing to record.');
        /*
          The text the rows are supposed to have come out of, so the store can
          tell an identity that was read from one that was invented.

          Read whole rather than through fileAsPromptText, which clips at 200k
          and labels the clip. A truncated source would report every identity
          past the cut as absent, and a guard that cries wolf on large uploads
          is worse than no guard — this file already says as much about the
          line-count yardstick that had to be abandoned.

          Only the attached-file path. A pasted collection never reaches this
          subprocess as text — only its row count does — so those uploads are
          judged as before, and the check simply does not run.
        */
        let sourceText = null;
        if (ctx.fileId) {
          const f = getFileBody(db, ctx.fileId);
          if (f?.is_text) sourceText = Buffer.from(f.body).toString('utf8');
        }
        const snap = stageSnapshot(db, {
          repo,
          host: args.host ?? ctx.host ?? null,
          sourceFormat: args.source_format ?? null,
          claimedRows: args.claimed_rows ?? null,
          countedRows: ctx.countedRows ?? null,
          entities,
          analyst: ctx.analyst ?? 'claude',
          sessionId: ctx.sessionId ?? null,
          fileId: ctx.fileId ?? null,
          snapshotId: ctx.snapshotId ?? null,
          staged: Boolean(ctx.staged),
          sourceText,
        });
        const warn = snap.status === 'incomplete' ? `  WARNING: ${snap.note}` : '';
        const where = ctx.staged
          ? ' It is HELD FOR REVIEW and is not in the baseline until the analyst commits it.'
          : '';
        return ok(`Staged ${snap.extracted_rows} row(s) into ${repo}` +
          `${snap.host ? ` for ${snap.host}` : ' (host not attributed)'}.${warn}${where}${misread}`);
      }

      case 'query_baseline': {
        const hits = queryBaseline(db, { repo: args.repo, host: args.host, q: args.text });
        if (hits.length === 0) return ok('No characterization data matches. Nothing has been baselined for that yet.');
        return ok(hits.map(h =>
          `[${h.repo}] ${h.label} — ${h.host ?? 'unattributed'} — seen on ${h.seenOn}` +
          `${h.change && h.change !== 'same' && h.change !== 'baseline' ? ` — ${h.change.toUpperCase()} since the previous snapshot` : ''}` +
          `${h.confident ? '' : ' (from an incomplete snapshot)'}`).join('\n'));
      }

      case 'query_terrain': {
        const all = terrainHosts();
        let hits = all;
        if (args.ip) hits = hits.filter(h => h.ip === args.ip);
        else if (args.hostname) {
          const q = String(args.hostname).toLowerCase();
          hits = hits.filter(h => h.name.toLowerCase().includes(q));
        } else if (args.cidr) {
          const p = String(args.cidr).replace(/0\/\d+$/, '');
          hits = hits.filter(h => (h.ip ?? '').startsWith(p));
        }
        if (hits.length === 0) {
          return ok(`No terrain match. This address or host is not in the ${missionName()} inventory — ` +
            'worth reporting as unmapped.');
        }
        return ok(JSON.stringify(hits.slice(0, 60), null, 2));
      }

      case 'search_records': {
        let rows = listRecords(db, {
          state: args.state ?? undefined,
          hostname: args.hostname ?? undefined,
        });
        if (args.text) {
          const q = String(args.text).toLowerCase();
          rows = rows.filter(r => ['description', 'hostname', 'indicator', 'command', 'analyst_notes', 'mitre']
            .some(f => (r[f] ?? '').toLowerCase().includes(q)));
        }
        if (rows.length === 0) return ok('No matching records on file.');
        const brief = rows.slice(0, 40).map(r => ({
          id: r.id, state: r.state, event_time: r.event_time, hostname: r.hostname,
          indicator: r.indicator, description: (r.description ?? '').slice(0, 160), mitre: r.mitre,
        }));
        return ok(JSON.stringify(brief, null, 2));
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (e) {
    // A bad argument must come back as a tool error Claude can correct, never
    // a crash that kills the turn or a malformed row in the store.
    return err(`Tool error: ${e.message}`);
  }
}

// --- stdio JSON-RPC loop ---------------------------------------------------

function main() {
  const db = openDb(process.env.HUNT_DB || 'data/hunt.db');
  initSchema(db);
  const ctx = {
    sessionId: process.env.HUNT_SESSION || null,
    analyst: process.env.HUNT_ANALYST || 'claude',
    // Set for characterization turns so a staged snapshot can be reconciled
    // against the upload it came from.
    repo: process.env.HUNT_CHAR_REPO || null,
    host: process.env.HUNT_CHAR_HOST || null,
    countedRows: process.env.HUNT_CHAR_ROWS ? Number(process.env.HUNT_CHAR_ROWS) : null,
    fileId: process.env.HUNT_CHAR_FILE || null,
    // Chosen by the analyst in the composer. Deliberately not a tool
    // argument: the model has no basis for picking a collection run, and
    // should not be able to file rows into the wrong one.
    snapshotId: process.env.HUNT_CHAR_SNAPSHOT || null,
    staged: process.env.HUNT_CHAR_STAGED === '1',
  };

  const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');
  const reply = (id, result) => send({ jsonrpc: '2.0', id, result });

  let buf = '';
  // Decode across chunk boundaries. A stage_entities call carries hundreds of
  // rows, so it is certain to be split, and a multi-byte character cut in half
  // would corrupt the JSON-RPC frame rather than just one character.
  const decoder = new StringDecoder('utf8');
  process.stdin.on('data', (chunk) => {
    buf += decoder.write(chunk);
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;

      let msg;
      try { msg = JSON.parse(line); } catch { continue; }

      if (msg.method === 'initialize') {
        reply(msg.id, {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'hunt', version: '0.1.0' },
        });
      } else if (msg.method === 'tools/list') {
        reply(msg.id, { tools: TOOLS });
      } else if (msg.method === 'tools/call') {
        reply(msg.id, handleToolCall(db, msg.params?.name, msg.params?.arguments ?? {}, ctx));
      } else if (msg.id != null) {
        send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } });
      }
    }
  });
  process.stdin.on('end', () => process.exit(0));
}

if (process.env.HUNT_MCP_STDIO === '1') main();
