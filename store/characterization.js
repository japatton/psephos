/**
 * Characterization: what normal looked like, so anomalies have something to be
 * anomalous against.
 *
 * This is deliberately not the record model. Four hundred running processes
 * are a baseline, not four hundred findings, and filing them as pending
 * records would bury the adjudication rail under rows nobody will ever judge.
 *
 * Three things make a baseline useful to a hunter, and the list is the least
 * of them:
 *
 *   diff    — a process list from Tuesday is mildly interesting; Tuesday
 *             against Wednesday is where the adversary is.
 *   rarity  — a scheduled task on one of eighty hosts is interesting; the same
 *             task on all eighty is corporate.
 *   lookup  — "is this normal here?" is the question that turns a suspicion
 *             into a finding or kills it, and it is asked from evidence mode.
 *
 * Diff and rarity are computed on read rather than stored, for the same reason
 * derivedConnections is: a baseline that can drift from the snapshots that
 * justify it is worse than no baseline.
 */
import { createHash } from 'node:crypto';
import { newId, nowIso } from '../lib/ids.js';
import { writeAudit } from './audit.js';
import { snapshotLabel, uniqueLabel } from '../lib/snapshot-name.js';

/**
 * The repositories, and — the part that actually decides whether diffing
 * works — what counts as the same thing twice.
 *
 * A process keyed on PID would make every reboot look like the whole host
 * changed. Keys are chosen to be stable across the reboots, restarts and
 * re-runs that separate two snapshots.
 */
export const REPOS = {
  'accounts': {
    label: 'Accounts', scope: 'host', feeds: 'M1H-tt1',
    identFields: ['username', 'user', 'name', 'account', 'samAccountName', 'uid', 'userId'],
    ident: (e) => low(field(e, 'username', 'user', 'name', 'account', 'samAccountName', 'uid', 'userId')),
    columns: ['username', 'user', 'uid', 'fullName', 'groups', 'shell', 'home', 'enabled', 'lastLogon'],
    /*
      What each column answers to besides its own name. Declared from the data
      actually on file: 470 rows carried UserId, GroupNames, HomeDirectory and
      DefaultShell while the uid, groups, home and shell columns rendered
      blank, because a column resolved only against its own spelling.
    */
    columnAliases: {
      username: ['username', 'userName', 'samAccountName'],
      uid: ['uid', 'userId'],
      groups: ['groups', 'groupNames', 'groupName'],
      shell: ['shell', 'defaultShell', 'loginShell'],
      home: ['home', 'homeDirectory', 'homeDir'],
    },
  },
  'processes': {
    label: 'Processes', scope: 'host', feeds: 'M1H-tt2',
    // Not the PID. PIDs change every boot; the process does not.
    identFields: ['name', 'processName', 'process', 'image', 'executable', 'path', 'executablePath', 'imagePath'],
    ident: (e) => `${low(field(e, 'name', 'processName', 'process', 'image', 'executable'))}` +
      `|${low(field(e, 'path', 'executablePath', 'image', 'imagePath'))}`,
    columns: ['name', 'path', 'user', 'parent', 'commandLine', 'pid'],
  },
  'scheduled-tasks': {
    label: 'Scheduled tasks', scope: 'host', feeds: 'M1H-tt3',
    note: '4698 is absent estate-wide, so diffing these snapshots is the only detection you have.',
    identFields: ['taskPath', 'path', 'uri', 'location', 'taskName', 'name'],
    /*
      A task path wins outright, which is every Windows row and leaves their
      identities byte for byte unchanged.

      Cron has no such path. It has a name and a directory, and the same job
      name genuinely can appear in two of them — /etc/cron.d/backup and
      /etc/cron.daily/backup are different jobs. Keyed on the name alone they
      would silently become one row, and silently is the problem: two rows
      folding into one is far below the twenty-row floor the fold guard needs
      before it will say anything.
    */
    ident: (e) => {
      const path = low(field(e, 'taskPath', 'path', 'uri'));
      if (path) return path;
      const name = low(field(e, 'taskName', 'name'));
      const location = low(field(e, 'location'));
      return location ? `${location}|${name}` : name;
    },
    columns: ['name', 'taskPath', 'trigger', 'action', 'user', 'author', 'enabled', 'date'],
    columnAliases: {
      taskPath: ['taskPath', 'path', 'uri'],
      user: ['user', 'userId', 'runAs'],
    },
  },
  'services': {
    label: 'Services', scope: 'host', feeds: 'M1H-tt5',
    identFields: ['name', 'serviceName', 'unit', 'displayName'],
    ident: (e) => low(field(e, 'name', 'serviceName', 'unit', 'displayName')),
    columns: ['name', 'displayName', 'binary', 'startType', 'account', 'state'],
    // 287 rows arrived as service.path / service.mode / service.context.
    columnAliases: {
      binary: ['binary', 'path', 'binaryPath', 'pathName', 'imagePath'],
      startType: ['startType', 'mode', 'startMode'],
      account: ['account', 'context', 'startName', 'logOnAs'],
      state: ['state', 'status'],
    },
  },
  /*
    Autostart. A RegistryRunKeys export spells the hive path registry.path and
    the value name registry.key, and this repository was already shaped for
    exactly that — location, name, value, command, user — so it reads those
    spellings rather than gaining a near-duplicate repository beside it.
    The name column resolves registryKey FIRST: a bare "name" in one of these
    exports is the user, not the key.
  */
  'persistence': {
    label: 'Persistence', scope: 'host', feeds: 'M1H-tt4',
    identFields: ['registryPath', 'location', 'path', 'source', 'registryKey', 'key',
      'value', 'name', 'command', 'data'],
    ident: (e) => `${low(field(e, 'registryPath', 'location', 'path', 'source'))}` +
      `|${low(field(e, 'registryKey', 'key', 'value', 'name', 'command', 'data'))}`,
    columns: ['location', 'name', 'value', 'command', 'user'],
    columnAliases: {
      location: ['location', 'registryPath', 'path', 'source'],
      name: ['registryKey', 'key', 'name'],
      value: ['registryValue', 'value', 'rootValue', 'data'],
      user: ['user', 'userName'],
    },
  },

  /*
    Named pipes. Filed nowhere until now: the operator made a run for them, the
    export landed with no repository that fit, and 548 rows sat in a transcript.
    A C2 framework names its pipes, and this export carries ioc_name and
    ioc_toolkit columns for precisely that reason.
  */
  'named-pipes': {
    label: 'Named pipes', scope: 'host', feeds: 'M1H-tt2',
    identFields: ['path', 'filePath', 'pipe', 'pipeName', 'name', 'fileName'],
    // The path, not the PID or the instance count: both churn every reboot.
    ident: (e) => low(field(e, 'path', 'filePath', 'pipe', 'pipeName', 'name', 'fileName')),
    columns: ['name', 'path', 'processPath', 'processId', 'instances', 'iocName', 'iocToolkit'],
    columnAliases: {
      processPath: ['processPath', 'process'],
      processId: ['processId', 'pid'],
      instances: ['instances', 'pipeCurrentInstances', 'currentInstances'],
      iocName: ['iocName', 'fileIocName'],
      iocToolkit: ['iocToolkit', 'fileIocToolkit'],
    },
    /*
      Deliberately no rank on the IOC columns. 80 of the 333 pipes on file
      carry one, and every one is a Windows default that these toolkits
      impersonate on purpose — spoolss on spoolsv.exe, MsFteWds on
      SearchIndexer.exe, each present on 8 to 10 of 10 hosts. Sorting on the
      label would pin eighty false positives to the top of the table for the
      rest of the exercise. Rarity already does the useful work: a flagged pipe
      on one host of ten sorts high, and that is the one worth opening.
    */
  },

  /*
    BITS jobs. T1197: a transfer queued through BITS survives reboots and runs
    as the service rather than as the caller, which is why it is collected and
    why a job nobody can account for matters more than its file does.
  */
  'bits-jobs': {
    label: 'BITS jobs', scope: 'host', feeds: 'M1H-tt4',
    identFields: ['name', 'jobName', 'owner', 'remote', 'fileRemote'],
    /*
      Job name, owner and destination. Never bits.id: that is a fresh GUID each
      time the job is created, so it would never diff against anything. Never
      the local path either — half of them are temp names like wctCF9.tmp that
      churn on every collection.

      The owner is in there because these jobs are per user. Six people on one
      host each have an Outlook address-book job with the same name and the
      same URL, and without the owner they collapse into one row that says a
      host has an OAB job rather than which accounts do.
    */
    ident: (e) => `${low(field(e, 'name', 'jobName'))}` +
      `|${low(field(e, 'owner'))}` +
      `|${low(field(e, 'remote', 'fileRemote', 'url'))}`,
    columns: ['name', 'remote', 'local', 'owner', 'state', 'method', 'type', 'priority'],
    columnAliases: {
      remote: ['remote', 'fileRemote', 'url'],
      local: ['local', 'fileLocal'],
    },
  },

  /*
    What answers from the network, which is a different question from what a
    host says it is listening on. Kept apart from listening-ports deliberately:
    netstat is the host's own account of itself and nmap is what a scanner can
    reach, and where those two disagree is worth a look rather than worth
    reconciling away into one row.
  */
  'network-services': {
    label: 'Network services (scanned)', scope: 'host', feeds: 'M1H-tt2',
    identFields: ['port', 'protocol', 'proto'],
    ident: (e) => `${low(field(e, 'port'))}/${low(field(e, 'protocol', 'proto')) || 'tcp'}`,
    columns: ['port', 'protocol', 'state', 'service', 'version'],
  },
  'listening-ports': {
    label: 'Listening ports', scope: 'host', feeds: 'M1N-tt1',
    identFields: ['protocol', 'proto', 'port', 'localPort', 'process', 'processName', 'program', 'name'],
    ident: (e) => `${low(field(e, 'protocol', 'proto'))}|${low(field(e, 'port', 'localPort'))}` +
      `|${low(field(e, 'process', 'processName', 'program', 'name'))}`,
    columns: ['protocol', 'port', 'address', 'process', 'pid', 'state'],
  },
  'connections': {
    label: 'Connections', scope: 'host', feeds: 'M1N-tt3',
    identFields: ['source', 'src', 'localAddress', 'sourceIp', 'destination', 'dst', 'remoteAddress', 'destinationIp', 'port', 'destinationPort', 'remotePort'],
    ident: (e) => `${low(field(e, 'source', 'src', 'localAddress', 'sourceIp'))}` +
      `|${low(field(e, 'destination', 'dst', 'remoteAddress', 'destinationIp'))}` +
      `|${low(field(e, 'port', 'destinationPort', 'remotePort'))}`,
    columns: ['source', 'destination', 'port', 'protocol', 'process'],
  },
  'domain-accounts': {
    label: 'Domain accounts', scope: 'domain', feeds: 'M2-account-creation',
    note: '4720 is absent estate-wide. Diffing directory state is the detection for account creation.',
    identFields: ['username', 'samAccountName', 'name', 'user', 'account'],
    ident: (e) => low(field(e, 'username', 'samAccountName', 'name', 'user', 'account')),
    columns: ['username', 'enabled', 'whenCreated', 'lastLogon', 'description'],
    // 87 rows spelled it SamAccountName and read as having no username at all.
    columnAliases: {
      username: ['username', 'samAccountName', 'name'],
      whenCreated: ['whenCreated', 'created', 'createdAt'],
      lastLogon: ['lastLogon', 'lastLogonDate', 'lastLogonTimestamp'],
    },
  },
  'groups': {
    label: 'Group membership', scope: 'domain', feeds: 'M2-account-creation',
    note: '4728, 4732 and 4756 are absent, so membership changes only show as a diff.',
    identFields: ['group', 'groupName', 'member', 'memberName', 'user'],
    ident: (e) => `${low(field(e, 'group', 'groupName'))}|${low(field(e, 'member', 'memberName', 'user'))}`,
    columns: ['group', 'member', 'memberType'],
  },
  'spns': {
    label: 'SPN inventory', scope: 'domain', feeds: 'M2-kerberoast',
    identFields: ['account', 'username', 'samAccountName', 'spn', 'servicePrincipalName'],
    ident: (e) => `${low(field(e, 'account', 'username', 'samAccountName'))}` +
      `|${low(field(e, 'spn', 'servicePrincipalName'))}`,
    columns: ['account', 'spn', 'passwordLastSet', 'privileged'],
  },
  'vulnerabilities': {
    label: 'Vulnerabilities', scope: 'host', feeds: 'M1V-tt7',
    note: 'Rarity matters as much as severity here. A finding on one host of eighty is a ' +
      'configuration outlier — often a forgotten or rogue system. The same finding on all eighty ' +
      'is a policy gap. They are different problems with different owners.',
    // Plugin id, not CVE: a plugin is the stable Nessus identity, one plugin can
    // carry several CVEs, and several plugins can cover one CVE. Port is folded
    // in so a service on two ports stays two rows once the export carries it.
    identFields: ['pluginId', 'plugin', 'port'],
    ident: (e) => `${low(field(e, 'pluginId', 'plugin'))}|${low(field(e, 'port'))}`,
    columns: ['name', 'risk', 'cvss', 'cve', 'pluginId', 'port', 'solution'],
    // Severity outranks rarity for this repository, unlike everywhere else.
    rank: (e) => ({ critical: 0, high: 1, medium: 2, low: 3, none: 4 }[low(e.attrs?.risk)] ?? 5),
  },
  'software': {
    label: 'Installed software', scope: 'host', feeds: 'M1V-tt4',
    /*
      The version is deliberately NOT in the identity: a bump has to read as a
      change to one row, not as one package leaving and a different one
      arriving. The architecture is, because glibc.x86_64 and glibc.i686 are
      two installed packages, as are the x86 and x64 Visual C++
      redistributables — and most sources do not report it at all, in which
      case this is exactly what it was before.
    */
    identFields: ['name', 'package', 'displayName', 'product', 'arch', 'architecture'],
    ident: (e) => {
      const name = low(field(e, 'name', 'package', 'displayName', 'product'));
      const arch = low(field(e, 'arch', 'architecture'));
      return arch ? `${name}|${arch}` : name;
    },
    columns: ['name', 'version', 'publisher', 'installDate'],
  },
  'command-history': {
    label: 'Command history', scope: 'host', feeds: 'M1H-tt2',
    note: 'Where an operator\'s own hands show. With 4104 suppressed and 4688 patchy, '
      + 'shell history is often the only record of what was actually typed on a host.',
    identFields: ['command', 'commandLine', 'line', 'user', 'userName', 'account'],
    // The command itself is the fact. The same command run twice is one
    // baseline entry; two different commands are never the same entry, which
    // is the property a history list lives or dies on.
    ident: (e) => `${low(field(e, 'user', 'userName', 'account'))}` +
      `|${low(field(e, 'command', 'commandLine', 'line'))}`,
    columns: ['user', 'command', 'shell', 'when'],
  },
  'shares': {
    label: 'Shares', scope: 'host', feeds: 'M1N-tt1',
    note: 'A share nobody remembers publishing, writable by everyone, is how one host '
      + 'becomes several.',
    identFields: ['name', 'share', 'shareName', 'path'],
    /*
      The path discriminates where there is one. Two shares can carry the same
      name at different paths — data on C: and data on D:, or two Samba
      definitions — and keyed on the name alone the second would take the
      first's place. Nothing on file collides today; the reason to close it is
      that two rows folding into one is far below the twenty-row floor the fold
      guard needs before it says anything, so a share would cease to exist in
      silence.
    */
    ident: (e) => {
      const name = low(field(e, 'name', 'share', 'shareName'));
      const path = low(field(e, 'path'));
      if (!name) return path;
      return path ? `${name}|${path}` : name;
    },
    columns: ['name', 'path', 'description', 'permissions', 'type'],
  },
  'host-config': {
    label: 'Host configuration', scope: 'host', feeds: 'M1H-tt5',
    note: 'Security-relevant settings rather than inventory: SMB versions, script-block '
      + 'logging, LSA protection, firewall profile. This is the ground truth for which '
      + 'telemetry exists at all, so a gap here explains a gap everywhere else.',
    identFields: ['setting', 'name', 'key', 'feature', 'protocol', 'policy'],
    ident: (e) => low(field(e, 'setting', 'name', 'key', 'feature', 'protocol', 'policy')),
    columns: ['setting', 'value', 'source'],
  },
  'unclassified': {
    label: 'Unclassified', scope: 'host', feeds: '',
    note: 'The model could not place this format. Kept so nothing is silently dropped.',
    identFields: ['label', 'name'],
    /*
      Content, always. It used to be label-first, and a label is a constant per
      format — every "PSConsoleHistory" row on a host carried the same ident,
      so each overwrote the last and a three-hundred-row console history was
      stored as one row. 879 rows went that way before it was caught.

      For a catch-all repository the only safe identity is the row itself: two
      rows are the same when their content is the same, and never otherwise.
    */
    ident: (e) => contentIdent(e),
    columns: ['label', 'name', 'value'],
  },
};

const low = (v) => String(v ?? '').trim().toLowerCase();

/**
 * Field lookup that does not care how the source spelled it.
 *
 * Real uploads do not use our field names and never will. One collection came
 * back as ECS ("task.name", "host.ip"), another as Velociraptor PascalCase
 * ("UserName", "HomeDirectory"). Matching those literally against `username`
 * and `taskPath` found nothing, and because a row with no identity was skipped,
 * seventeen snapshots stored zero rows while reporting that they had extracted
 * dozens. Strip everything that is not alphanumeric, lowercase, and try a list
 * of aliases.
 */
const normCache = new Map();
const normKey = (k) => {
  let v = normCache.get(k);
  if (v === undefined) {
    v = String(k).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (normCache.size < 5000) normCache.set(k, v);
  }
  return v;
};

/*
  The normalised map is cached against the row object. Building it per call was
  the dominant cost of a large view: displayOf asks for roughly eight fields
  per row, so a 145,000-row repository rebuilt it well over a million times.
  A WeakMap keyed on the attrs object means once per row instead.
*/
const flatCache = new WeakMap();

/*
  Namespaces that describe the machine a collection ran on, not the thing the
  row is about.

  Every ECS export opens with host.name, and the tail alias let it claim the
  bare "name" before task.name or file.name could reach it — so 131 scheduled
  tasks were labelled with the host they were found on rather than the task.
  The full key still resolves, so host.name is reachable as hostName.
*/
const META_NS = new Set(['host', 'os', 'agent', 'client', 'collection']);

function flatten(e) {
  let flat = flatCache.get(e);
  if (flat) return flat;
  flat = Object.create(null);
  for (const [k, v] of Object.entries(e)) {
    const n = normKey(k);
    if (flat[n] == null || flat[n] === '') flat[n] = v;
    // "task.name" should also answer to "name", so index the last segment too.
    const dot = k.lastIndexOf('.');
    if (dot >= 0) {
      // ...unless the namespace describes the machine rather than the row.
      if (!META_NS.has(normKey(k.slice(0, k.indexOf('.'))))) {
        const tail = normKey(k.slice(dot + 1));
        if (tail && flat[tail] == null) flat[tail] = v;
      }
    }
  }
  flatCache.set(e, flat);
  return flat;
}

export function field(e, ...aliases) {
  if (!e || typeof e !== 'object') return '';
  const flat = flatten(e);
  for (const a of aliases) {
    const v = flat[normKey(a)];
    if (v == null || v === '') continue;
    return Array.isArray(v) ? v.join(', ') : String(v);
  }
  return '';
}

/** Last resort so a row is never dropped for want of a name we recognise. */
/*
  Whether an identity was read out of the source or made up.

  A store cannot tell a correct username from a mis-assigned one — both are
  strings in the right column. It can tell one that is not in the source at all,
  and that is the half worth catching: an extraction that invents an identity
  leaves a value appearing nowhere in the text it claims to have read.

  This does not catch mis-pairing. Two real values matched to the wrong rows are
  both present in the source and this will pass them, which is why the note it
  produces says the identity was not found rather than claiming the upload is
  otherwise sound.

  Compared on the alphanumeric runs, because a source lays a value out with
  padding, quotes or a trailing comma that the extracted field does not carry.
*/
const alnum = (v) => String(v ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '');

function inventedIdents(spec, rows, sourceText) {
  const hay = alnum(sourceText);
  if (!hay) return [];
  const missing = new Set();
  for (const { e } of rows) {
    for (const name of spec.identFields ?? []) {
      const v = field(e, name);
      if (!v) continue;
      const needle = alnum(v);
      // A one or two character part is too short to say anything: it matches
      // by accident in any file long enough to matter.
      if (needle.length < 3) continue;
      if (!hay.includes(needle)) missing.add(String(v).trim());
    }
  }
  return [...missing];
}

const contentIdent = (e) => 'raw:' + createHash('sha1')
  .update(JSON.stringify(Object.entries(e ?? {}).sort())).digest('hex').slice(0, 24);
export const isRepo = (r) => Object.prototype.hasOwnProperty.call(REPOS, r);
export const repoList = () =>
  Object.entries(REPOS).map(([key, r]) => ({ key, ...r, ident: undefined, rank: undefined }));

/** Every non-blank line. The yardstick the model's own count is checked against. */
export const countRows = (text) => String(text ?? '').split('\n').filter(l => l.trim()).length;

/**
 * Record one upload.
 *
 * The reconciliation is the point. Model extraction drops rows silently, and
 * in a diffing system a dropped row becomes a phantom NEW item on the next
 * upload — which somebody then investigates. So compare what arrived against
 * what the model says it saw and against a plain line count, and when they
 * disagree say so rather than presenting the deltas as fact.
 */
/**
 * Snapshots — the named collection runs the analyst chooses between.
 *
 * A run is what "is this part of a baseline?" is asking about. Uploads append
 * to one, so a paged collection ends up as a single picture of the estate at
 * one moment instead of a fake time series.
 */
export function createCharSnapshot(db, { repo, note = null, createdBy = null } = {}) {
  if (!isRepo(repo)) throw new Error(`a baseline belongs to one repository; got ${repo ?? 'nothing'}`);
  const id = newId();
  const at = nowIso();
  /*
    The name is generated, never typed. Operators naming their own runs
    produced four conventions in two days, each hand-encoding the repository
    into a field that did not know what a repository was. The note is where
    anything they actually want to say goes.
  */
  const taken = db.prepare('select 1 from char_snapshots where label = ? limit 1');
  const label = uniqueLabel(snapshotLabel(repo, createdBy, at), (c) => Boolean(taken.get(c)));
  db.prepare('insert into char_snapshots (id,repo,label,note,created_by,created_at) values (?,?,?,?,?,?)')
    .run(id, repo, label, note, createdBy, at);
  return getCharSnapshot(db, id);
}

/**
 * Mark a collection finished, which is what makes coverage meaningful.
 *
 * While a snapshot is collecting, a host that has not appeared yet is
 * indistinguishable from one that did not answer, and calling the second thing
 * out on the first would be the crying-wolf failure all over again.
 */
export function setSnapshotComplete(db, id, complete, actor = null) {
  if (!getCharSnapshot(db, id)) throw new Error(`no such snapshot: ${id}`);
  db.prepare('update char_snapshots set completed_at = ?, completed_by = ? where id = ?')
    .run(complete ? nowIso() : null, complete ? actor : null, id);
  return getCharSnapshot(db, id);
}

/**
 * Which declared columns this collection did not gather, as the operator says.
 *
 * A property of the RUN, not of each row: one operator running one command
 * across sixteen hosts has one answer, and asking per row is the difference
 * between a tick and an afternoon. Every row in the run is then read through
 * it, so a column nobody collected stops reading as a column that changed.
 *
 * Replaces the whole set rather than merging, so unticking is possible.
 */
export function setFieldGaps(db, snapshotId, fields, { actor = null, note = null } = {}) {
  const snap = getCharSnapshot(db, snapshotId);
  if (!snap) throw new Error(`no such baseline: ${snapshotId}`);
  // Only columns this repository actually declares. Acknowledging a field that
  // is not compared would read as diligence while doing nothing.
  const declared = new Set(REPOS[snap.repo]?.columns ?? []);
  const unknown = (fields ?? []).map(String).filter(f => !declared.has(f));
  if (unknown.length) throw new Error(`${snap.repo} has no column named ${unknown.join(', ')}`);

  const want = [...new Set((fields ?? []).map(String))];
  const before = fieldGapsFor(db, snapshotId).map(g => g.field);
  const at = nowIso();
  db.exec('begin');
  try {
    db.prepare('delete from char_field_gaps where snapshot_id = ?').run(snapshotId);
    const ins = db.prepare(
      'insert into char_field_gaps (snapshot_id,field,note,ack_by,ack_at) values (?,?,?,?,?)');
    for (const f of want) ins.run(snapshotId, f, note, actor, at);
    db.exec('commit');
  } catch (e) { db.exec('rollback'); throw e; }

  // Audited like a commit: it changes what counts as a change for everyone.
  writeAudit(db, {
    analyst: actor, action: 'characterization.acknowledge',
    targetType: 'char_snapshot', targetId: snapshotId,
    before: { gaps: before }, after: { gaps: want, note },
  });
  return want;
}

/*
  Which OS family a host belongs to, from the free-text os column terrain
  supplies.

  Ordered, and network before the rest, because "Cisco IOS" contains none of the
  Windows or Linux markers but "PAN-OS" and "JunOS" would fall through to
  unknown if the network patterns ran last against a looser rule.

  Unknown is a real answer. An unrecorded OS is the common case on a discovered
  host, and guessing one here is the mistake the terrain loader refuses to make
  everywhere else: an empty field is honest, a guessed one is a fact the team
  will act on.
*/
const OS_FAMILIES = [
  ['network', /\b(cisco|ios-?xe|ios-?xr|junos|nx-?os|pan-?os|fortios|routeros|arubaos|switch|router|firewall)\b/i],
  ['windows', /\b(windows|microsoft|win(?:2k|2\d{3}|7|8|10|11|xp)?\d*)\b/i],
  ['linux', /\b(linux|ubuntu|debian|centos|rhel|red\s*hat|fedora|suse|alpine|arch|amzn|amazon\s*linux|oracle\s*linux|gentoo)\b/i],
  ['unix', /\b(aix|solaris|hp-?ux|freebsd|openbsd|netbsd|bsd)\b/i],
  ['macos', /\b(mac\s*os|macos|darwin|osx)\b/i],
];

/** @returns {'windows'|'linux'|'network'|'unix'|'macos'|'unknown'} */
export function osFamily(os) {
  const s = String(os ?? '').trim();
  if (!s) return 'unknown';
  for (const [family, re] of OS_FAMILIES) if (re.test(s)) return family;
  return 'unknown';
}

/**
 * The OS families a baseline actually covers, with how many hosts of each.
 *
 * The point is not to block a mixed run — an estate-wide collection is a
 * legitimate thing to take — but to stop the mix being invisible at the moment
 * somebody acknowledges a field gap across all of it.
 */
export function osFamiliesIn(db, snapshotId) {
  const rows = db.prepare(`
    select distinct e.host as host
    from char_entities e join char_uploads u on u.id = e.upload_id
    where u.snapshot_id = ? and e.host is not null and e.host <> ''`).all(snapshotId);

  const byName = new Map(db.prepare('select name, os from hosts').all()
    .map(h => [String(h.name).toLowerCase(), h.os]));

  const counts = new Map();
  for (const r of rows) {
    const f = osFamily(byName.get(String(r.host).toLowerCase()));
    counts.set(f, (counts.get(f) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([family, hosts]) => ({ family, hosts }))
    .sort((a, b) => b.hosts - a.hosts || a.family.localeCompare(b.family));
}

/** Every acknowledged gap in the case, for the report's coverage section. */
export const allFieldGaps = (db) => db.prepare(`
  select s.repo as repo, g.field as field, g.note as note, g.ack_by as ack_by
  from char_field_gaps g join char_snapshots s on s.id = g.snapshot_id
  order by s.repo, g.field`).all();

export const fieldGapsFor = (db, snapshotId) => db.prepare(
  'select field, note, ack_by, ack_at from char_field_gaps where snapshot_id = ? order by field')
  .all(snapshotId);

/** Every run's acknowledged gaps for one repository, in one query. */
function gapMap(db, repo) {
  const rows = db.prepare(`select g.snapshot_id sid, g.field from char_field_gaps g
    join char_snapshots s on s.id = g.snapshot_id where s.repo = ?`).all(repo);
  const by = new Map();
  for (const r of rows) {
    if (!by.has(r.sid)) by.set(r.sid, new Set());
    by.get(r.sid).add(r.field);
  }
  return by;
}
const NO_GAPS = new Set();

/**
 * How two collections of the same thing differ, column by column.
 *
 * Compared over the repository's declared columns through the alias lookup,
 * not over raw JSON. Raw JSON compared collection plumbing too: 47 accounts
 * read as changed because a Velociraptor _id differed between two exports of
 * an identical machine.
 *
 * A column with a value on one side and nothing on the other is the case this
 * whole mechanism exists for. If the run that lacks it has acknowledged not
 * collecting it, that is not a change — it is a question nobody asked.
 */
function compareRows(repo, before, after, gapsBefore, gapsAfter) {
  const changes = [];
  const gaps = [];
  for (const c of REPOS[repo].columns) {
    const vb = colValue(repo, before, c);
    const va = colValue(repo, after, c);
    if (vb === va) continue;
    if (vb && va) { changes.push({ field: c, from: vb, to: va }); continue; }
    const missingIn = va ? 'before' : 'after';
    const acknowledged = (missingIn === 'before' ? gapsBefore : gapsAfter).has(c);
    (acknowledged ? gaps : changes).push({
      field: c, from: vb || null, to: va || null, missingIn, acknowledged,
    });
  }
  return { changes, gaps };
}

export const getCharSnapshot = (db, id) =>
  db.prepare('select * from char_snapshots where id = ?').get(id) ?? null;

/**
 * Newest first, with how much each holds — what the picker shows.
 *
 * Scoped to one repository, because that is the whole point: every picker used
 * to list all twenty runs whatever you were looking at, and processes had data
 * in two of them. Runs with no repository at all are legacy empties and are
 * never offered.
 */
export const listCharSnapshots = (db, repo = null) =>
  db.prepare(`select s.*,
      (select count(distinct u.host) from char_uploads u where u.snapshot_id = s.id) hosts,
      (select count(*) from char_uploads u where u.snapshot_id = s.id) uploads,
      (select count(*) from char_entities e
         join char_uploads u on u.id = e.upload_id where u.snapshot_id = s.id) rows
    from char_snapshots s
    where ${repo ? 's.repo = ?' : 's.repo is not null'}
    order by s.created_at desc, s.rowid desc`).all(...(repo ? [repo] : []));

/** The run an upload joins when the analyst has not picked one yet. */
export function ensureCharSnapshot(db, id, { repo, createdBy = null } = {}) {
  if (id) {
    const found = getCharSnapshot(db, id);
    if (found) {
      /*
        Refuse rather than reassign. A processes upload landing in an accounts
        baseline is how the catch-all got its data, and silently moving it
        would put rows in a repository the operator was not looking at.
      */
      if (repo && found.repo && found.repo !== repo) {
        throw new Error(`${found.label} is a ${found.repo} baseline; this upload is ${repo}`);
      }
      return found;
    }
  }
  if (!isRepo(repo)) throw new Error('cannot choose a baseline without knowing the repository');
  const latest = db.prepare(
    'select * from char_snapshots where repo = ? order by created_at desc, rowid desc limit 1').get(repo);
  return latest ?? createCharSnapshot(db, { repo, createdBy: createdBy ?? 'system' });
}

export function stageSnapshot(db, {
  repo, host, sourceFormat, claimedRows, countedRows, entities = [],
  analyst = null, sessionId = null, fileId = null, snapshotId = null,
  kind = 'collection', staged = false,
  // The text the rows were read out of, when the caller still has it. Optional:
  // a check that cannot run must not invent a verdict.
  sourceText = null,
}) {
  if (!isRepo(repo)) throw new Error(`unknown repository: ${repo}`);
  const spec = REPOS[repo];
  const id = newId();
  const ts = nowIso();
  const h = String(host ?? '').trim() || null;
  const run = ensureCharSnapshot(db, snapshotId, { repo, createdBy: analyst });

  const rows = entities.filter(e => e && typeof e === 'object');

  /*
    Work out what will actually be stored BEFORE reconciling. Reconciling
    against what the model returned was the flaw that hid a total failure:
    seventeen snapshots reported extracting dozens of rows and stored none,
    because every row was dropped for having field names we did not recognise,
    and 47 == 47 looked healthy the whole time. What matters is what survived
    to the table.
  */
  const rowsToStore = [];
  const seen = new Set();
  let unnamed = 0;
  for (const e of rows) {
    let ident = spec.ident(e);
    if (!ident || ident === '|' || /^\|+$/.test(ident)) {
      // Never drop it. A row we cannot name is still evidence of something,
      // and losing it silently is the failure mode this whole file guards.
      ident = contentIdent(e);
      unnamed++;
    }
    if (seen.has(ident)) continue;
    seen.add(ident);
    rowsToStore.push({ ident, e });
  }

  const invented = sourceText ? inventedIdents(spec, rowsToStore, sourceText) : [];
  const { status, note } = reconcile({
    stored: rowsToStore.length, returned: rows.length, claimed: claimedRows, unnamed, invented,
  });

  db.exec('begin');
  try {
    /*
      committed_at is what makes an upload visible. Imports through the review
      panel stage uncommitted so nothing reaches a baseline unseen; everything
      else commits on arrival, so this stays the default rather than a trap.
    */
    db.prepare(`insert into char_uploads
      (id, snapshot_id, repo, host, source_format, file_id, session_id, analyst,
       claimed_rows, counted_rows, extracted_rows, returned_rows, status, note, ts,
       kind, committed_at)
      values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(id, run.id, repo, h, sourceFormat ?? null, fileId, sessionId, analyst,
        num(claimedRows), num(countedRows), rowsToStore.length, rows.length, status, note, ts,
        kind, staged ? null : ts);

    const ins = db.prepare(`insert into char_entities
      (id, upload_id, repo, host, ident, label, attrs, ts) values (?,?,?,?,?,?,?,?)`);
    /*
      A snapshot holds each distinct thing once. Collapsing is expected, not
      loss: a Windows host runs dozens of svchost.exe from the same path, and
      counting instances would make every snapshot differ from the last for no
      reason anyone cares about.
    */
    for (const { ident, e } of rowsToStore) {
      ins.run(newId(), id, repo, h, ident, labelOf(repo, e), JSON.stringify(e), ts);
    }
    db.exec('commit');
  } catch (err) {
    db.exec('rollback');
    throw err;
  }
  return getUpload(db, id);
}

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : null);

function reconcile({ stored, returned, claimed, unnamed, invented = [] }) {
  const c = num(claimed);
  if (stored === 0) return { status: 'incomplete', note: 'nothing was stored' };

  /*
    The model's own count is the only trustworthy yardstick. A non-blank line
    count is not one: an ECS CSV spends about eight lines per task and a
    Velociraptor JSON export about thirty-two per user, so comparing rows to
    lines flagged every honest upload as short and taught the team to ignore
    the warning — which is worse than not warning at all. If the model did not
    report a count we simply do not know, and we say nothing.
  */
  /*
    Compare what the model RETURNED against what it claimed, not what was
    stored: collapsing duplicates legitimately reduces the stored count (a host
    runs dozens of svchost.exe) and must never read as loss.
  */
  if (c != null && returned < c) {
    const lost = c - returned;
    return {
      status: 'incomplete',
      note: `the model reported ${c} rows in the source but ${stored} were stored; ` +
        `${lost} ${lost === 1 ? 'is' : 'are'} missing, so deltas from this snapshot are not reliable`,
    };
  }
  /*
    Ahead of the unnamed check: a made-up identity is the worse finding. An
    unnamed row announces itself as unusable, and this one does not — it looks
    like data, which is how the row-order usernames in domain-accounts survived.
  */
  if (invented.length) {
    const shown = invented.slice(0, 5).join(', ');
    const rest = invented.length > 5 ? ` and ${invented.length - 5} more` : '';
    return {
      status: 'incomplete',
      note: `${invented.length} identity value(s) do not appear in the source this was read ` +
        `from — ${shown}${rest}. They were not read out of it, so check the extraction before ` +
        'trusting any row here. Note this cannot see two real values matched to the wrong rows.',
    };
  }
  if (unnamed) {
    return {
      status: 'incomplete',
      note: `${unnamed} row(s) had no field this repository recognises as an identity, so they ` +
        'are stored under a content hash and will not diff against anything. Check the field names.',
    };
  }

  /*
    Collapsing is expected — a host runs dozens of svchost.exe from one path —
    but there is a rate past which it stops being duplicates and starts being a
    broken identity. The catch-all keyed rows on a label that was constant per
    format, so three hundred console-history lines stored as one row, and this
    function called it ok the whole time: every fold looks legitimate when the
    only question asked is whether the model returned what it claimed.

    Deliberately loose. Ten rows folding to four is a normal inventory; two
    hundred folding to one is an identity that is not identifying anything.
  */
  const folded = returned - stored;
  if (returned >= FOLD_FLOOR && stored / returned <= FOLD_RATIO) {
    return {
      status: 'incomplete',
      note: `${returned} rows collapsed to ${stored}: ${folded} shared an identity with ` +
        'another row. Some folding is normal, this much usually means the identity for this ' +
        'repository is not reading the fields this source uses.',
    };
  }
  return { status: 'ok', note: null };
}

/** Below this a small fold is unremarkable; above it, a big one is suspicious. */
const FOLD_FLOOR = 20;
const FOLD_RATIO = 0.25;

/**
 * What to call this row in the table.
 *
 * Declared columns first, then the repository's own identFields, then a
 * generic sweep for anything a human would read as a name. The identFields
 * step matters because a source that spells the identity differently from the
 * column list would otherwise show as "unnamed" while the row itself was
 * stored and diffed perfectly well — 47 domain accounts read that way, each
 * carrying a full name nothing looked at.
 */
export function labelOf(repo, e) {
  for (const c of REPOS[repo].columns) {
    const v = field(e, c);
    if (v) return v.slice(0, 200);
  }
  for (const c of REPOS[repo].identFields ?? []) {
    const v = field(e, c);
    if (v) return v.slice(0, 200);
  }
  const generic = field(e, 'name', 'label', 'title', 'fullName', 'displayName',
    'description', 'id');
  return (generic || 'unnamed').slice(0, 200);
}

/**
 * What a declared column answers to: its own name, plus any alias the
 * repository declares for it.
 *
 * One place, because the table, the diff and the gap check must agree about
 * whether a column has a value. When they disagreed, a column rendered blank
 * while the diff called the row changed for a field the analyst could not see.
 */
export const aliasesFor = (repo, col) => REPOS[repo]?.columnAliases?.[col] ?? [col];
export const colValue = (repo, e, col) => field(e, ...aliasesFor(repo, col));

/**
 * Collection plumbing, not facts about a host.
 *
 * A Velociraptor export carries _id and host on every row. They differ between
 * two collections of the identical machine, which made 47 unchanged accounts
 * read as changed, and they tell an analyst nothing the row's own host column
 * does not already say.
 */
const METADATA = new Set(['_id', '_ts', '_source', '_collection', 'host', 'hostname',
  'fqdn', 'computer', 'computername', 'agent', 'clientid', 'flowid', 'artifact']);

/**
 * The declared columns, resolved through the alias lookup, plus whatever else
 * the row carries. Done here rather than in the browser so field naming is
 * normalised in exactly one place — an ECS row spelling it "task.name" should
 * appear under Name like everything else.
 */
function displayOf(repo, attrs) {
  const out = {};
  const consumed = new Set();
  for (const c of REPOS[repo].columns) {
    const aliases = aliasesFor(repo, c);
    for (const a of aliases) consumed.add(normKey(a));
    const v = field(attrs, ...aliases);
    if (v) out[c] = v;
  }
  /*
    Then anything else the row carries, under whatever the source called it.
    Showing "GroupNames" is honest when we did not recognise it as "groups" —
    hiding it because the spelling was unfamiliar is how data disappears.
    Arrays are joined; a group list must not render as [object Object].
  */
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (Object.keys(out).length >= 8) break;
    const key = String(k).split('.').pop();
    if (out[key] != null || consumed.has(normKey(key)) || METADATA.has(normKey(key))) continue;
    if (v == null || v === '') continue;
    if (Array.isArray(v)) { if (v.length) out[key] = v.join(', '); continue; }
    if (typeof v === 'object') continue;
    out[key] = String(v);
  }
  return out;
}

// --- reading ----------------------------------------------------------------

export const getUpload = (db, id) =>
  db.prepare('select * from char_uploads where id = ?').get(id) ?? null;

export const listSnapshots = (db, { repo, host } = {}) => {
  const where = [];
  const args = [];
  if (repo) { where.push('u.repo = ?'); args.push(repo); }
  if (host) { where.push('u.host is ?'); args.push(host); }
  return db.prepare(`select u.*, s.label snapshot_label from char_uploads u
    left join char_snapshots s on s.id = u.snapshot_id
    ${where.length ? 'where ' + where.join(' and ') : ''}
    order by u.ts desc, u.rowid desc`).all(...args);
};

/**
 * The snapshots holding data for one repo and host, newest first.
 *
 * "Previous" is the next most recent snapshot THAT HAS DATA for this repo and
 * host — not simply the one before it. Without that, a collection run where
 * somebody only gathered accounts would report every scheduled task on those
 * hosts as GONE, which is a lie the analyst would have to disprove by hand.
 */
function snapshotsWith(db, repo, host) {
  return chainMap(db, repo).get(host ?? null) ?? [];
}

/**
 * Every host's snapshot chain for a repository, in one query.
 *
 * This used to be a per-host three-table join that reached into char_entities
 * purely to prove the host had data. At ninety hosts over four hundred
 * thousand rows that was five and a half seconds of the eight the whole view
 * took — the entity table was being scanned ninety times to answer a question
 * one grouped query answers once.
 */
function chainMap(db, repo) {
  const rows = db.prepare(`select u.host, s.id, s.label, s.created_at, s.completed_at, s.rowid srow
    from char_uploads u
    join char_snapshots s on s.id = u.snapshot_id
    where u.repo = ? and u.kind = 'collection' and u.committed_at is not null
      and exists (select 1 from char_entities e where e.upload_id = u.id)
    group by u.host, s.id
    order by s.created_at desc, s.rowid desc`).all(repo);

  const by = new Map();
  for (const r of rows) {
    const k = r.host ?? null;
    if (!by.has(k)) by.set(k, []);
    by.get(k).push({ id: r.id, label: r.label, created_at: r.created_at, completed_at: r.completed_at });
  }
  return by;
}

/**
 * Every distinct row for a repo and host within one snapshot.
 *
 * Unioned across that snapshot's uploads, because a paged collection arrives
 * in chunks and all of them describe the same moment. Later chunks win on
 * conflict so a re-upload can correct a field, but nothing is ever removed —
 * a snapshot only grows.
 */
function rowsIn(db, snapshotId, repo, host) {
  // Manual uploads contribute rows but never presence, so a correction is
  // visible without making the host count as having reported.
  const rows = db.prepare(`select e.* from char_entities e
    join char_uploads u on u.id = e.upload_id
    where u.snapshot_id = ? and e.repo = ? and e.host is ?
      and u.committed_at is not null
    order by e.ts, e.rowid`).all(snapshotId, repo, host ?? null);
  const by = new Map();
  for (const r of rows) by.set(r.ident, { ...r, attrs: parse(r.attrs) });
  return [...by.values()];
}

/** Was any upload in this snapshot, for this scope, short of what it claimed? */
function scopeIsConfident(db, snapshotId, repo, host) {
  const bad = db.prepare(`select count(*) n from char_uploads
    where snapshot_id = ? and repo = ? and host is ? and status <> 'ok'
      and committed_at is not null`)
    .get(snapshotId, repo, host ?? null).n;
  return bad === 0;
}

const parse = (s) => { try { return JSON.parse(s ?? '{}'); } catch { return {}; } };

/** Hosts that have ever contributed to a repository. */
export const hostsIn = (db, repo) =>
  db.prepare(`select distinct host from char_uploads
    where repo = ? and kind = 'collection' and committed_at is not null
    order by host`).all(repo).map(r => r.host);

/** Which hosts a given snapshot actually collected for a repository. */
const hostsCollectedIn = (db, repo, snapshotId) =>
  db.prepare(`select distinct u.host from char_uploads u
    where u.repo = ? and u.snapshot_id = ?
      and u.kind = 'collection' and u.committed_at is not null
      and exists (select 1 from char_entities e where e.upload_id = u.id)`)
    .all(repo, snapshotId).map(r => r.host);

/**
 * Hosts that ought to have reported but did not, and hosts never seen at all.
 *
 * The first is a regression and can be a finding: an agent that stopped
 * answering between two collections is what disabling the collection path
 * looks like from here. The second is a coverage gap, which is a different
 * question with a different owner.
 *
 * Gaps are scoped to enclaves that have been characterized at all. Unscoped
 * this reads ninety-one hosts forever -- thirty-one of them CPT tooling,
 * twenty-six of them OT nobody intends to scan -- and a band that always
 * alarms is a band nobody reads.
 */
function coverageFor(db, repo, { current, against, seen }) {
  const reasons = new Map(db.prepare('select * from char_host_status where repo = ?')
    .all(repo).map(r => [r.host, r]));

  // Absent from the current side, present on the side it is compared against.
  const expected = against ? hostsCollectedIn(db, repo, against.id) : [];
  const here = new Set(current ? hostsCollectedIn(db, repo, current.id) : seen);
  const missing = expected.filter(h => h && !here.has(h)).map(h => ({
    host: h,
    lastSeen: against.label,
    lastSeenAt: against.created_at,
    reason: reasons.get(h)?.reason ?? null,
    note: reasons.get(h)?.note ?? null,
  }));

  const characterized = new Set(hostsIn(db, repo).filter(Boolean));
  const terrain = db.prepare('select name, ip, enclave from hosts').all();
  const liveEnclaves = new Set(terrain
    .filter(t => characterized.has(t.name) || characterized.has(t.ip))
    .map(t => t.enclave).filter(Boolean));

  const never = {};
  for (const t of terrain) {
    if (!t.enclave || !liveEnclaves.has(t.enclave)) continue;
    if (characterized.has(t.name) || characterized.has(t.ip)) continue;
    (never[t.enclave] = never[t.enclave] ?? []).push(t.name);
  }

  return {
    // While a snapshot is still collecting, a host that has not arrived yet is
    // not a finding. Say so neutrally and withhold the reason picker.
    collecting: Boolean(current && !current.completed_at),
    missing,
    neverCharacterized: Object.entries(never)
      .map(([enclave, hosts]) => ({ enclave, hosts: hosts.sort(), count: hosts.length }))
      .sort((a, b) => b.count - a.count),
  };
}

export function setHostStatus(db, repo, host, { reason, note = null, actor = null }) {
  if (!isRepo(repo)) throw new Error(`unknown repository: ${repo}`);
  if (!reason) {
    db.prepare('delete from char_host_status where repo = ? and host = ?').run(repo, host);
    return null;
  }
  db.prepare(`insert into char_host_status (repo,host,reason,note,set_by,set_at) values (?,?,?,?,?,?)
    on conflict(repo,host) do update set reason=excluded.reason, note=excluded.note,
      set_by=excluded.set_by, set_at=excluded.set_at`)
    .run(repo, host, reason, note, actor, nowIso());
  return db.prepare('select * from char_host_status where repo = ? and host = ?').get(repo, host);
}

export function repoView(db, repo, { host, q, snapshot, against: againstId, filters } = {}) {
  if (!isRepo(repo)) throw new Error(`unknown repository: ${repo}`);
  const allHosts = hostsIn(db, repo);
  const hosts = host ? [host] : allHosts;

  const rows = [];
  let incomplete = 0;
  const comparing = new Set();
  const pinned = snapshot ? getCharSnapshot(db, snapshot) : null;
  const pinnedAgainst = againstId ? getCharSnapshot(db, againstId) : null;

  /*
    One pass over the data, not two. Rarity used to walk every host's current
    snapshot and the diff then read exactly the same rows again — at estate
    scale that second pass was seconds, not milliseconds. Collect once, count
    from what was collected.
  */
  const allGaps = gapMap(db, repo);
  const perHost = [];
  const counts = new Map();
  for (const h of allHosts) {
    const chain = snapshotsWith(db, repo, h);
    const cur = pinned ?? chain[0];
    if (!cur || (pinned && !chain.some(c => c.id === pinned.id))) continue;
    const now = rowsIn(db, cur.id, repo, h);
    for (const e of now) counts.set(e.ident, (counts.get(e.ident) ?? 0) + 1);
    if (!host || h === host) perHost.push({ h, chain, cur, now });
  }
  const total = allHosts.length;

  for (const { h, chain, cur, now } of perHost) {
    /*
      An explicit comparison is literal for every host. Asking for B and
      silently being given C because B had no data for this host would be a
      lie, and "absent from B" is exactly what the coverage band is for.
    */
    const current = cur;
    const prior = pinned
      ? (pinnedAgainst && chain.some(c => c.id === pinnedAgainst.id) ? pinnedAgainst : null)
      : chain[1];
    const confident = scopeIsConfident(db, current.id, repo, h);
    if (!confident) incomplete++;
    comparing.add(prior ? `${current.label} against ${prior.label}` : `${current.label} (first)`);

    const before = prior ? rowsIn(db, prior.id, repo, h) : null;
    const beforeBy = new Map((before ?? []).map(e => [e.ident, e]));

    const gapsNow = allGaps.get(current.id) ?? NO_GAPS;
    const gapsThen = prior ? (allGaps.get(prior.id) ?? NO_GAPS) : NO_GAPS;

    for (const e of now) {
      const was = beforeBy.get(e.ident);
      let change = 'baseline';
      let diff = null;
      if (before) {
        if (!was) change = 'new';
        else {
          diff = compareRows(repo, was.attrs, e.attrs, gapsThen, gapsNow);
          // A row that differs ONLY by a field somebody acknowledged not
          // collecting is not a changed asset, and must not be counted as one.
          change = diff.changes.length ? 'changed' : diff.gaps.length ? 'partial' : 'same';
        }
      }
      rows.push({
        id: e.id, host: h, ident: e.ident, label: e.label, attrs: e.attrs,
        display: displayOf(repo, e.attrs),
        change,
        changes: diff?.changes.length ? diff.changes : null,
        gaps: diff?.gaps.length ? diff.gaps : null,
        previous: was && change !== 'same' && change !== 'baseline' ? was.attrs : null,
        hosts: counts.get(e.ident) ?? 1, totalHosts: total,
        // A snapshot that lost rows produces deltas nobody should act on.
        confident,
        snapshotId: current.id, snapshot: current.label, ts: current.created_at,
        previousSnapshotId: prior?.id ?? null,
      });
    }

    // Things that were there last time and are not now. Worth as much as new.
    for (const e of before ?? []) {
      if (now.some(n => n.ident === e.ident)) continue;
      rows.push({
        id: e.id, host: h, ident: e.ident, label: e.label, attrs: e.attrs,
        display: displayOf(repo, e.attrs),
        change: 'gone', previous: e.attrs,
        hosts: counts.get(e.ident) ?? 0, totalHosts: total,
        confident,
        snapshotId: current.id, snapshot: current.label, ts: current.created_at,
      });
    }
  }

  /*
    Filtering happens here, before the display cap. Filtering a truncated table
    in the browser would answer "absent" when it meant "not in the first 500",
    which in a hunt tool is worse than having no filter.
  */
  const needle = String(q ?? '').trim().toLowerCase();
  const cols = Object.entries(filters ?? {})
    .map(([k, v]) => [k, String(v ?? '').trim().toLowerCase()])
    .filter(([, v]) => v);

  let filtered = needle
    ? rows.filter(r => (r.label + ' ' + r.ident + ' ' + JSON.stringify(r.attrs)).toLowerCase().includes(needle))
    : rows;
  for (const [col, want] of cols) {
    filtered = filtered.filter(r => {
      const have = col === 'host' ? String(r.host ?? '')
        : col === 'change' ? String(r.change ?? '')
          : String(r.display?.[col] ?? field(r.attrs, col) ?? '');
      return have.toLowerCase().includes(want);
    });
  }

  /*
    Change first, because the delta is what anyone acts on. Then whatever the
    repository considers most urgent — severity for vulnerabilities — and then
    rarity, because the thing on one host of eighty is the outlier worth
    looking at. Alphabetical last, so the order is at least stable.
  */
  // partial sits below the real deltas: worth seeing, never worth chasing.
  const order = { new: 0, changed: 1, gone: 2, partial: 3, baseline: 4, same: 5 };
  const rank = REPOS[repo].rank ?? (() => 0);
  filtered.sort((a, b) =>
    (order[a.change] - order[b.change]) || (rank(a) - rank(b)) ||
    (a.hosts - b.hosts) || a.label.localeCompare(b.label));

  /*
    The repository's own two most recent runs, not one host's view of them.

    These were read off perHost[0] — whichever host sorts first alphabetically —
    and that is exactly the host whose chain does not reach the newest run when
    it is the one that stopped reporting. `against` then resolved to null and
    coverageFor returned an empty `missing` however many hosts had gone dark, so
    whether the tool noticed a silent collector depended on how the estate
    happened to name its machines.

    Filtering to a single host keeps the per-host chain, because there the
    question really is about that host's own history.
  */
  const repoRuns = host ? null : listCharSnapshots(db, repo);
  const currentSnap = pinned ?? (repoRuns ? repoRuns[0] : perHost[0]?.cur) ?? null;
  const againstSnap = pinnedAgainst
    ?? (repoRuns ? repoRuns[1] : perHost[0]?.chain[1]) ?? null;

  return {
    repo, ...repoList().find(r => r.key === repo),
    hosts: allHosts,
    incompleteSnapshots: incomplete,
    comparing: [...comparing].slice(0, 3),
    snapshot: currentSnap ? { id: currentSnap.id, label: currentSnap.label, completedAt: currentSnap.completed_at } : null,
    against: againstSnap ? { id: againstSnap.id, label: againstSnap.label } : null,
    coverage: coverageFor(db, repo, { current: currentSnap, against: againstSnap, seen: hosts }),
    // The true filtered total, so the truncation notice never understates it.
    matched: filtered.length,
    filters: Object.fromEntries(cols),
    counts: {
      total: rows.length,
      new: rows.filter(r => r.change === 'new').length,
      gone: rows.filter(r => r.change === 'gone').length,
      changed: rows.filter(r => r.change === 'changed').length,
      // Reported separately and deliberately not folded into changed.
      partial: rows.filter(r => r.change === 'partial').length,
    },
    fieldGaps: withOsMix(db, fieldGapSummary(rows)),
    rows: filtered,
  };
}

/**
 * The columns driving gaps right now, so acknowledging can happen at scale.
 *
 * An operator should never tick a box per row. This says "90 rows differ only
 * because username is absent, on these two runs" and the panel offers one
 * button for the lot.
 */
/*
  What acknowledging is about to cover.

  A gap is acknowledged for a whole run, so on a run that spans OS families one
  click silences a real gap and a meaningless one together — "shell not
  collected" is a genuine gap on Linux and a category error on Windows. Nothing
  stops that, and probably nothing should: an estate-wide collection is a
  legitimate thing to take, and refusing one would trade a quiet
  over-acknowledgement for a loud obstruction.

  What was wrong is that the mix was invisible at the moment of the decision.
  This attaches it so the panel can say so, and the operator is choosing rather
  than assuming.
*/
function withOsMix(db, summary) {
  const ids = new Set();
  for (const c of summary.candidates) for (const sid of c.snapshots) if (sid) ids.add(sid);
  if (!ids.size) return { ...summary, osMix: [] };

  const totals = new Map();
  for (const sid of ids) {
    for (const { family, hosts } of osFamiliesIn(db, sid)) {
      totals.set(family, (totals.get(family) ?? 0) + hosts);
    }
  }
  // Only families that carry meaning for this decision. Unknown is not a family
  // an operator can reason about, and listing it invites treating it as one.
  const named = [...totals.entries()]
    .filter(([f]) => f !== 'unknown')
    .map(([family, hosts]) => ({ family, hosts }))
    .sort((a, b) => b.hosts - a.hosts);
  return { ...summary, osMix: named.length > 1 ? named : [] };
}

function fieldGapSummary(rows) {
  const candidates = new Map();
  const acknowledged = new Map();
  const bump = (into, field, snapshotId) => {
    if (!into.has(field)) into.set(field, { field, rows: 0, snapshots: new Set() });
    const e = into.get(field);
    e.rows++;
    if (snapshotId) e.snapshots.add(snapshotId);
  };
  for (const r of rows) {
    // An unacknowledged gap arrives as a change carrying missingIn; a real
    // value change does not carry it at all.
    for (const c of r.changes ?? []) {
      if (!c.missingIn) continue;
      bump(candidates, c.field, c.missingIn === 'after' ? r.snapshotId : r.previousSnapshotId);
    }
    for (const g of r.gaps ?? []) {
      bump(acknowledged, g.field, g.missingIn === 'after' ? r.snapshotId : r.previousSnapshotId);
    }
  }
  const out = (m) => [...m.values()]
    .map(e => ({ ...e, snapshots: [...e.snapshots] }))
    .sort((a, b) => b.rows - a.rows);
  return { candidates: out(candidates), acknowledged: out(acknowledged) };
}

/**
 * What the collections currently say about one host.
 *
 * For the host drawer on the map, which had no idea characterization existed:
 * an analyst clicking a node could see its findings and its verdict but not
 * one fact anybody had actually collected from it.
 *
 * Newest committed snapshot per repository, not a merge across all of them —
 * "what is on this box now" is the question, and answering it with the union
 * of every collection ever taken would put processes that exited last week
 * beside ones running today.
 */
export function hostCharacterization(db, host, { samples = 6 } = {}) {
  const name = String(host ?? '').trim();
  if (!name) return [];

  const repos = db.prepare(`select distinct u.repo from char_uploads u
    join char_entities e on e.upload_id = u.id
    where e.host = ? and u.committed_at is not null`).all(name).map(r => r.repo);

  const out = [];
  for (const repo of repos) {
    if (!isRepo(repo)) continue;
    const [current] = snapshotsWith(db, repo, name);
    if (!current) continue;
    const rows = rowsIn(db, current.id, repo, name);
    out.push({
      repo,
      label: REPOS[repo].label,
      snapshot: current.label,
      at: current.created_at,
      columns: REPOS[repo].columns,
      rows: rows.length,
      sample: rows.slice(0, samples).map(e => ({
        label: e.label, display: displayOf(repo, e.attrs),
      })),
    });
  }
  return out.sort((a, b) => a.label.localeCompare(b.label));
}

/** Repository list with how much is in each, for the tab's left rail. */
export function summary(db) {
  return repoList().map(r => {
    const snaps = db.prepare('select count(*) n from char_uploads where repo = ?').get(r.key).n;
    const hosts = hostsIn(db, r.key).length;
    let changed = 0;
    if (snaps) {
      const v = repoView(db, r.key);
      changed = v.counts.new + v.counts.gone + v.counts.changed;
    }
    return { ...r, snapshots: snaps, hosts, changed };
  });
}

/**
 * The lookup evidence mode needs: is this thing normal here?
 *
 * Returns matches with their rarity, which is the part that answers the
 * question — "present on 1 of 82 hosts" and "present on 82 of 82" are very
 * different answers to "is this normal".
 */
export function queryBaseline(db, { repo, host, q, limit = 40 } = {}) {
  const repos = repo && isRepo(repo) ? [repo] : Object.keys(REPOS);
  const out = [];
  for (const r of repos) {
    const view = repoView(db, r, { host, q });
    for (const row of view.rows.slice(0, limit)) {
      out.push({
        repo: r, host: row.host, label: row.label, attrs: row.attrs,
        change: row.change, seenOn: `${row.hosts} of ${row.totalHosts} host(s)`,
        confident: row.confident,
      });
    }
    if (out.length >= limit) break;
  }
  return out.slice(0, limit);
}

/**
 * What a staged import is about to put in the baseline.
 *
 * Per repository, per host, with counts, warnings and sample rows. A preview
 * reading only "131 rows" would have caught none of the three failures this
 * step exists to prevent: zero rows stored, the wrong host, and job manifests
 * filed as if they were things on a machine.
 */
export function stagedPreview(db, { sessionId } = {}) {
  const where = sessionId ? 'and u.session_id = ?' : '';
  const args = sessionId ? [sessionId] : [];
  const uploads = db.prepare(`select u.*, s.label snapshot_label from char_uploads u
    left join char_snapshots s on s.id = u.snapshot_id
    where u.committed_at is null ${where} order by u.ts`).all(...args);

  return uploads.map(u => {
    const rows = db.prepare('select * from char_entities where upload_id = ? limit 4').all(u.id)
      .map(r => ({ label: r.label, attrs: parse(r.attrs) }));
    const stored = db.prepare('select count(*) n from char_entities where upload_id = ?').get(u.id).n;
    // Would this land on a host the repository has never seen? Usually a
    // mis-attribution, occasionally a genuinely new box; either way, worth
    // saying before it is committed rather than after.
    const known = u.host ? hostsIn(db, u.repo).includes(u.host) : false;
    return {
      id: u.id, repo: u.repo, host: u.host, sourceFormat: u.source_format,
      snapshot: u.snapshot_label, snapshotId: u.snapshot_id,
      rows: stored, claimed: u.claimed_rows, status: u.status, note: u.note,
      newHost: Boolean(u.host) && !known,
      unattributed: !u.host,
      samples: rows,
    };
  });
}

/**
 * Promote staged uploads into the live baseline.
 *
 * Audited, because this is the most consequential thing anyone does to
 * characterization: it changes what "normal" means for the whole estate, and
 * every later delta is measured against it. Correcting a single row already
 * demanded a reason and left a trail; committing a whole upload left none.
 *
 * The actor is optional so existing callers keep working, but the route
 * supplies it.
 */
export function commitStaged(db, ids, { actor = null } = {}) {
  const ts = nowIso();
  let n = 0;
  db.exec('begin');
  try {
    for (const id of ids) {
      const r = db.prepare('update char_uploads set committed_at = ? where id = ? and committed_at is null')
        .run(ts, id);
      n += r.changes;
    }
    db.exec('commit');
  } catch (e) { db.exec('rollback'); throw e; }
  if (n) {
    writeAudit(db, {
      analyst: actor, action: 'characterization.commit',
      targetType: 'char_upload', targetId: ids.join(','),
      after: { uploads: n, at: ts },
    });
  }
  return n;
}

/** Throw staged uploads away before they reach the baseline. Also audited. */
export function discardStaged(db, ids, { actor = null } = {}) {
  let n = 0;
  db.exec('begin');
  try {
    for (const id of ids) {
      const u = db.prepare('select id from char_uploads where id = ? and committed_at is null').get(id);
      if (!u) continue;
      db.prepare('delete from char_entities where upload_id = ?').run(id);
      db.prepare('delete from char_uploads where id = ?').run(id);
      n++;
    }
    db.exec('commit');
  } catch (e) { db.exec('rollback'); throw e; }
  if (n) {
    writeAudit(db, {
      analyst: actor, action: 'characterization.discard',
      targetType: 'char_upload', targetId: ids.join(','),
      before: { uploads: n },
    });
  }
  return n;
}

/** Correct the host on a staged upload before it is committed. */
export function reattributeStaged(db, id, host) {
  const u = db.prepare('select * from char_uploads where id = ? and committed_at is null').get(id);
  if (!u) throw new Error('no such staged upload');
  const h = String(host ?? '').trim() || null;
  db.prepare('update char_uploads set host = ? where id = ?').run(h, id);
  db.prepare('update char_entities set host = ? where upload_id = ?').run(h, id);
  return stagedPreview(db).find(p => p.id === id) ?? null;
}

/**
 * Corrections. Deliberately narrow.
 *
 * A baseline is what we observed. Letting it become what we think was there is
 * a provenance problem, so the collected values are kept alongside the
 * corrected ones and every change lands in the audit table.
 *
 * Identity fields are refused outright. Editing `username` on an account or
 * `taskPath` on a task silently re-keys the row: the old identity reads GONE
 * and the new one NEW, on both sides of every future diff. To fix an identity,
 * discard and re-import.
 */
function assertIdentityUnchanged(repo, before, after) {
  const spec = REPOS[repo];
  if (spec.ident(before) !== spec.ident(after)) {
    throw new Error(
      'that field is part of the row identity — changing it would make the old row read GONE ' +
      'and the new one NEW in every future diff. Discard and re-import instead.');
  }
}

/** A place to hang manually adjusted rows so they still belong to a snapshot. */
function manualUploadFor(db, { snapshotId, repo, host, actor }) {
  const found = db.prepare(`select * from char_uploads
    where snapshot_id = ? and repo = ? and host is ? and kind = 'manual' limit 1`)
    .get(snapshotId, repo, host ?? null);
  if (found) return found;
  const id = newId();
  const ts = nowIso();
  db.prepare(`insert into char_uploads
    (id, snapshot_id, repo, host, source_format, analyst, extracted_rows, status, ts, kind, committed_at)
    values (?,?,?,?,?,?,0,'ok',?, 'manual', ?)`)
    .run(id, snapshotId, repo, h0(host), 'manual adjustment', actor, ts, ts);
  return getUpload(db, id);
}
const h0 = (v) => (String(v ?? '').trim() || null);

export function correctEntity(db, id, { attrs, reason, actor = null }) {
  const e = getEntity(db, id);
  if (!e) throw new Error(`no such row: ${id}`);
  if (!String(reason ?? '').trim()) throw new Error('a correction needs a reason');
  const merged = { ...e.attrs, ...(attrs ?? {}) };
  assertIdentityUnchanged(e.repo, e.attrs, merged);

  db.prepare(`update char_entities set attrs = ?, collected_attrs = coalesce(collected_attrs, ?),
    edited_by = ?, edited_at = ? where id = ?`)
    .run(JSON.stringify(merged), JSON.stringify(e.attrs), actor, nowIso(), id);
  writeAudit(db, {
    analyst: actor, action: 'characterization.correct', targetType: 'char_entity', targetId: id,
    before: e.attrs, after: { ...merged, _reason: reason },
  });
  return getEntity(db, id);
}

export function reattributeEntity(db, id, { host, reason, actor = null }) {
  const e = getEntity(db, id);
  if (!e) throw new Error(`no such row: ${id}`);
  if (!String(reason ?? '').trim()) throw new Error('a reattribution needs a reason');
  const to = h0(host);
  if (!to) throw new Error('a host is required');

  const up = getUpload(db, e.upload_id);
  /*
    The same refusal moveEntity makes, for the same reason. A manual upload does
    not establish presence — hostsIn counts collections only, deliberately, so
    that adjusting one row cannot make a host look like it reported — which
    means a row reattributed to a host this snapshot never collected lands
    where no view will ever show it. repoView drops it, hostCharacterization
    cannot see it, queryBaseline cannot find it. The row is still in the table
    and is unreachable from every read path, which is worse than being told no.

    This is the likely case, not the exotic one: correcting a mis-attributed
    host is exactly when the true host may not have been collected yet. Collect
    it and the reattribution goes through.
  */
  if (!hostsCollectedIn(db, e.repo, up.snapshot_id).includes(to)) {
    throw new Error(
      `this snapshot never collected ${to}, so the row would be invisible there. ` +
      'Collect that host into this snapshot first, or correct the row where it is.');
  }
  const target = manualUploadFor(db, { snapshotId: up.snapshot_id, repo: e.repo, host: to, actor });
  db.prepare('update char_entities set host = ?, upload_id = ?, edited_by = ?, edited_at = ? where id = ?')
    .run(to, target.id, actor, nowIso(), id);
  writeAudit(db, {
    analyst: actor, action: 'characterization.reattribute', targetType: 'char_entity', targetId: id,
    before: { host: e.host }, after: { host: to, reason },
  });
  return getEntity(db, id);
}

export function moveEntity(db, id, { snapshotId, reason, actor = null }) {
  const e = getEntity(db, id);
  if (!e) throw new Error(`no such row: ${id}`);
  if (!String(reason ?? '').trim()) throw new Error('a move needs a reason');
  if (!getCharSnapshot(db, snapshotId)) throw new Error('no such snapshot');

  /*
    Refuse a move into a snapshot that never collected this host. A manual
    upload does not establish presence, so the row would land where no view
    would ever show it — an orphan is worse than a refusal.
  */
  if (!hostsCollectedIn(db, e.repo, snapshotId).includes(e.host)) {
    throw new Error(
      'that snapshot never collected this host, so the row would be invisible there. ' +
      'Move it to a snapshot that did, or re-import.');
  }

  const from = getUpload(db, e.upload_id);
  const target = manualUploadFor(db, { snapshotId, repo: e.repo, host: e.host, actor });
  db.prepare('update char_entities set upload_id = ?, edited_by = ?, edited_at = ? where id = ?')
    .run(target.id, actor, nowIso(), id);
  writeAudit(db, {
    analyst: actor, action: 'characterization.move', targetType: 'char_entity', targetId: id,
    before: { snapshot: from.snapshot_id }, after: { snapshot: snapshotId, reason },
  });
  return getEntity(db, id);
}

export const getEntity = (db, id) => {
  const r = db.prepare('select * from char_entities where id = ?').get(id);
  return r ? { ...r, attrs: parse(r.attrs) } : null;
};
