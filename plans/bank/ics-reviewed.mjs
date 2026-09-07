/**
 * ICS overlays that have been through an independent review.
 *
 * Each was drafted from general control-system practice, then read line by line
 * by a reviewer that did not write it, against MITRE's own description of the
 * technique and against the authored entries in plans/bank/ics.mjs. What the
 * review could establish is that the entry is correct, that it says something a
 * competent person would not get from the technique name, that its commands
 * would actually run, and that its steps have outcomes somebody could disagree
 * with. What it could not establish — and what still separates these from
 * ics.mjs — is that anybody has checked them against the estate in front of you.
 *
 * That is the whole reason this is a third file and not a promotion into the
 * second. `authored` claims a real engagement stood behind the argument.
 * Nothing here claims that, and the badge and the bank panel say so.
 *
 * The review corrected far more than prose: commands that returned nothing,
 * Zeek fields that do not exist, expects no result could fail, and several
 * arguments whose central claim was untrue. Where a fix would have meant
 * rewriting the entry rather than editing it, the entry stayed drafted.
 *
 * Every command here reads a capture, a log or a file that already exists.
 */
const step = (text, tooling, expect) => ({ text, tooling, expect, source: 'bank' });

const asReviewed = (m) => Object.fromEntries(
  Object.entries(m).map(([id, d]) => [id, { ...d, provenance: 'reviewed' }]));

export const reviewed = asReviewed({
  T0838: {
    intent:
      'An adversary does not need to interfere with an alarm at the moment it should fire if '
        + 'they can quietly change what counts as alarm-worthy beforehand. A raised deadband or a '
        + 'disabled point stays wrong indefinitely and looks exactly like the routine tuning a site '
        + 'does anyway, which is what makes this quieter and more durable than Alarm Suppression '
        + '(T0878) — the config change happens once, long before anyone is watching for it.',
    tools: [
      'Historian',
      'host logs',
      'Kibana',
    ],
    dataSources: [
      'SCADA/HMI alarm configuration export',
      'SCADA audit trail',
      'engineering change records',
      'Application Log',
    ],
    terrain: [
      'HMIs',
      'SCADA servers',
      'engineering workstations',
    ],
    commands: [],
    steps: [
      step('Take the current alarm configuration — thresholds, deadbands, enabled flags, priorities '
        + '— from the SCADA project or the alarm server\'s own export, and diff it against the last '
        + 'recorded baseline or change record rather than reviewing it point by point from memory. '
        + 'Read it from the server; do not query controllers for it. Where alarm limits live in '
        + 'controller registers, a change to them is a write and T0836 is the task that sees it.',
        'host logs · Psephos · Characterization', 'A dated diff, or a first baseline where none existed.'),
      step('For every point whose configuration changed, take the account and origin from the SCADA '
        + 'audit trail and check for a matching authorised ticket. Alarm tuning is a real and '
        + 'ordinary activity, so the finding is the unmatched change, not the change itself.',
        'SCADA audit trail · Psephos · Comms', 'Each change matched to a ticket, or filed with who made it and from where.'),
      step('Look specifically for a threshold moved to a value the process would realistically never '
        + 'reach, or a point quietly disabled. Use the historian\'s trend range for the point, not '
        + 'the engineering nominal. Neither shows up as an obvious "no alarm" on a summary screen '
        + 'the way a suppressed message does.',
        'Historian · host logs', 'Every threshold inside the range the trend shows the point actually reaching, or the point named.'),
      step('File the current configuration as the new baseline regardless of outcome, so the next '
        + 'person is diffing against something recorded rather than reconstructing it.',
        'Psephos · Evidence', 'A filed baseline record.'),
    ],
    evidenceExpected:
      'A diffed alarm configuration with every change matched to a ticket or filed as '
        + 'unexplained.',
    doNext:
      'An unmatched change to a safety-relevant alarm point escalates immediately — the site is '
        + 'currently blind to whatever that point was protecting against. Nobody restores the old '
        + 'setting on the hunt\'s judgement; that is the process owner\'s call.',
  },

  T0878: {
    intent:
      'Where Modify Alarm Settings changes whether an alarm would ever fire, this interferes '
        + 'with the alarm on its way to the operator — held at the outstation, blocked in transit, '
        + 'forced-acknowledged, or filtered at the collector — so the process genuinely misbehaved '
        + 'and the operator was not told. That gap between what happened and what was reported is '
        + 'only visible by holding two records against each other; neither the historian nor the '
        + 'alarm log alone shows the absence.',
    tools: [
      'Historian',
      'Arkime',
      'Zeek',
    ],
    dataSources: [
      'alarm history',
      'historian trends',
      'alarm limit configuration',
      'operator shift logs',
      'Zeek dnp3.log',
    ],
    terrain: [
      'HMIs',
      'SCADA/alarm servers',
      'historians',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h fc_request < dnp3.log | grep DISABLE_UNSOLICITED',
      'zeek-cut id.resp_h fc_reply < dnp3.log | awk \'$2=="UNSOLICITED_RESPONSE"{print $1}\' | sort | uniq -c | sort -rn',
    ],
    steps: [
      step('For each process excursion in historian trend data that crossed a configured alarm '
        + 'limit, check whether a corresponding alarm exists in the alarm history for the same '
        + 'window. A limit-crossing excursion with no alarm at all is the core signature of this '
        + 'technique; if the limit itself moved, that is Modify Alarm Settings and a different '
        + 'entry.',
        'Historian · alarm history · alarm limit configuration', 'Every limit-crossing excursion matched to an alarm, or flagged as unaccompanied.'),
      step('Check for alarms present in the history but acknowledged or cleared faster than an '
        + 'operator could plausibly have actioned them, and attribute each acknowledgment to '
        + 'whoever the shift log says was at the console. Some alarm servers allow scripted '
        + 'acknowledgment, which reads as normal operator behaviour to a casual review.',
        'alarm history · operator shift logs', 'Each acknowledgment attributed to a person on shift with a plausible interval; sub-second or unattributed acks filed.'),
      step('Where the alarm server exposes subscription or filtering state, check for a filter that '
        + 'would drop a specific alarm class downstream of generation, and match each one to a '
        + 'change record. This is distinct from a source-side config change and points at the '
        + 'collector or forwarder instead.',
        'alarm server configuration · host logs', 'Every filter or subscription on the alarm path matched to an authorised change, or filed.'),
      step('Where the estate runs DNP3, read the wire for the suppression itself: a '
        + 'DISABLE_UNSOLICITED request from anything but the usual master, or an outstation whose '
        + 'unsolicited responses stop while its polled values keep arriving. On Modbus there is no '
        + 'alarm message to suppress — the alarm is computed at the server from polled values — so '
        + 'the wire can only confirm the value the historian already holds, and the first three '
        + 'steps are the whole hunt.',
        'Zeek dnp3.log · Arkime', 'No DISABLE_UNSOLICITED outside a commissioning record, and unsolicited-response counts per outstation stable across the window.'),
    ],
    evidenceExpected:
      'Limit-crossing excursions cross-checked against alarm history, each acknowledgment '
        + 'attributed, and — where DNP3 is in use — a stated answer on whether unsolicited '
        + 'reporting was disabled or stopped.',
    doNext:
      'Escalate immediately, and tell the operators which alarms they cannot currently trust. A '
        + 'suppressed alarm means an operator did not know something they needed to know at the '
        + 'moment they needed to know it.',
  },

  T0814: {
    intent:
      'Denial of Service on a control device competes directly with real fault diagnosis: a PLC '
        + 'that drops polls because it is flooded looks identical, from a summary view, to one that '
        + 'is simply failing on its own. That resemblance is why this technique is the one most '
        + 'likely to be waved off as hardware trouble rather than investigated, and it cuts the '
        + 'other way too — a flaky device gets called an attack once somebody is primed to see one. '
        + 'The task exists to make that call defensible in either direction, from data the site '
        + 'already has: the wire on one side of the gap and the historian on the other.',
    tools: [
      'Zeek',
      'Arkime',
      'Historian',
    ],
    dataSources: [
      'Zeek conn.log',
      'Zeek modbus.log',
      'historian trends',
      'HMI alarm history',
    ],
    terrain: [
      'controllers',
      'HMIs',
      'brokers and historians',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | sort | uniq -c | sort -rn | head -30',
      'zeek-cut ts id.resp_h conn_state < conn.log | awk \'{print int($1/60)*60, $2, $3}\' | sort | uniq -c | sort -rn | head -30',
      'zeek-cut ts id.orig_h id.resp_h func exception < modbus.log | awk \'$5!="-"\' | tail -40',
    ],
    steps: [
      step('Count connections and Modbus exception responses toward the device per minute across the '
        + 'gap, against its baselined polling cadence, and ignore byte volume. A controller\'s TCP '
        + 'table holds a handful of sessions, so exhausting it costs almost nothing in bytes, and a '
        + 'flood of small malformed requests dwarfs the legitimate master in count while looking '
        + 'unremarkable in volume. Half-open states (S0, REJ, RSTO) climbing while the master\'s '
        + 'completed sessions fall is the shape.',
        'Zeek', 'A per-minute connection and exception count for the device across the gap, with the spike attributed to a source, or shown absent.'),
      step('Line the historian trend gap and the HMI comms-loss alarm up against the traffic '
        + 'timeline to the second. What separates the two explanations is coincidence, not the '
        + 'shape of the edge on its own: a device that goes quiet on the same second the spike '
        + 'starts and comes back when it stops was flooded; one that stays down after the traffic '
        + 'clears, or went down with nothing unusual on the wire, was not.',
        'Historian · HMI alarm history · Zeek', 'The gap\'s start and end timestamped from the historian and the alarm, each stated as aligned or not aligned with the traffic.'),
      step('Where there is a gap and no spike, read the last few transactions the device answered '
        + 'before it went quiet. A single malformed request that crashes a parser is a DoS with no '
        + 'rate signature at all, and the last function code and exception before silence are the '
        + 'only evidence it leaves. A gap with no spike and an ordinary last transaction is the '
        + 'honest case for a fault.',
        'Zeek modbus.log · Arkime', 'The last transactions before the gap recorded, and stated as ordinary or not.'),
      step('Check for a plausible equipment explanation — a known-flaky device, a maintenance '
        + 'window, a power event — before calling this an attack, and state which possibility the '
        + 'evidence supports and how strongly. This is one of the honest ambiguities in ICS '
        + 'hunting, and a stated \'cannot distinguish\' beats a default either way.',
        'Psephos · Comms', 'A stated conclusion with its confidence, not a default assumption.'),
    ],
    evidenceExpected:
      'A timeline putting the traffic spike, the historian gap and the alarm on one axis, the '
        + 'last transactions before the gap, and an explicit fault-versus-attack call with its '
        + 'confidence.',
    doNext:
      'Where the device sits in a safety loop, escalate regardless of the fault-versus-attack '
        + 'call — the process was unresponsive either way. A named flood source is a compromised or '
        + 'misbehaving host and goes to the boundary and discovery tasks, not just to the file.',
  },

  T0816: {
    intent:
      'Most devices that support this also support it for legitimate maintenance, so the '
        + 'finding is not that a restart happened but who triggered it, from where, and whether it '
        + 'lines up with anything scheduled. A single restart on its own is close to unremarkable; '
        + 'several devices restarting close together across a segment is not, since short of a '
        + 'power event equipment does not fail in that synchronised a pattern. The command itself '
        + 'is decoded for only a few protocols — DNP3 Cold and Warm Restart, the Modbus Diagnostics '
        + 'sub-function Restart Communications Option — and everywhere else the only thing on the '
        + 'wire is the gap it leaves, so most of this hunt is reading gaps and asking what arrived '
        + 'just before them.',
    tools: [
      'Zeek',
      'Arkime',
      'Historian',
    ],
    dataSources: [
      'Zeek conn.log',
      'Zeek dnp3.log',
      'Zeek modbus.log',
      'device and HMI event logs',
      'maintenance records',
      'historian trends',
    ],
    terrain: [
      'controllers',
      'protection relays',
      'RTUs',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h fc_request < dnp3.log | grep -E \'COLD_RESTART|WARM_RESTART\'',
      'zeek-cut ts id.orig_h id.resp_h func < modbus.log | grep DIAGNOSTICS',
      'zeek-cut ts id.resp_h < conn.log | sort -k2,2 -k1,1n | awk \'$2==h && $1-t>60 {print h, t, $1-t} {h=$2; t=$1}\'',
    ],
    steps: [
      step('Pull the decoded restart commands first — Cold and Warm Restart from dnp3.log, '
        + 'Diagnostics from modbus.log — and attribute each to a source. modbus.log does not carry '
        + 'the diagnostics sub-function, so open the session in Arkime to confirm it was Restart '
        + 'Communications Option and not a loopback test before treating it as a restart.',
        'Zeek · Arkime', 'Every decoded restart command attributed to a source, or listed as unattributed.'),
      step('Then find the restarts nothing decoded. A controller that stops answering its poller and '
        + 'comes back on a fresh session a minute later has restarted whatever the protocol, so '
        + 'list polling gaps per device and read what reached the device in the seconds before each '
        + 'one — that is where the trigger is, if it was on the wire at all.',
        'Zeek', 'A per-device gap timeline, each gap paired with whatever preceded it.'),
      step('Check for clustering: several devices on a segment restarting within a short window is a '
        + 'stronger signal than any one restart alone, because outside a power event that is not '
        + 'the shape hardware failure takes — and whether there was a power event is a question the '
        + 'site can answer in a minute.',
        'Zeek · Historian · Comms', 'Restarts assessed as independent or clustered, with any cluster explained or filed.'),
      step('Cross-reference each restart against the maintenance record, and check the historian for '
        + 'what the process did during the outage window — a controller down for even seconds can '
        + 'matter more than the restart event itself. A restart with no trace on the wire, from a '
        + 'local panel, a serial engineering port or a power cycle, shows up here and nowhere else.',
        'Historian · Psephos · Comms', 'Every restart matched to maintenance, or filed with its process impact.'),
    ],
    evidenceExpected:
      'A per-device restart timeline — decoded commands and polling gaps — with source, '
        + 'clustering assessment, and process impact per event.',
    doNext:
      'An unscheduled restart on a protection or safety device escalates immediately, ahead of '
        + 'the rest of the queue. Nobody sends a restart of their own to see what happens.',
  },

  T0881: {
    intent:
      'Unlike a device restart this stops a software service while the host underneath keeps '
        + 'running, and it is chosen for what nobody sees: the best candidates are logging agents, '
        + 'alarm forwarders and the historian\'s own collector, services whose absence produces '
        + 'silence rather than an error anyone would notice. That silence is the trap for the '
        + 'hunter as well — the agent that would have shipped the stop event is the thing that '
        + 'stopped — so the technique is hunted from both ends: the host\'s service-manager log, and '
        + 'the collector\'s record of when each host went quiet.',
    tools: [
      'host logs',
      'Kibana',
    ],
    dataSources: [
      'Windows System log · Service Control Manager 7034/7036/7040',
      'journald messages from PID 1 (Stopped, Deactivated)',
      'process creation (Sysmon 1 / Security 4688 / auditd) for sc, net, Stop-Service, systemctl',
      'SIEM per-host ingest timeline',
    ],
    terrain: [
      'HMIs',
      'historians',
      'engineering workstations',
    ],
    commands: [
      'journalctl _PID=1 --since "7 days ago" | grep -E \'Stopped |Deactivated successfully\' | tail -50',
      'Get-WinEvent -FilterHashtable @{LogName=\'System\';ProviderName=\'Service Control Manager\';Id=7034,7036,7040;StartTime=(Get-Date).AddDays(-7)} | Format-Table TimeCreated,Id,Message -Wrap',
    ],
    steps: [
      step('Build the service state timeline from the service manager\'s own log rather than from the '
        + 'host\'s current state. On Windows that is Service Control Manager 7036 (entered the '
        + 'stopped state) and 7040 (start type changed, which is how a service is disabled) in the '
        + 'System log; on Linux it is PID 1\'s Stopped and Deactivated messages in journald. Keep '
        + '7034 apart from 7036: a service that terminated unexpectedly crashed, one that entered '
        + 'the stopped state was told to.',
        'host logs · journald · System event log', 'A per-host list of stop and disable events, timestamped, with crashes separated from commanded stops.'),
      step('Attribute each stop through process creation. sc stop, net stop, Stop-Service, '
        + 'Set-Service, and systemctl stop, disable or mask leave a command line, an account and a '
        + 'parent process; a stop from services.msc or a remote service-control call leaves only '
        + 'the requester\'s session. Read the logging agent, alarm forwarder and historian collector '
        + 'entries first — those are the ones picked for producing no other symptom.',
        'Sysmon · Security 4688 · auditd', 'Each stop attributed to an account and a parent process or session, or listed as unattributed; the silent-service candidates read first, not last.'),
      step('Check the collector\'s view of the same window. Sort hosts in Kibana by last-seen and '
        + 'look for any that went quiet and came back: the host\'s own log can be complete and still '
        + 'say nothing, because the agent that would have shipped the stop is the one that was '
        + 'stopped. A gap on the collector with no reboot and no stop event on the host is the '
        + 'finding, and it is the only evidence left if the host log was truncated as well.',
        'Kibana', 'A per-host ingest gap list for the window, each gap matched to a stop event or a reboot on the host, or filed as unexplained.'),
      step('For each unexplained stop, look at what happened next on that host: a write under the '
        + 'stopped service\'s data directory, or another inhibit-response finding already on file. A '
        + 'service holds its store open while it runs, so a stop followed by a modification of the '
        + 'store is the shape of data destruction in progress, not a service outage; and a stopped '
        + 'forwarder just before another technique is corroboration, not a separate coincidence to '
        + 'explain.',
        'host logs · Psephos · Evidence', 'Each unexplained stop linked to a filed finding on the same host in the same window, or filed on its own with what followed it.'),
    ],
    evidenceExpected:
      'A per-host service state timeline from both the host and the collector, with each stop '
        + 'matched to a change record, attributed, or filed.',
    doNext:
      'A stopped protective or logging service on a safety-relevant host escalates immediately '
        + 'rather than waiting for the queue: the gap in coverage stays open for as long as the '
        + 'service does, and restarting it is the site\'s decision, not the hunter\'s.',
  },

  T0809: {
    intent:
      'On OT the value of destroying data is rarely concealment for its own sake — it is '
        + 'removing the configuration and history that would let engineers reconstruct what '
        + 'happened or restore quickly: control programs, historian archives, alarm logs. It tends '
        + 'to come last, after the operational objective is already achieved, which is why this is '
        + 'usually found retrospectively rather than caught in progress, and why the copy matters '
        + 'as much as the original.',
    tools: [
      'host logs',
      'Historian',
    ],
    dataSources: [
      'File',
      'Process',
      'Command',
      'historian archive',
      'backup and archive inventory',
    ],
    terrain: [
      'historians',
      'engineering workstations',
      'HMIs',
    ],
    commands: [
      'find /var/lib /opt /srv -newermt "-2 days" \\( -type d -o -empty \\) 2>/dev/null | head -60',
      'grep -E "COMMAND=.*(shred|wipefs|dd if=/dev/(zero|urandom)|rm -rf)" /var/log/auth.log 2>/dev/null | tail -40',
    ],
    steps: [
      step('Look for deletion evidence on historians and engineering workstations from what the '
        + 'filesystem already records. A deleted file leaves no timestamp of its own, but its '
        + 'parent directory\'s mtime changes, and a wiper that overwrites rather than unlinks leaves '
        + 'recent, often empty, files behind — so hunt recently modified directories and truncated '
        + 'files, not recently written ones. Then read sudo logs and shell history for the '
        + 'utilities that do this: shred, wipefs, dd to a block device, rm -rf.',
        'host logs', 'A dated list of directories that lost contents in the window, each matched to a change record or filed.'),
      step('Check the historian for a gap in the stored trend rather than in the files. An archive '
        + 'truncated by a wiper or a purge command shows as missing history in the trend view, the '
        + 'operators may already have noticed it, and it dates the event more precisely than any '
        + 'file timestamp.',
        'Historian · Site operator', 'Trend continuous across the window, or the gap\'s start and end recorded.'),
      step('Check backup and archive completeness against the known inventory. A missing recent '
        + 'backup or engineering project archive is itself the finding even where host logs show '
        + 'nothing, since destruction of the copy is as effective as destruction of the original.',
        'Psephos · Characterization', 'Every historian archive and engineering project in the inventory has a dated copy that predates the window, or the gap is named.'),
      step('Cross-reference against other inhibit-response findings already on file. Destruction '
        + 'that follows alarm suppression or a credential change is confirmation of intent, not an '
        + 'isolated event to assess on its own.',
        'Psephos · Evidence', 'Each destruction event placed on the case timeline relative to any alarm suppression or credential change already filed.'),
    ],
    evidenceExpected:
      'Directories that lost contents in the window, historian trend continuity, the backup '
        + 'inventory reconciled, and every destruction event placed on the case timeline.',
    doNext:
      'Confirmed destruction of engineering or historian data is an incident. Preserve whatever '
        + 'remains — the backups included — before anyone attempts to rebuild from it, and treat a '
        + 'backup as suspect until it has been checked against the inventory.',
  },

  T0835: {
    intent:
      'The effect of this technique sits inside the PLC\'s own I/O table, below anything a '
        + 'protocol decoder sees: a forced input or output is reported faithfully as the value the '
        + 'controller now believes, so the wire shows a controller that is internally consistent '
        + 'and wrong. What is not below the wire is the act of installing the force — it arrives as '
        + 'an engineering-protocol session, not as a Modbus poll — and most controller families '
        + 'flag installed forces in a status word that the SCADA may already be collecting. So hunt '
        + 'the installation and the flag, which are visible, and be honest that the effect itself '
        + 'can only be checked against a measurement the suspect controller does not own.',
    tools: [
      'Zeek',
      'Historian',
      'Psephos · Characterization',
    ],
    dataSources: [
      'Zeek conn.log',
      'controller status and diagnostic tags as collected by SCADA or the historian',
      'historian trends',
      'independent physical sensor readings',
      'engineering change records',
    ],
    terrain: [
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p service < conn.log | awk \'$4==102||$4==44818\' | sort -u | head -40',
    ],
    steps: [
      step('List every engineering-protocol session to a controller in the window — S7comm on 102, '
        + 'EtherNet/IP on 44818, the vendor equivalent for whatever else is on the segment — and '
        + 'attribute each to a workstation and a change record. Forces are installed from '
        + 'engineering software, so the installation has a source address even when the effect has '
        + 'no protocol signature.',
        'Zeek · change records', 'Every engineering session matched to a named workstation and an authorised change, or one filed as unexplained.'),
      step('Check whether the controllers\' force status is already collected. Rockwell, Siemens and '
        + 'most others expose an installed-forces flag as a status word, and many sites poll it '
        + 'into SCADA or the historian without knowing why. Read what has been collected; do not '
        + 'query the controller for it.',
        'Historian · SCADA diagnostics · Psephos · Characterization', 'Per controller: the flag is collected and was clear for the window, was set (a finding), or is not collected (a gap to file).'),
      step('Determine whether any physically independent measurement exists for the process value in '
        + 'question — a separate transmitter, gauge, or safety-rated sensor not sharing the suspect '
        + 'PLC\'s I/O path.',
        'Psephos · Characterization', 'A stated yes or no per process value in question.'),
      step('Where independent measurement exists, compare it against the value the PLC reported for '
        + 'the same window, since the PLC\'s own reporting cannot be trusted to reveal a manipulated '
        + 'image of itself.',
        'Historian', 'Independent and reported values agree within instrument tolerance across the window, or a divergence window is named.'),
      step('Where no independent measurement exists and the force flag is not collected, file that '
        + 'as the finding. A controller whose only view of its own I/O state is itself cannot have '
        + 'this technique verified from outside the device, and the site should know that rather '
        + 'than receive a false assurance.',
        'Psephos · Evidence', 'A filed statement of what cannot be verified, per controller.'),
    ],
    evidenceExpected:
      'Every engineering session to a controller attributed, the force-status flag read for '
        + 'each controller where it is collected, and an explicit statement per controller of '
        + 'whether independent verification exists and what any comparison showed.',
    doNext:
      'A set force flag or a confirmed divergence is safety-relevant and goes to the process '
        + 'owner immediately; nothing is cleared or corrected from the hunt, because removing a '
        + 'force on a running process is itself a control action.',
  },

  T0800: {
    intent:
      'Putting a protection relay into firmware-update mode is a legitimate maintenance action, '
        + 'and that is exactly the cover it provides: for the duration the relay\'s protection '
        + 'functions are off, which is the state an adversary wants in place before forcing the '
        + 'fault the relay would otherwise clear. The mode is rarely announced on the wire — a '
        + 'relay in it mostly stops talking — so the task is not spotting a status flag but finding '
        + 'every gap in a relay\'s cadence, matching each to an authorisation, and naming how long '
        + 'protection was actually absent.',
    tools: [
      'Zeek',
      'Arkime',
      'Historian',
    ],
    dataSources: [
      'Zeek dnp3.log',
      'Zeek conn.log',
      'historian trends',
      'engineering software logs',
      'maintenance records',
    ],
    terrain: [
      'protection relays',
      'controllers',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h < dnp3.log | sort -k3,3 -k1,1n | awk \'$3==p && $1-t>60 {print p, t, $1, $1-t} {p=$3; t=$1}\'',
      'zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | awk \'$4==20000||$4==102\' | sort -k3,3 -k1,1n | awk \'$3==p && $1-t>60 {print p, t, $1, $1-t} {p=$3; t=$1}\'',
    ],
    steps: [
      step('Find every gap in each relay\'s polling cadence. A relay in update mode stops answering '
        + 'its master, so the evidence is silence against a metronome rather than a status field: '
        + 'list the responders on the SCADA protocol and every interval where one went quiet for '
        + 'longer than its poll period. Set the threshold from the observed period, not from a '
        + 'guess.',
        'Zeek dnp3.log · Zeek conn.log', 'A per-relay list of gaps with start and end times, possibly empty.'),
      step('For each gap, read what the relay said when it came back and what reached it just before '
        + 'it went quiet. On DNP3 the first reply after a reboot carries the Device Restart '
        + 'internal indication, which dates it; on IEC 61850 the logical-node Mod attribute reads '
        + 'off or blocked, but only if the sensor decodes MMS, which stock Zeek does not. A single '
        + 'small packet to a management port immediately before the silence is a relay being '
        + 'knocked into this state rather than updated — that is how Industroyer\'s SIPROTEC module '
        + 'did it.',
        'Zeek dnp3.log · Arkime', 'Each gap classified: restart after a transfer, restart after an unsolicited packet, or unexplained.'),
      step('Cross-reference every gap against the maintenance and change record, and against the '
        + 'engineering software\'s own log on the workstation that would have pushed the update. '
        + 'Firmware updates are planned events on a working site, so a gap the record cannot '
        + 'account for is the finding whatever caused it.',
        'Psephos · Comms · engineering software logs', 'Each gap matched to an authorised update, or filed.'),
      step('Record the exposure window per event from the historian rather than the capture: the '
        + 'historian shows the hole in the relay\'s measurements even where the sensor did not see '
        + 'the segment. A legitimate update still left the process unprotected for that whole '
        + 'window, and that fact is a finding on its own regardless of intent.',
        'Historian · Psephos · Evidence', 'A start, end and duration filed per event.'),
    ],
    evidenceExpected:
      'Every gap in a protection relay\'s cadence in the window, each classified, matched to an '
        + 'authorisation or filed, with its exposure window recorded.',
    doNext:
      'An unmatched gap on a protection device goes to the lead and the protection engineer '
        + 'immediately, not to the end of the queue: if the relay is still silent the process is '
        + 'running without it, and nobody reboots it on a hunter\'s judgement.',
  },

  T0892: {
    intent:
      'Changing a device or software credential does not just block a responder\'s access in the '
        + 'abstract — timed against an incident already in progress, it delays exactly the people '
        + 'trying to intervene at exactly the moment intervention matters, which makes it a '
        + 'delaying tactic aimed at the response rather than a lockout for its own sake. It is also '
        + 'one of the few techniques in this tactic whose victim — the locked-out engineer — is '
        + 'available to ask directly, which is faster and more reliable than reconstructing it from '
        + 'logs.',
    tools: [
      'host logs',
      'HMI application logs',
      'Zeek',
    ],
    dataSources: [
      'Operational Databases',
      'Network Traffic',
      'device and host authentication logs',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
      'controllers',
      'protection relays',
    ],
    commands: [
      'grep -Ei "accepted|failed" /var/log/auth.log | tail -50',
      'grep -Ei "password changed|chauthtok|chpasswd|usermod" /var/log/auth.log | tail -50',
    ],
    steps: [
      step('Review authentication logs on HMIs, engineering workstations and any device with its own '
        + 'login for accounts that succeeded until a point and failed afterwards. The transition is '
        + 'the shape, not the failures — a working account that stops working is a changed '
        + 'credential or a disabled one, and either is this technique.',
        'host logs', 'Accounts that went from succeeding to failing, each with the time of the transition, or none.'),
      step('Check the credential-change events themselves where the platform logs them — 4723 and '
        + '4724 on Windows, a password-changed line from PAM on Linux, and the user-management '
        + 'audit trail of the HMI or SCADA application, which is separate from the OS — and match '
        + 'each to a change ticket. An unscheduled change on a device anyone would need to reach '
        + 'quickly is the finding regardless of anything else happening.',
        'host logs · HMI application logs · Psephos · Comms', 'Each change matched to a ticket, or filed.'),
      step('For hardware controllers and protection relays, do not expect to see the change. It goes '
        + 'over the vendor\'s engineering protocol, which the sensor rarely decodes, and the device '
        + 'keeps no log you can read passively. What is visible is the engineering session that '
        + 'carried it: diff sessions to each controller and relay in the window against the '
        + 'baselined engineering workstations, and treat one from anywhere else as the candidate.',
        'Zeek', 'Every engineering session to a controller or relay attributed to a known workstation, or one identified.'),
      step('Ask the engineering team directly whether anyone has been locked out recently, rather '
        + 'than relying only on log reconstruction. A relay password change leaves no log at all, '
        + 'and the engineer who could not get in is the only record of it.',
        'Site engineer · Psephos · Comms', 'A recorded answer from a named person, possibly empty.'),
    ],
    evidenceExpected:
      'A per-account success-to-failure timeline, every logged credential change matched to a '
        + 'ticket or filed, engineering sessions to controllers and relays attributed, and the '
        + 'engineers\' answer recorded.',
    doNext:
      'File and escalate immediately if it coincides with any other active finding — a '
        + 'locked-out engineer during an ongoing event is safety-relevant, not just an access '
        + 'nuisance. Nobody resets the credential on the hunt\'s judgement; that is the site\'s call, '
        + 'and the change may have been made to something that still needs the old one.',
  },

  T0851: {
    intent:
      'Under this tactic a rootkit\'s job is narrow: hide the artefact of some other '
        + 'inhibit-response technique — a hidden process holding a service stopped, a hooked vendor '
        + 'library showing the engineer the program that was there before the download — so it is '
        + 'hunted as a companion to whatever has already been found rather than as a freestanding '
        + 'search. On a controller or relay with no host-level tooling there is nothing to search '
        + 'at all, and the only purchase is comparing what the device claims about itself against '
        + 'what the network independently saw of it, because a rootkit that suppresses a local '
        + 'record cannot recall what already left the wire.',
    tools: [
      'host logs',
      'Zeek',
      'Arkime',
    ],
    dataSources: [
      'Zeek conn.log',
      'HMI and engineering workstation host logs',
      'engineering software install files',
      'vendor release hashes',
    ],
    terrain: [
      'controllers',
      'protection relays',
      'HMIs',
      'engineering workstations',
      'appliances',
    ],
    commands: [
      'cat /proc/sys/kernel/tainted; cat /proc/modules | awk \'{print $1}\' | sort',
      'find /opt /usr/lib /usr/local/lib -name \'*.so*\' -newermt \'-30 days\' 2>/dev/null | head -30',
      'zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | sort | uniq -c | sort -rn | head -40',
    ],
    steps: [
      step('Where the device is a general-purpose host — HMI, historian, engineering workstation, '
        + 'appliance — read the standard indicators from what the kernel already records: on Linux '
        + 'a non-zero taint value, a loaded-module list that does not match the known-clean build '
        + 'of that image, a process list read from /proc that disagrees with the one the service '
        + 'manager reports. Treat a clean result as weak evidence; a competent rootkit hides from '
        + 'exactly this, which is why the wire comparison below exists.',
        'host logs · /proc', 'Taint value and module list recorded per host and matching the clean build, or one host named that does not.'),
      step('On the engineering workstation look at the vendor\'s protocol library rather than the '
        + 'operating system. The best-known ICS rootkit was a replaced communications DLL that '
        + 'answered the engineer\'s read of the controller with the program that had been there '
        + 'before the download, so a reprogrammed controller looked unmodified from the only '
        + 'console able to check it. Hash the engineering software\'s installed libraries against a '
        + 'clean install of the same version and read their timestamps against the change record.',
        'host logs · vendor release hashes', 'Every library hash matches the vendor release, or a named file and date that does not.'),
      step('Compare what each host reports about itself against what the sensor independently saw of '
        + 'it in the same window: every flow in conn.log with the host as source should also appear '
        + 'in the host\'s own connection, firewall or audit record. A rootkit that suppresses the '
        + 'local record cannot alter what already left the wire, so a flow the sensor saw and the '
        + 'host cannot account for is the finding.',
        'Zeek · Arkime · host logs', 'Every flow the sensor saw from the host appears in the host\'s own record, or a named flow the host does not account for.'),
      step('Where the device is a controller or relay with no host-level visibility, say so plainly: '
        + 'the wire comparison is the entire hunt for that device, and its firmware cannot be '
        + 'verified passively — there is nothing further to check without an outage and the '
        + 'vendor\'s tooling.',
        'Psephos · Evidence', 'An explicit coverage statement per device class, naming what cannot be checked and why.'),
    ],
    evidenceExpected:
      'Taint, module and library checks on every general-purpose host, a host-versus-wire '
        + 'comparison for every device, and a stated coverage gap for every controller class.',
    doNext:
      'A confirmed or suspected rootkit is an incident. The device is untrustworthy end to end '
        + 'and is imaged before anything it says about itself is relied on again, and every '
        + 'controller it manages is treated as possibly reprogrammed and handed to T0889 with that '
        + 'caveat.',
  },

  T1691: {
    intent:
      'What separates this from Block Communications (T1695) is selectivity: a specific message '
        + 'class is dropped while the rest of the link\'s traffic keeps flowing, which usually means '
        + 'something on the path is parsing and choosing rather than a cable or a radio simply '
        + 'failing. That makes it harder to notice — most of what a dashboard shows still looks '
        + 'normal — and it is why the hunt starts from message accounting rather than link status.',
    tools: [
      'Zeek',
      'Arkime',
      'Historian',
    ],
    dataSources: [
      'Zeek modbus.log',
      'Zeek dnp3.log',
      'Zeek conn.log',
      'HMI/SCADA master comms diagnostics',
      'historian trends',
      'network map',
      'sensor inventory',
    ],
    terrain: [
      'control segments',
      'the IT/OT boundary',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h func < modbus.log | sort | uniq -c | sort -rn | head -40',
      'zeek-cut id.orig_h id.resp_h fc_request fc_reply < dnp3.log | sort | uniq -c | sort -rn | head -40',
    ],
    steps: [
      step('Say which side of the suspected drop the tap sits on before reading absence into '
        + 'anything. A tap upstream of the drop sees the request leave and no reply come back; a '
        + 'tap downstream sees no request at all. Both are the technique, but only one of them '
        + 'shows a gap on the wire, and a single sensor sees one side.',
        'Zeek · sensor inventory', 'Tap position stated relative to the sender, the receiver and any candidate in-path device.'),
      step('Count messages per stream and per function code on the wire, and hold that against what '
        + 'the sending master\'s own comms diagnostics say it sent or what the receiver logged. One '
        + 'function code missing from a pair whose other traffic continues at its usual rate is the '
        + 'signature; a link fault takes everything on the pair down together.',
        'Zeek · HMI/SCADA master diagnostics', 'A per-stream, per-function-code count for the window, with any class present at the sender and absent on the wire named — or none.'),
      step('Look for anything on the path able to parse and choose: a bump-in-the-wire not on the '
        + 'network map, a gateway or protocol converter that is on the map but now terminates '
        + 'sessions it used to pass through, or a changed MAC-to-IP pairing at either endpoint. '
        + 'Dropping one message class while the rest flows generally needs something that '
        + 'understands the protocol, and that something is usually a host.',
        'Psephos · Network Map · Zeek', 'The path enumerated end to end, every in-path device named, and any unexplained device or changed endpoint MAC filed.'),
      step('Where messages arrive late rather than never, pair requests with their responses per '
        + 'function code and compare the round-trip against the baseline for that protocol. A delay '
        + 'confined to one message class on a link whose other classes answer at their usual speed '
        + 'is the same selectivity signature in a different form.',
        'Zeek', 'Per-function-code round-trip times against baseline: outliers confined to one class, or none.'),
    ],
    evidenceExpected:
      'A per-stream, per-message-class count against what the sender says it sent, the tap '
        + 'position stated, and the path enumerated with any unexplained device or changed endpoint '
        + 'filed.',
    doNext:
      'Unexplained, selective message loss is filed and escalated as a possible active in-path '
        + 'device, since whatever can drop a message class can also alter one; the specific class '
        + 'lost is then worked under T1691.001 or T1691.002.',
  },

  'T1691.002': {
    intent:
      'This is the network-layer sibling of Alarm Suppression: instead of interfering with the '
        + 'alarm at the HMI, the telemetry that would have shown the process misbehaving is dropped '
        + 'before it arrives, so the operator\'s screen goes stale or quiet rather than visibly '
        + 'wrong. A frozen value that still looks plausible is easier to miss for longer than an '
        + 'alarm that never sounded, which is what makes this worth hunting separately rather than '
        + 'folding into that task.',
    tools: [
      'Historian',
      'Zeek',
      'HMI logs',
    ],
    dataSources: [
      'historian trends',
      'Zeek conn.log',
      'Zeek modbus.log',
      'Zeek dnp3.log',
      'HMI and SCADA comm-fail and tag-quality logs',
    ],
    terrain: [
      'controllers',
      'HMIs',
      'historians',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p conn_state orig_bytes resp_bytes < conn.log | awk \'$4==502 || $4==20000\' | sort -k2,3 | tail -40',
      'zeek-cut id.orig_h id.resp_h func exception < modbus.log | awk \'$4!="-"\' | sort | uniq -c | sort -rn | head -20',
    ],
    steps: [
      step('For each historian gap or flat trend on a controller, pull the same window from the wire '
        + 'and classify it. Polls going out with nothing coming back — orig_bytes climbing while '
        + 'resp_bytes stays flat, or connections in S0 or REJ — means the reporting message is '
        + 'being dropped between the device and the master. Polls and responses both present but '
        + 'nothing recorded means the drop is inside the master host or the historian feed. Polling '
        + 'itself stopped is a different task. Behind a serial gateway the first shape appears '
        + 'instead as Modbus exception 0x0B, gateway target device failed to respond. Check the '
        + 'wire before calling a flat trend frozen: historian compression stores a steady value as '
        + 'a flat line too.',
        'Historian · Zeek conn.log · Zeek modbus.log', 'Each gap classified as responses missing on the wire, responses present but not recorded, or polling stopped.'),
      step('Distinguish this from a genuine link fault by checking whether other reporting traffic '
        + 'on the same link, from other devices, arrived normally in the same window. A fault '
        + 'usually takes the whole link down; selective loss usually does not.',
        'Zeek', 'Loss stated as selective to one device or point, or common to the link.'),
      step('Check the master\'s own comm-fail and tag-quality alarms for every window where responses '
        + 'were missing on the wire. A master that stopped hearing from a device should have said '
        + 'so; missing responses with no comm-fail raised means the operator was kept from '
        + 'noticing, which pairs this with alarm suppression and changes what the intrusion is for.',
        'HMI logs · Alarm history', 'A comm-fail or bad-quality record for each window of missing responses, or its absence filed.'),
      step('Ask whether an operator noticed and dismissed a stale reading as a display glitch, since '
        + 'a plausible frozen value is the most likely reason this goes unreported for a long time.',
        'Site operator · Psephos · Comms', 'A recorded answer, possibly empty.'),
    ],
    evidenceExpected:
      'Each historian gap classified against the wire, the link-fault alternative assessed and '
        + 'stated, and the master\'s comm-fail alarms checked for the same windows.',
    doNext:
      'Confirmed selective reporting loss on a safety-relevant point escalates immediately — '
        + 'the operator has been working from data that stopped updating and may not know it. '
        + 'Nobody restarts a link or a collector on the hunter\'s judgement.',
  },

  T1695: {
    intent:
      'Where the T1691 family blocks particular messages, this denies the medium — everything '
        + 'on the link stops at once, not some of it. Total silence is easier to notice than '
        + 'partial and harder to attribute: the base rate of cable, switch and radio failure in OT '
        + 'is genuinely high, and a passive sensor sees only the absence, never the cause. So the '
        + 'first move is ruling out a mundane cause, and the second is asking what the silence was '
        + 'for — blocking is usually timed to cover something else.',
    tools: [
      'Zeek',
      'Arkime',
      'Historian',
      'Alarm history',
    ],
    dataSources: [
      'Zeek conn.log',
      'SCADA master comms-failure alarms',
      'historian tag quality',
      'boundary firewall log',
      'maintenance and change records',
    ],
    terrain: [
      'control segments',
      'the IT/OT boundary',
      'remote telemetry links',
    ],
    commands: [
      'zeek-cut ts id.resp_h < conn.log | awk \'{printf "%d %s\\n", int($1/60)*60, $2}\' | sort | uniq -c | sort -k2n | tail -60',
      'zeek-cut -d ts id.orig_h id.resp_h id.resp_p < conn.log | sort | tail -40',
    ],
    steps: [
      step('Establish whether the outage is total for the link — every responder on the segment, '
        + 'every protocol, stops in the same minute — or partial. Polling that continues while '
        + 'particular responses go missing is T1691, not this. For a serial, radio or cellular link '
        + 'that no sensor taps, the evidence is the master\'s own comms-failure alarms and historian '
        + 'tags going bad-quality, and that is the only evidence there is.',
        'Zeek · Alarm history · Historian', 'A stated cutoff time and the list of devices that went silent at it, or a partial outage rerouted to T1691.'),
      step('Check for a mundane cause before assuming interference: a known-flaky switch, scheduled '
        + 'maintenance, a power event, a contractor on the cable run. Ordinary comms failure is '
        + 'common enough in OT that this technique is not the default explanation, and the site '
        + 'usually knows within a phone call.',
        'Site engineer · Psephos · Comms', 'A named cause from a named person, or an explicit statement that nobody can account for it.'),
      step('Where nothing accounts for it, read the outage window as a window: what crossed the '
        + 'boundary, what wrote to a controller, who logged in to an HMI or engineering station '
        + 'while the link was down and the operator could not see. Blocking is frequently timed to '
        + 'cover another action, and that action is the finding.',
        'Zeek · Firewall log · Psephos · Evidence', 'A list of what else moved in the window — crossings, writes, sessions — or an explicit empty one.'),
    ],
    evidenceExpected:
      'A cutoff time and silent-device list per link, a named mundane cause or an explicit '
        + 'absence of one, and a stated account of what moved elsewhere during the window.',
    doNext:
      'An unexplained total-link outage escalates immediately and is treated as a window during '
        + 'which something else may have happened unseen; the hunt does not restore the link or '
        + 'touch the equipment.',
  },

  'T1695.001': {
    intent:
      'Serial links are usually the last-mile connection to a relay or an RTU and rarely log '
        + 'anything about themselves, so a serial outage leaves no capture of its own absence — '
        + 'only the silence of whatever depended on it. That pushes this hunt toward the polling '
        + 'master rather than toward the link: its application log says whether the port opened and '
        + 'went unanswered, which is a cable, or could not be opened at all, which is a host — a '
        + 'serial port is normally held by one process at a time, and the process holding it is the '
        + 'one direct piece of evidence this technique leaves. Check the physical explanations '
        + 'before the analytical ones either way, since a loose connector explains most serial '
        + 'problems in practice.',
    tools: [
      'host logs',
      'Historian',
    ],
    dataSources: [
      'polling master application log (comms timeouts and port-open errors)',
      'historian tag quality and data gaps for the affected points',
      'serial-to-Ethernet gateway session log',
      'master host process and kernel logs (lsof, journald, Sysmon)',
    ],
    terrain: [
      'protection relays',
      'RTUs',
      'serial-to-Ethernet gateways',
      'polling masters',
    ],
    commands: [
      'lsof /dev/ttyS* /dev/ttyUSB* 2>/dev/null',
      'journalctl -k --since "7 days ago" | grep -Ei \'ttyS|ttyUSB|ftdi|cp210|pl2303|disconnect\'',
    ],
    steps: [
      step('Where a serial-to-Ethernet gateway sits in front of the link, check its own connection '
        + 'or session log for the affected port going idle, erroring or resetting — it is often the '
        + 'only device on the path capable of recording anything about a serial segment at all.',
        'host logs', 'The port\'s state at the time of the gap from the gateway\'s own log — idle, errored or reset — or a stated absence of any gateway log.'),
      step('Check the polling master\'s own timeout and retry counters for the device on that link, '
        + 'and note whether the failure is one device or every device on the port. A serial failure '
        + 'shows up there as repeated timeouts well before anyone thinks to check the cable, and a '
        + 'multidrop loop losing all its devices at once is the port or the cable, not one relay.',
        'Historian · host logs', 'The onset of timeouts timestamped, and a stated answer on whether it was one device or the whole port.'),
      step('On the master host, establish which process held the serial port in the window and '
        + 'whether the application was refused the port rather than left waiting on it. An '
        + 'application that opened the port and got no reply points at the link; one that could not '
        + 'open it points at another process on the host, which is the technique rather than a '
        + 'fault. Read what the host already records — lsof, journald, Sysmon process creation — '
        + 'rather than restarting anything. Where the master is a hardware RTU or front-end with no '
        + 'host logs, say so; the timeout counters are then all this technique offers.',
        'host logs · Sysmon · journald', 'The process holding the port named and expected, an unexpected one filed, or a stated no-host-evidence gap.'),
      step('Rule out the physical explanations that dominate serial problems in practice — a loose '
        + 'connector, a failed converter — by asking whoever has physical access, rather than '
        + 'concluding it from logs alone.',
        'Site engineer · Psephos · Comms', 'A recorded physical-cause check from a named person, with the answer.'),
    ],
    evidenceExpected:
      'Gateway or master-side evidence of the outage with its onset timestamped, the process '
        + 'holding the port on the master named or the gap stated, and a recorded physical-cause '
        + 'check.',
    doNext:
      'Escalate once a physical cause has been checked and ruled out — a serial outage on a '
        + 'protection-relay link is worth chasing down in person either way. An unexpected process '
        + 'holding the port on the master is an incident, not a comms fault; nobody kills it or '
        + 'frees the port on the hunter\'s judgement.',
  },

  'T1695.002': {
    intent:
      'Blocking Ethernet is rarely done by cutting a cable. An adversary who is already on the '
        + 'engineering workstation or the HMI blocks from there — a host firewall rule, a killed '
        + 'master process, a claimed address — and the link on the switch stays up throughout. So '
        + 'the discriminating evidence is not the link-state log but a pair: did control traffic to '
        + 'a device stop, and did the port stay up while it did. Link-down with a matching switch '
        + 'event is a fault or a hand on a cable until shown otherwise; a polling gap with the link '
        + 'up is a host or device that was made to stop talking, and that is this technique. '
        + 'Ethernet is the one medium where both halves of that pair are logged, which is why this '
        + 'task is worth working where the serial and Wi-Fi ones mostly are not.',
    tools: [
      'Zeek',
      'Arkime',
      'switch syslog',
    ],
    dataSources: [
      'Zeek conn.log',
      'switch syslog (link state, spanning-tree, MAC flap)',
      'boundary firewall interface logs',
      'HMI and engineering workstation firewall and process logs',
      'maintenance records',
    ],
    terrain: [
      'control segments',
      'switches',
      'the IT/OT boundary',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut -d ts id.resp_h < conn.log | awk \'{print substr($1,1,13), $2}\' | sort | uniq -c',
      'zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log | awk \'$4=="S0"||$4=="REJ"\' | sort | uniq -c | sort -rn | head -40',
      'grep -Eih \'link.?(down|up)|%LINK|%LINEPROTO|%SPANTREE|topology change|MACFLAP\' /var/log/syslog /var/log/switch/*.log 2>/dev/null | tail -60',
    ],
    steps: [
      step('Find the gap on the wire first. Control traffic is periodic, so a per-responder count by '
        + 'hour shows a silenced controller as a missing hour, and conn_state S0 or REJ toward that '
        + 'device shows whether its master kept trying. Do this before opening switch logs, because '
        + 'the gap is what the switch logs will have to explain.',
        'Zeek', 'A list of device-and-window gaps, possibly empty, each noting whether the master kept trying.'),
      step('Pull switch and boundary firewall interface logs for link-down and link-up on the ports '
        + 'serving those devices and match them to the gaps. A gap with a matching link event is a '
        + 'fault or a hand on a cable until shown otherwise; a gap with the link up the whole time '
        + 'is the case this technique is about.',
        'switch syslog · Zeek', 'Each gap tagged link-down or link-up, with the switch event cited where there was one.'),
      step('For every link-up gap, name the end that went quiet and hunt it as a host. A master that '
        + 'stopped sending points at the engineering workstation or HMI: a firewall rule added '
        + '(Windows logs it as event 4946 where the audit policy is on), the master process killed, '
        + 'or a MAC flap on the switch where another host claimed its address. A controller that '
        + 'stopped answering while its master kept sending overlaps Denial of Service, T0814, and '
        + 'the evidence you collect is the same either way.',
        'host logs · switch syslog', 'The silent end named per link-up gap, and a host-side cause found or explicitly stated as not found.'),
      step('Check whether each outage maps to a single port, a single VLAN, or the whole segment, '
        + 'and look for spanning-tree topology changes in the same window. Blast radius separates '
        + 'targeted interference from infrastructure fault, and an adversary with switch management '
        + 'reroutes rather than cuts — which leaves the link up and a topology change in the log, a '
        + 'more informative trace than a plain link-down.',
        'switch syslog · Psephos · Network Map', 'Blast radius stated per outage, and every topology change in the window matched to a change record or filed.'),
    ],
    evidenceExpected:
      'Every polling gap in the window tagged link-down or link-up with the switch event cited, '
        + 'the silent end named for each link-up gap, and blast radius stated per outage.',
    doNext:
      'A link-up gap traced to a host-side block, or a single-port or single-VLAN outage with '
        + 'no maintenance record, escalates immediately; a whole-segment link-down gets the '
        + 'physical-cause check any other link failure would first. Nothing on the switch or the '
        + 'host is changed on the hunter\'s judgement.',
  },

  'T1695.003': {
    intent:
      'Wireless is the one medium in this family that can be blocked without touching any owned '
        + 'infrastructure at all — jamming and forged deauthentication happen over the air, and the '
        + 'access point records the effect, not the cause. That makes the limiting factor whether '
        + 'the site\'s wireless controller logs anything meaningful in the first place, and on a '
        + 'plant network it often does not. Where there is no wireless IDS the honest finding is '
        + 'frequently that this cannot be hunted from existing data, and saying so is more useful '
        + 'than a false assurance of coverage.',
    tools: [
      'wireless controller/AP logs',
      'Historian',
      'host logs',
    ],
    dataSources: [
      'Operational Databases',
      'Network Traffic',
      'Application Log',
      'wireless controller/AP association logs',
      'historian trends',
      'polling master timeout counters',
    ],
    terrain: [
      'wireless access points',
      'wireless field devices',
    ],
    commands: [],
    steps: [
      step('Establish whether the wireless controller or access points log association and '
        + 'deauthentication events at all, whether those logs are collected centrally, and whether '
        + '802.11w protected management frames are enforced. Where PMF is required a forged '
        + 'deauthentication is discarded and jamming is the only blocking left, which narrows what '
        + 'the rest of the task looks for; where nothing is logged, the rest of the task is not '
        + 'possible.',
        'Psephos · Characterization', 'A stated yes or no on log coverage, and on PMF enforcement.'),
      step('Where logs exist, look for the shape of a deauthentication attack rather than a count: '
        + 'several field devices dropped in the same second with the same reason code, then '
        + 'reassociating and dropping again, against the ordinary rate at which a single flaky link '
        + 'comes and goes. Jamming looks different — every client on the affected AP or channel '
        + 'goes at once, and the controller\'s noise-floor or channel-utilisation counters climb '
        + 'where it records them.',
        'wireless controller/AP logs', 'No simultaneous multi-device drop above the background rate, or the window and the devices named.'),
      step('Where no wireless-specific logging exists, fall back to the wired side: the polling '
        + 'master\'s timeouts and the historian\'s gap for each wireless-attached device show when it '
        + 'went quiet, and whether several went quiet together. That dates the outage; it cannot '
        + 'say the wireless link was the cause, and the record should say so.',
        'Historian · host logs', 'A dated gap per affected device, or none, with the wireless link recorded as unverifiable.'),
      step('Ask whoever owns the wireless what changed in the window — AP firmware, channel plan, '
        + 'new equipment or a welder near the devices. Plant Wi-Fi fails for mundane RF reasons far '
        + 'more often than it is jammed, and the question costs minutes.',
        'Site engineer · Psephos · Comms', 'A recorded answer from a named person.'),
    ],
    evidenceExpected:
      'Wireless log coverage and PMF enforcement stated explicitly, plus any simultaneous '
        + 'multi-device drop found and dated, or the wired-side gap where wireless logging is '
        + 'absent.',
    doNext:
      'A confirmed deauthentication or jamming pattern against field devices is filed and '
        + 'escalated, and treated as T1695 treats any blocked link — as a window in which something '
        + 'else may have happened unseen. A coverage gap is filed as its own finding for the site '
        + 'to close.',
  },

  'T1693.002': {
    intent:
      'Modular hardware — comms modules, I/O cards, remote adapters — carries firmware of its '
        + 'own that the main unit\'s inventory entry does not ask about, so the practical finding '
        + 'here is usually that nobody at the site knows this layer exists to be checked, rather '
        + 'than that it has been tampered with. Establishing that gap is worth more than anything a '
        + 'look at the module will produce, because a module\'s firmware can no more be verified '
        + 'passively than the controller\'s can; the update shape from the parent entry still '
        + 'applies, but with a weaker restart signature, and the honest output is a coverage '
        + 'statement.',
    tools: [
      'Psephos · Characterization',
      'Zeek',
      'Arkime',
    ],
    dataSources: [
      'asset inventory',
      'Zeek conn.log',
      'vendor advisories',
      'maintenance records',
    ],
    terrain: [
      'controllers',
      'remote I/O adapters',
      'appliances',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes < conn.log | sort -k5 -rn | head -30',
    ],
    steps: [
      step('Establish, module by module, whether the site\'s asset inventory tracks firmware at that '
        + 'level at all. An I/O card or comms daughterboard is frequently invisible to whatever '
        + 'process records "the PLC\'s firmware version", and a chassis with eight modules can carry '
        + 'nine firmware images of which the inventory names one.',
        'Psephos · Characterization · asset inventory', 'A stated coverage answer per module class: tracked, tracked but stale, or not tracked.'),
      step('Where module versions are already reported into an inventory or a monitoring system, '
        + 'check each against the vendor\'s advisories rather than treating a version number as '
        + 'assurance in itself. Read what has been collected; do not query the module for it.',
        'Psephos · Characterization · vendor advisories', 'A per-module version list with each version marked current, known-vulnerable, or unexpected.'),
      step('Look for the transfer half of the update shape from the parent entry, scoped to the '
        + 'chassis or remote adapter. A module update is routed over the backplane through the '
        + 'chassis\'s own Ethernet address, so on the wire it is a large inbound transfer to an '
        + 'address you already watch — and the restart that follows is the module\'s, not the CPU\'s, '
        + 'so polling may never gap. Match each transfer to a maintenance record; module updates '
        + 'are usually done in the same session as a CPU update, so a module-sized transfer with no '
        + 'session around it is the odd shape.',
        'Zeek · Arkime · maintenance records', 'Every large inbound transfer to a chassis or adapter matched to a maintenance session, or filed.'),
    ],
    evidenceExpected:
      'A coverage statement for module-level firmware per module class, a version check '
        + 'wherever collected data allowed one, and every large transfer to a chassis or adapter '
        + 'matched to a maintenance session.',
    doNext:
      'An untracked module-firmware layer is filed as a visibility gap for the site whether or '
        + 'not anything was found on it. A module suspected of carrying modified firmware is a '
        + 'vendor conversation, as with the parent entry; nothing is reflashed or reseated on a '
        + 'hunter\'s judgement.',
  },

  T0861: {
    intent:
      'Point and tag names are the map from a register address to what it actually means — '
        + 'pressure, flow, a safety interlock — and stealing that map is quieter and often more '
        + 'valuable than any single read or write, because it is what turns a wire full of numbers '
        + 'into a plant an adversary understands. On Modbus the names never touch the wire at all; '
        + 'they live in the project file and the historian\'s tag database, so the map is taken from '
        + 'the systems that hold it and the capture only ever shows the address walk. The tell is '
        + 'not the read itself but its shape: a client that walks an address space or pulls a full '
        + 'tag list once looks nothing like a master polling the same twenty points every second.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
      'host logs',
    ],
    dataSources: [
      'ICSNPP modbus_detailed.log',
      'ICSNPP OPC UA browse log',
      'OPC UA server audit logs',
      'historian audit log',
    ],
    terrain: [
      'historians and brokers',
      'engineering workstations',
      'controllers',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h address < modbus_detailed.log | sort -u | awk \'{n[$1" "$2]++} END {for (k in n) print n[k], k}\' | sort -rn | head -20',
      'zeek-cut id.orig_h id.resp_h < opcua-binary-browse.log 2>/dev/null | sort | uniq -c | sort -rn | head -20',
      'grep -Ei "browse|export|tag list" /var/log/historian/audit.log 2>/dev/null | tail -50',
    ],
    steps: [
      step('Count the distinct addresses each source touches on each controller and compare against '
        + 'its polling set. A master reads the same handful of registers on a metronome; a walker '
        + 'touches hundreds once and stops. Volume will not separate them — a walk can be fewer '
        + 'bytes than an hour of polling — but the address count will.',
        'ICSNPP modbus_detailed.log · Arkime', 'A per-source distinct-address count per controller; every source above its baselined polling set named, or none.'),
      step('On OPC UA, look at who issues Browse and whether the walk is bounded. Every client '
        + 'browses at session start, so a browse alone is not the finding; a client outside the '
        + 'baseline browsing, or a known connector walking the whole tree with no restart to '
        + 'explain it, is.',
        'ICSNPP OPC UA browse log · OPC UA server audit log', 'Each browsing client matched to a baselined connector and a session start, or filed.'),
      step('Check the historian and engineering software audit logs for a full tag-database export. '
        + 'That and the project file are the whole map in one place, and the export is usually '
        + 'logged even where the wire traffic is opaque. Project archives leaving the estate belong '
        + 'to T0882; this task owns the export.',
        'historian audit log · host logs', 'Every export matched to an authorised job, or filed.'),
      step('Treat a confirmed tag-list theft as intelligence for everything that follows: once an '
        + 'adversary has names, later writes need far less trial and error to land on the right '
        + 'register. Raise the priority of every write-detection task for this segment accordingly.',
        'Psephos · Evidence', 'A filed finding that names which downstream tasks now matter more.'),
    ],
    evidenceExpected:
      'Per-source distinct-address counts and browse attributions against baseline, and every '
        + 'tag-database export matched to a job or filed.',
    doNext:
      'A confirmed tag-map theft is filed and used to reweight later write-detection tasks '
        + 'toward the segment it covered, not treated as closed once recorded.',
  },

  T0877: {
    intent:
      'The I/O image is the controller\'s whole input and output state, and the technique as '
        + 'MITRE defines it reads that through the device\'s own API — on the wire only as the '
        + 'vendor engineering protocol, and from code on the device not at all. What a capture can '
        + 'show is the proxy: a read that sweeps the table rather than polling the blocks a '
        + 'master\'s screens need. A working master reads the same fixed blocks forever, often large '
        + 'ones, so a big read flags nothing; the shape worth finding is a run of reads across '
        + 'addresses nobody polls, each made once, because nothing that runs the process asks that '
        + 'way.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
    ],
    dataSources: [
      'Zeek modbus.log',
      'Zeek s7comm.log or enip.log where the ICSNPP parser is loaded',
      'baselined block-read pattern per master',
    ],
    terrain: [
      'controllers',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h func < modbus.log | sort | uniq -c | sort -rn | head -40',
      'zeek-cut id.orig_h id.resp_h register < modbus_register_change.log | sort | uniq -c | awk \'$1<3\' | head -60  # needs track-memmap.zeek',
    ],
    steps: [
      step('Count every (source, controller, function, address, quantity) tuple in the window. The '
        + 'high-count rows are the master\'s fixed block table and are the baseline; the rows seen '
        + 'once or twice are the population to read. In that remainder look for the sweep — one '
        + 'source reading consecutive address ranges at the protocol\'s maximum quantity, each once. '
        + 'That is a memory dump wearing the function code of a poll. On S7 or Logix estates the '
        + 'same shape is a run of area or tag reads in s7comm.log or enip.log, and without that '
        + 'parser it is not visible.',
        'Zeek modbus.log', 'A named source and the address span it swept, or a statement that no read outside the master\'s block table occurred.'),
      step('Attribute each read outside the block table to an engineering or diagnostic tool and a '
        + 'reason, from host logs on the source rather than by asking the controller. A read trips '
        + 'nothing that watches only for writes, so an unowned one is the finding.',
        'Zeek · host logs', 'Each unbaselined read attributed to a tool and a reason, or filed.'),
      step('Cross-reference against any point-and-tag findings for the same window. A swept image '
        + 'paired with a stolen tag map is a near-complete snapshot of the process, and the pairing '
        + 'is worth stating explicitly rather than filing the two separately.',
        'Psephos · Evidence', 'A joined finding where both are present.'),
      step('Say plainly where this cannot be seen. Access to the image through the controller\'s own '
        + 'runtime — code on the device, or a vendor protocol nobody parses — leaves nothing in a '
        + 'Modbus log, and MITRE\'s only log source for it is the asset itself. Route that to the '
        + 'program-change hunt, where the download that put the code there is visible even when the '
        + 'read is not.',
        'Psephos · Evidence', 'An explicit statement per controller class of whether the image is visible on the wire at all.'),
    ],
    evidenceExpected:
      'Reads outside the baselined block table per controller, any sweep named with its source '
        + 'and span, and a statement per controller class of whether the image is visible on the '
        + 'wire.',
    doNext:
      'An unattributed sweep on a controller already flagged for tag identification is '
        + 'escalated as deliberate process mapping, not logged as a routine anomaly — and nobody '
        + 'confirms it by reading the image themselves.',
  },

  T0801: {
    intent:
      'Watching process state is, by itself, the weakest signal in this tactic to hunt '
        + 'directly: a status or alarm read looks identical whether the reader is the SCADA system '
        + 'or an adversary timing a later action against a particular state. The honest position is '
        + 'that this is rarely a standalone finding — it earns its keep as corroboration, by '
        + 'putting a targeted read immediately before an action already flagged elsewhere. The one '
        + 'place it is attributable on its own is a historian or OPC server, which unlike a '
        + 'controller records which client asked.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
      'Historian',
    ],
    dataSources: [
      'Zeek modbus.log',
      'Zeek dnp3.log',
      'historian and OPC server access logs',
      'site tag map',
      'incident timeline of other findings',
    ],
    terrain: [
      'controllers',
      'HMIs',
      'historians',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h func < modbus.log | grep -E \'READ_(COILS|DISCRETE_INPUTS)\' | awk \'{print $2, $3, $4}\' | sort | uniq -c | sort -rn | head -40',
    ],
    steps: [
      step('Do not chase this in isolation. For each write or command already flagged under another '
        + 'task, look at the minutes before it from the same source: a burst of reads against the '
        + 'same controller that does not fit that source\'s polling baseline is the shape of '
        + 'somebody waiting for the process to reach a state before acting.',
        'Zeek modbus.log · Zeek dnp3.log · Psephos · Evidence', 'For every flagged action, a stated yes or no on whether a state-read burst preceded it, with the source and the window.'),
      step('Separate readers of state from readers of values. On Modbus the first cut is by function '
        + 'code — coils and discrete inputs carry run/stop, open/closed and alarm bits, holding and '
        + 'input registers carry measurements — and the tag map settles the rest. A source found '
        + 'under T0846 that reads status bits specifically, rather than the wide register sweeps a '
        + 'curious survey makes, is choosing its moment rather than mapping the plant.',
        'Zeek modbus.log · site tag map', 'Each unexplained speaker classified as reading state, reading values, or both, with the addresses that decided it.'),
      step('Check the historian and OPC server access logs for clients reading live state or alarm '
        + 'tags. This is where the technique is attributable on its own: the controller cannot say '
        + 'who asked, but a historian records the client, the tags and the time, and a client that '
        + 'is not an HMI, a report job or a named engineering tool has no reason to be there.',
        'Historian · OPC server logs', 'Every client reading live state named and its job stated, or filed as unexplained.'),
    ],
    evidenceExpected:
      'A stated finding on whether any flagged action was preceded by targeted state '
        + 'monitoring, which may honestly be "no correlation found", and a named list of historian '
        + 'and OPC clients reading live state.',
    doNext:
      'Wire evidence is filed as supporting evidence attached to whatever finding it '
        + 'corroborates; it does not stand up a case on its own. An unexplained historian or OPC '
        + 'client is a finding in its own right and goes to the lead.',
  },

  T0868: {
    intent:
      'Operating mode gates what is even possible on a controller: a download needs the CPU in '
        + 'a mode that permits it, and on many controllers that mode is set by a physical key on '
        + 'the front. So a mode read is the reconnaissance step for the action that follows it, not '
        + 'an end in itself, and the read alone rarely means anything — engineering software '
        + 're-reads CPU state the whole time it is online, and HMIs poll status constantly. What '
        + 'matters is who asked, and what the same session did next.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
    ],
    dataSources: [
      'Zeek modbus.log',
      'Zeek s7comm_read_szl.log (ICSNPP parser)',
      'engineering software access history',
      'HMI alarm history',
      'badge/camera log for physical key-switch presence',
    ],
    terrain: [
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h func < modbus.log | grep -E \'REPORT_SLAVE_ID|READ_EXCEPTION_STATUS|DIAGNOSTICS|DEVICE_IDENT\' | sort | uniq -c | sort -rn | head -40',
      'zeek-cut id.orig_h id.resp_h szl_id szl_id_name < s7comm_read_szl.log | sort | uniq -c | sort -rn | head -40',
    ],
    steps: [
      step('Count mode reads by source, not by presence. On S7 the read is SZL 0x0424 and TIA Portal '
        + 'issues it continuously while online, so the usual engineering station will show '
        + 'thousands and mean nothing; on Modbus there is no mode function, only Report Server ID '
        + '(17) with its run indicator and the vendor-defined bits in Read Exception Status (7) and '
        + 'Diagnostics (8). Anywhere other than the baselined engineering stations and HMIs, one '
        + 'read is enough to be a question.',
        'Zeek · engineering logs', 'Every mode-read source is a baselined engineering station or HMI, or one is named that is not.'),
      step('For each source that is not the usual one, read what the same session did next. A mode '
        + 'read followed by a program download, a STOP/RUN request or a register write is targeting '
        + 'practice; a read followed by nothing is much weaker evidence and usually an inventory '
        + 'tool.',
        'Zeek · Arkime', 'Each unexplained mode read paired with the next function in its session, and every read-then-write pair listed.'),
      step('The commonest mode check leaves nothing on the span at all: an engineer at the panel '
        + 'with a laptop on the front port. So for a controller that changed mode — the HMI alarm '
        + 'history normally records a STOP or RUN transition — with no matching session in the '
        + 'capture, badge and camera are the only record of who was there. A transition with '
        + 'neither a session nor a person at the panel is the finding, not a gap.',
        'HMI alarm history · badge log · camera log', 'Each off-wire mode transition matched to a named person at the panel, or filed as unexplained.'),
    ],
    evidenceExpected:
      'Mode reads attributed to a source, each unexplained one paired with what followed it in '
        + 'the same session, and every off-wire mode transition matched to a person or filed.',
    doNext:
      'A mode read followed by an unattributed write or download is escalated as a single '
        + 'event, not filed as two unrelated findings.',
  },

  T0852: {
    intent:
      'A screenshot is passive from the process\'s point of view — nothing on the wire changes — '
        + 'but it is an active act on the host, which makes this a host-hunting task wearing a '
        + 'collection label. Chase the capture tooling and the image artefact on the HMI itself; a '
        + 'sensor watching the control protocol will never see it happen. The exception is the '
        + 'commonest case: an adversary viewing the HMI over VNC or RDP captures the screen on '
        + 'their own end, leaves no file behind, and is found through the session rather than the '
        + 'artefact.',
    tools: [
      'host logs',
      'Zeek',
    ],
    dataSources: [
      'HMI process-execution logs (Sysmon, auditd, journald)',
      'file-creation events for image files',
      'remote-session logs on the HMI',
      'Zeek conn.log and files.log for egress',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
    ],
    commands: [
      'find /tmp /var/tmp /home -newermt "-7 days" \\( -iname "*.png" -o -iname "*.bmp" -o -iname "*.jpg" \\) 2>/dev/null',
      'journalctl --since "7 days ago" 2>/dev/null | grep -Ei "vnc|xrdp" | tail -50',
    ],
    steps: [
      step('Look for capture utilities in process execution on HMI hosts — scrot, xwd, import, '
        + 'ffmpeg with x11grab on Linux; PowerShell loading System.Drawing, nircmd or the snipping '
        + 'tool under a non-operator account on Windows — and for image files landing in temp or '
        + 'user directories. Operators do screenshot HMIs for shift reports, so the question is who '
        + 'and when, not whether. Where the HMI is an embedded panel with no host logging, record '
        + 'that the technique cannot be hunted there rather than reporting a clean result.',
        'Sysmon · auditd · journald', 'Every capture execution and fresh image artefact attributed to an operator action, or filed; a stated gap for any panel without host logs.'),
      step('Attribute every VNC and RDP session to the HMI in the window to a person and a purpose. '
        + 'A remote viewer is a screen capture that never writes a file on the host, and on OT it '
        + 'is how this technique most often happens.',
        'host logs · Zeek conn.log', 'Each remote session attributed, or one filed as an unexplained viewer.'),
      step('Check for an outbound session from the same host shortly after an image artefact appears '
        + '— that is the point the capture becomes exfiltration, and it is a materially worse '
        + 'finding than the file sitting on the host. files.log only names the image if it left '
        + 'over a protocol Zeek extracts files from; over TLS you get a byte count in conn.log and '
        + 'nothing else, so sort the host\'s outbound sessions by bytes rather than by type.',
        'Zeek files.log · Zeek conn.log · host logs', 'Any capture-then-egress pair identified, or the host\'s outbound sessions in the window listed and each accounted for.'),
      step('Where the HMI shows a safety-relevant process — fire, gas, emergency shutdown — treat '
        + 'any capture activity or unexplained remote viewer as safety-relevant on its own, since '
        + 'seeing the screen is often the step before manipulating it.',
        'Analyst', 'Escalation path exercised if the HMI is safety-related.'),
    ],
    evidenceExpected:
      'Capture-tool execution, unexplained image artefacts and unattributed remote sessions on '
        + 'HMI hosts, each matched to an operator or filed, with egress checked for every artefact.',
    doNext:
      'A safety-relevant HMI with any capture activity or an unexplained remote viewer goes to '
        + 'the lead immediately, ahead of the rest of the queue.',
  },

  T0840: {
    intent:
      'This is a host-log problem dressed as a network technique: an adversary already on a '
        + 'host listing its own current connections generates no new packets at all, so a sensor '
        + 'watching the wire sees nothing while the host\'s own execution log sees the whole thing. '
        + 'Hunting this on Zeek alone will always come back empty regardless of whether it '
        + 'happened; the most the wire can give you is the remote session the command was typed '
        + 'into. On OT the stakes are specific — an HMI\'s connection table is the list of '
        + 'controllers it polls, which is exactly the target list for the next move.',
    tools: [
      'host logs',
      'auditd',
      'Sysmon',
    ],
    dataSources: [
      'auditd execve records (comm= netstat, ss, lsof)',
      'Sysmon 1 (process create) or Security 4688 on Windows HMIs and engineering hosts',
      'shell history',
      'auth logs',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
      'historians and brokers',
    ],
    commands: [
      'grep -E \'comm="(netstat|ss|lsof)"\' /var/log/audit/audit.log 2>/dev/null | tail -50',
      'grep -hE \'^(netstat|ss|lsof)( |$)\' /home/*/.bash_history /root/.bash_history 2>/dev/null | tail -50',
    ],
    steps: [
      step('Establish first whether each host records process execution at all — an auditd execve '
        + 'rule, Sysmon, or 4688. Most HMIs do not by default, and on such a host this question has '
        + 'no answer rather than a negative one.',
        'host logs', 'A per-host statement of whether execution is logged, and a filed gap where it is not.'),
      step('Search the execution log and shell history on the hosts that do log for netstat, ss, '
        + 'lsof and Get-NetTCPConnection, rather than the network for their effect, since there is '
        + 'no network effect to find. In auditd the program is in the comm= and a0= fields; the '
        + 'proctitle is hex-encoded and a grep for the command line will miss it.',
        'auditd · Sysmon · shell history', 'A dated list of invocations per host and account, possibly empty.'),
      step('Attribute each invocation to a person and a reason. The same command run by an operator '
        + 'troubleshooting a link looks identical on the wire — there is none — but is a very '
        + 'different finding by who ran it and when, and the session it was run through is usually '
        + 'in the auth log.',
        'auth logs · host logs', 'Each invocation matched to a named person and a reason, or filed as unexplained.'),
      step('Treat an unexplained enumeration as a precursor rather than a closed finding. Its output '
        + 'is the set of controllers and brokers that host reaches, so the next move is most likely '
        + 'against one of them: flag the host, and put its peers on the watch list for a new master '
        + 'or subscriber.',
        'Psephos · Evidence', 'The host and the peers it polls flagged for follow-up, not just the command filed.'),
    ],
    evidenceExpected:
      'Connection-enumeration invocations per host attributed to a person and a reason or filed '
        + 'as unexplained, and a stated gap for every host that does not log execution.',
    doNext:
      'An unexplained enumeration on an HMI or engineering workstation raises priority on the '
        + 'controllers that host polls: a new master or subscriber appearing at any of them is the '
        + 'follow-on move.',
  },

  'T0846.001': {
    intent:
      'The parent technique\'s signature is fan-out — one source touching many controllers '
        + 'lightly. What this sub-technique adds is the vertical shape: many ports against one or a '
        + 'few hosts. On a controller whose network stack was written for a fixed set of peers, '
        + 'that shape is not merely reconnaissance, it is a documented cause of a fault, so the '
        + 'scan and the incident can be the same event. Hunt it with more urgency than the other '
        + 'discovery findings, and count distinct ports rather than connections, because the '
        + 'legitimate poller will always win a connection count.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
    ],
    dataSources: [
      'Zeek conn.log',
      'scanner and commissioning schedule',
    ],
    terrain: [
      'controllers',
      'HMIs',
      'appliances',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | sort -u | awk \'{print $1,$2}\' | uniq -c | sort -rn | head -20',
      'zeek-cut id.orig_h id.resp_h conn_state < conn.log | sort | uniq -c | sort -rn | head -40',
    ],
    steps: [
      step('Rank source-destination pairs by distinct destination ports, not by connection count. A '
        + 'master polls one port thousands of times; a scanner touches dozens once. Counting '
        + 'connections puts the master at the top of the list and hides the scan under it.',
        'Zeek conn.log', 'No pair beyond the handful of ports its role needs, or one pair with tens to hundreds of distinct ports named as the scan.'),
      step('For the target, read conn_state before, during and after the window — from the scanner\'s '
        + 'side and from the legitimate poller\'s. The scanner\'s REJ and S0 rows say which ports '
        + 'were closed; the poller\'s rows going from SF to S0 say the controller stopped answering, '
        + 'which is the fault the intent warns about.',
        'Zeek', 'Either the target\'s poller kept getting SF through and after the window, or the timestamp at which its answers stopped.'),
      step('Identify the source before assuming an adversary. The commonest port scanner on a '
        + 'control segment is an IT vulnerability scanner whose scope was widened, and that is a '
        + 'finding worth filing on its own terms, because it will do the same thing next cycle.',
        'Zeek · Psephos · Comms', 'The source named as a scheduled scanner, a commissioning host, or neither — with a named person behind the answer.'),
    ],
    evidenceExpected:
      'Pairs ranked by distinct-port count, the top pair\'s target checked for post-scan '
        + 'responsiveness from its poller\'s conn_state, and the source attributed.',
    doNext:
      'A port scan that reached a controller goes to the lead before the rest of the queue, '
        + 'whatever the source turns out to be: an IT scanner that can crash a PLC is a safety '
        + 'finding, not a misconfiguration.',
  },

  'T0846.002': {
    intent:
      'A broadcast query is a single frame answered by every device on the segment that speaks '
        + 'the protocol, which makes it a cheaper and faster inventory than the sequential fan-out '
        + 'the parent technique describes — the tell is a burst of near-simultaneous replies from '
        + 'previously quiet devices rather than a pattern spread over time, and because one clean '
        + 'sweep is usually all the adversary needs, the hunt has to take a single event seriously '
        + 'and search the whole retention for it, not just the window.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
    ],
    dataSources: [
      'Zeek conn.log',
      'Zeek bacnet.log and enip.log where the ICSNPP parsers are installed',
      'raw pcap for Profinet DCP',
    ],
    terrain: [
      'control segments',
      'building automation',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | awk \'$3=="255.255.255.255" || $3 ~ /\\.255$/\' | sort -k1 -n | head -40',
      'tcpdump -nr capture.pcap \'ether dst 01:0e:cf:00:00:00 or (udp and (dst port 47808 or dst port 44818) and ether broadcast)\' | head -40',
    ],
    steps: [
      step('List every frame sent to the segment or limited broadcast address on a control port — '
        + '47808 for BACnet Who-Is, 44818 for EtherNet/IP List Identity — then look for what '
        + 'answered it within the next two seconds. BACnet I-Am replies are themselves broadcasts '
        + 'and land in the same list; EtherNet/IP replies are unicast back to the requester, so '
        + 'they appear as many sources hitting one destination on one ephemeral port, and a sensor '
        + 'sees them only if it sits between requester and responders. The .255 pattern catches /24 '
        + 'and coarser subnets only, so check the segment mask before trusting an empty result.',
        'Zeek', 'A table of broadcast queries in the window, each with its source, port and the count of devices that answered, possibly empty.'),
      step('Attribute each query to a protocol and compare its source against the short list of '
        + 'things that legitimately issue one: the BMS head-end, the engineering workstation, the '
        + 'commissioning laptop. Who-Is and List Identity are routine configuration-tool traffic on '
        + 'building-automation and industrial-Ethernet segments respectively, so a known source '
        + 'with a documented reason is a weaker finding than an unrecognised one — and a broadcast '
        + 'does not cross a router, so an unrecognised source is on the segment, or on BACnet came '
        + 'through a BBMD whose forwarded-NPDU traffic names the real origin.',
        'Zeek · Arkime', 'Each query attributed to a protocol and a source, with every source not on the baseline of legitimate broadcasters named.'),
      step('Read the pcap for what conn.log cannot show. Profinet DCP Identify-All is an '
        + 'Ethernet-layer multicast, not IP, so on a Siemens estate the most common broadcast sweep '
        + 'never appears in conn.log at all. Note the converse too: Modbus has no discovery reply '
        + 'to a broadcast, so on a Modbus-only segment this technique has nothing to ride on and a '
        + 'negative there is a fact about the protocol rather than a finding.',
        'tcpdump · Zeek', 'DCP Identify-All frames listed with their sources, or a stated reason the segment carries no broadcast-discoverable protocol.'),
      step('Run the same query over the full capture retention, not just the hunt window. A segment '
        + 'inventory rarely needs a second sweep, so a single Who-Is from a workstation three weeks '
        + 'ago is the whole event and there will be no repeat to catch.',
        'Zeek · Arkime', 'The full retention searched, and every one-off broadcast from a non-baseline source listed alongside the in-window ones.'),
    ],
    evidenceExpected:
      'Broadcast-discovery events across the full retention with protocol, source and '
        + 'responding device set recorded, and a stated answer on whether the sensor position could '
        + 'see the replies at all.',
    doNext:
      'An unrecognised source performing a broadcast sweep is filed as reconnaissance from a '
        + 'host already on the segment, and the device set it now knows about is prioritised for '
        + 'closer watching.',
  },

  'T0846.003': {
    intent:
      'A multicast query is answered only by the devices that joined the group, so the '
        + 'responding set is a device class rather than a segment, and the group the adversary '
        + 'chose says what it was after: 239.255.255.250 for WS-Discovery reaches cameras and '
        + 'Windows hosts, 224.0.0.251 for mDNS reaches HMIs and anything with a browser, and a '
        + 'PROFINET DCP Identify-All reaches field devices. The groups in use on a control segment '
        + 'are few and static — PTP, a routing-protocol hello, mDNS chatter from the HMIs — so a '
        + 'source that has never queried a discovery group before is anomalous before you know what '
        + 'it asked, and the answers it collected are the inventory it now holds.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
    ],
    dataSources: [
      'Zeek conn.log (id.resp_h in 224.0.0.0/4)',
      'Zeek dns.log (mDNS on 5353)',
      'switch IGMP-snooping group tables',
      'PROFINET DCP where a parser or raw capture exists',
    ],
    terrain: [
      'control segments',
      'building automation',
      'camera and physical-security segments',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h id.resp_p proto < conn.log | awk \'{split($2,o,"."); if ((o[1]+0)>=224 && (o[1]+0)<=239) print}\' | sort | uniq -c | sort -rn | head -40',
      'zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | awk \'$3=="239.255.255.250" && ($4==3702 || $4==1900)\' | head -40',
    ],
    steps: [
      step('Inventory every source-group-port triple in the window and diff it against the baseline. '
        + 'The routine groups are few — PTP on 224.0.1.129, routing-protocol hellos on 224.0.0.x, '
        + 'mDNS from the HMIs — and a new source sending to a discovery group (WS-Discovery on '
        + '239.255.255.250:3702, SSDP on :1900, mDNS on 224.0.0.251:5353) is the finding, whatever '
        + 'it asked.',
        'Zeek', 'An empty diff, or a source-group pair to explain.'),
      step('For each discovery query, collect the replies that came back to the querier in the '
        + 'following seconds and read them as a class inventory. conn.log records the query as a '
        + 'one-way flow to the group and each unicast answer as its own flow back, so the '
        + 'responders are found by correlating on the querier\'s address and the timestamp, not in '
        + 'the query\'s own row.',
        'Zeek · Arkime', 'A responder list per query, named by device class.'),
      step('Where the querier is not on the responders\' segment, find out whether multicast is '
        + 'forwarded across that boundary on purpose. 224.0.0.251 is link-local and is never '
        + 'routed; 239.255.255.250 is administratively scoped and only crosses a router if somebody '
        + 'configured it to. An off-segment source therefore means either a routing configuration '
        + 'the site can name, or a capture point that sees more than one segment.',
        'Zeek · network configuration', 'Each off-segment multicast source explained by a named routing configuration or by tap placement, or filed.'),
      step('Match the protocol to a known engineering or discovery tool with a documented user — '
        + 'WS-Discovery from the video management server enumerating ONVIF cameras, DCP '
        + 'Identify-All from a PROFINET engineering station — before treating an unattributed one '
        + 'as reconnaissance. DCP is Layer 2 on its own Ethertype and never appears in conn.log; it '
        + 'needs a PROFINET-aware parser or a raw capture.',
        'Zeek · tcpdump', 'Each discovery query attributed to a tool and a person, or filed.'),
    ],
    evidenceExpected:
      'The multicast source-group inventory diffed against baseline, a responder list per '
        + 'discovery query, and each query attributed to a tool and a person or filed.',
    doNext:
      'An unattributed discovery query is filed as reconnaissance and the responder set it '
        + 'collected is prioritised for closer watching; one arriving from off-segment goes to the '
        + 'lead, since the site either forwards multicast deliberately or does not know that it '
        + 'does.',
  },

  T0887: {
    intent:
      'Distributed OT — pipelines, water networks, remote RTUs — often runs its backhaul over '
        + 'RF, and a receiver emits nothing: a purely over-the-air collection episode leaves no '
        + 'trace on the wired network and none in the air either. So the honest scope of this task '
        + 'is "what can we even see," and the hunt goes where an adversary has to do more than '
        + 'listen — the transmissions of a device joining, probing or jamming the link, and the '
        + 'radios and repeaters that are network hosts whatever else they are.',
    tools: [
      'spectrum monitoring where deployed',
      'wireless IDS or WLAN controller logs where deployed',
      'Zeek',
      'host logs',
    ],
    dataSources: [
      'RF spectrum survey or SDR capture logs, where collected',
      'radio and repeater inventory, including link encryption settings',
      'radio management and join logs (WLAN controller, WirelessHART or Zigbee network manager)',
      'backhaul link error and availability logs',
    ],
    terrain: [
      'remote sites and RTUs',
      'wireless backhaul',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | awk \'$3==22||$3==23||$3==80||$3==161||$3==443\' | sort -u | head -40',
    ],
    steps: [
      step('Establish, per link, what radio and protocol carry it, whether the link is encrypted, '
        + 'and whether anything monitors the band. Without a sensor at the physical layer this '
        + 'technique is unobservable from the network side, and that limit belongs in the finding '
        + 'rather than being hidden by it; the encryption setting decides whether a sniff yields '
        + 'the process or ciphertext.',
        'radio inventory · Analyst', 'A stated answer per link: protocol, encryption, and what if anything monitors it.'),
      step('Where a spectrum or wireless IDS log exists, look for the transmitting side of an '
        + 'adversary — a receiver is invisible, but a device that joins, probes or jams is not: an '
        + 'unknown node attempting to join a WirelessHART or Zigbee mesh, deauthentication or probe '
        + 'frames on 802.11, a new carrier on the licensed backhaul band, or a run of link errors '
        + 'and retransmits on a link that is otherwise stable. Think range rather than proximity: a '
        + 'directional antenna receives a 900 MHz link from kilometres away.',
        'spectrum monitoring · wireless IDS · link error logs', 'Every transmitter and join attempt in the log matched to an inventoried radio, or one filed.'),
      step('Treat a compromised radio or repeater on the backhaul path as the more findable version '
        + 'of this problem: its management plane is on the wire even when the RF exchange it '
        + 'enabled is not. Restrict the command to the addresses in the radio inventory and '
        + 'attribute every SSH, telnet, web or SNMP session to the management station and a change; '
        + 'a radio\'s flow set should be its peer and its manager and little else.',
        'Zeek · host logs', 'Each radio\'s management sessions attributed and its flow set matching its function, or one filed.'),
    ],
    evidenceExpected:
      'A per-link statement of protocol, encryption and RF visibility, every logged transmitter '
        + 'or join attempt matched to an inventoried radio, and each backhaul radio\'s management '
        + 'sessions attributed.',
    doNext:
      'An unmonitored or unencrypted RF link is filed as a visibility gap or exposure in its '
        + 'own right, the same way an unmonitored segment or a surviving default credential is; '
        + 'nothing is retuned or rekeyed on a hunter\'s judgement.',
  },

  T0888: {
    intent:
      'This is the step after the parent technique finds a device: an identification request '
        + 'asks a controller or appliance to describe itself — make, model, firmware revision — '
        + 'which is exactly what tells an adversary which manual and which known vulnerabilities '
        + 'apply. A successful identification response to an unrecognised requester is a sharper '
        + 'signal than the earlier discovery-stage connection ever was, because it marks the shift '
        + 'from finding a device to targeting it.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
    ],
    dataSources: [
      'Zeek modbus.log — function code 43 is logged as ENCAP_INTERFACE_TRANSPORT, and the exception column says whether the device answered',
      'Zeek enip.log or s7comm.log where an ICSNPP parser is installed — List Identity and SZL module-identification reads are the same question on those protocols',
      'asset inventory',
    ],
    terrain: [
      'controllers',
      'appliances',
      'HMIs',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h func exception < modbus.log | awk \'$4=="ENCAP_INTERFACE_TRANSPORT"\' | sort -k2,3 | uniq -c -f1',
    ],
    steps: [
      step('Pull every request that asks a device to describe itself rather than report a process '
        + 'value. On Modbus that is function 43, which Zeek names ENCAP_INTERFACE_TRANSPORT; it '
        + 'also carries CANopen, so on a segment with CANopen gateways confirm the MEI type is 0x0E '
        + 'in the Arkime session before counting it. Mark each requester as the tool that already '
        + 'maintains that device\'s inventory, or not.',
        'Zeek · Arkime', 'A list of source-to-device pairs that requested identification in the window, each source marked as the inventory tool or as unattributed.'),
      step('Cross-reference against the speaker-set diff run for the parent technique. A new speaker '
        + 'who goes on to request device identification has moved from finding a device to '
        + 'targeting it, and that transition is the finding worth naming explicitly.',
        'Zeek', 'Each identification exchange placed on the discovery-to-targeting timeline for its source.'),
      step('Separate answered requests from refused ones. A device that does not implement function '
        + '43 replies ILLEGAL_FUNCTION, which lands in the exception column; a request with no '
        + 'exception was answered, and the adversary now has what they needed to pick an exploit or '
        + 'a manual. Treat that as materially worse than an identical request that got nothing.',
        'Zeek', 'Every identification request marked answered or refused, with the answered ones from unattributed sources listed first.'),
      step('State which protocols this was actually checked on. Base Zeek decodes identification '
        + 'only for Modbus; without an ICSNPP parser an EtherNet/IP List Identity or an S7 SZL read '
        + 'is invisible as such, and a negative here is only as wide as the decoders in place.',
        'Analyst', 'A named list of protocols covered and, per T0842, of those where identification could not be seen.'),
    ],
    evidenceExpected:
      'Identification request/response pairs attributed to a known asset-management source or '
        + 'filed, with answered or refused stated for each and the protocols actually decoded '
        + 'named.',
    doNext:
      'An unattributed answered identification is escalated alongside anything else that source '
        + 'has touched, since it marks a shift from discovery to targeting.',
  },

  T0830: {
    intent:
      'Adversary-in-the-middle in OT can serve two purposes from one position — reading '
        + 'everything that transits and, at the same time, feeding the HMI a false view while '
        + 'feeding the controller a false command — and a hunter cannot tell which from the '
        + 'position alone, only from what changes. So this is hunted by its precondition rather '
        + 'than its content: occupying a path that should not have a device on it usually leaves '
        + 'evidence — an address binding, a TTL, a port event — even when nothing it forwarded '
        + 'does.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
    ],
    dataSources: [
      'switch MAC-move and Dynamic ARP Inspection logs where the switch emits them',
      'switch port link-state history',
      'Zeek conn.log with MAC logging (orig_l2_addr, resp_l2_addr)',
      'packet capture, for IP TTL',
    ],
    terrain: [
      'control segments',
      'the IT/OT boundary',
    ],
    commands: [
      'zeek-cut id.orig_h orig_l2_addr < conn.log | sort -u | awk \'{n[$1]++; m[$1]=m[$1]" "$2} END {for (h in n) if (n[h]>1) print h, m[h]}\'',
      'tcpdump -nn -v -r capture.pcap \'tcp port 502 or tcp port 20000 or tcp port 1883\' 2>/dev/null | grep -oE \'ttl [0-9]+\' | sort | uniq -c | sort -rn',
    ],
    steps: [
      step('Look for an address binding that changed. A controller\'s IP resolving to more than one '
        + 'MAC in the window, or the switch logging a MAC move or an ARP-inspection denial on a '
        + 'port that carries one fixed device, is the strongest AiTM tell available from existing '
        + 'collection — the population is fixed, so a second MAC behind a known IP has no innocent '
        + 'explanation short of a documented hardware swap.',
        'Zeek conn.log · switch logs', 'One MAC per controller and HMI address across the window, or a second MAC named with the time it appeared.'),
      step('Read the IP TTL on traffic arriving from each controller and HMI. Devices on a '
        + 'single-switch segment deliver their stack\'s initial value untouched — 64, 128 or 255 — '
        + 'and a host forwarding the traffic through its own IP stack decrements it by one. A value '
        + 'one below a known initial, from a device that has never sent it before, is a forwarding '
        + 'hop that should not exist. An inline transparent bridge leaves this untouched; the only '
        + 'log it leaves is the link-down and link-up on the switch port when it was inserted, so '
        + 'pull port state history for the window where the switch keeps it.',
        'tcpdump · switch port logs', 'One initial TTL per source address, or a decremented value tied to a source and a first-seen time; port link events in the window accounted for.'),
      step('Where an HMI-versus-wire divergence has already been found under view-manipulation '
        + 'hunting, treat positioning-in-the-path as one candidate mechanism and look for the '
        + 'evidence above rather than filing the two as unrelated findings.',
        'Psephos · Evidence', 'Any view-manipulation finding checked against a positioning explanation.'),
    ],
    evidenceExpected:
      'An IP-to-MAC and TTL stability check per control segment, with any second binding, '
        + 'decremented TTL or unexplained port link event attributed to a documented change or '
        + 'filed.',
    doNext:
      'A confirmed foreign device in the path is an incident, not a finding — it is '
        + 'intercepting live control traffic, and goes to the lead immediately. Nobody clears an '
        + 'ARP cache or bounces the port to shake it off; that tells the adversary and can drop the '
        + 'control session.',
  },

  T0802: {
    intent:
      'Scripted collection gives itself away by cadence rather than content. A person driving '
        + 'an HMI or an engineering tool is never as regular as a script, so a read pattern at a '
        + 'tight, constant interval from a source that is not a baselined polling master is the '
        + 'tell, even when every individual read is unremarkable. The harder case is the script '
        + 'running on the master itself, where cadence alone cannot separate it from the poll it '
        + 'hides behind — there the tell is a second interval superimposed on the first, or '
        + 'controllers and function codes that master never used before.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
      'host logs',
    ],
    dataSources: [
      'Zeek modbus.log',
      'Zeek conn.log',
      'OPC UA log from the ICSNPP parser where installed (base Zeek does not decode OPC UA)',
      'historian query logs',
      'host scheduling artefacts (cron, systemd timers, Task Scheduler Operational log)',
      'PowerShell script-block log (4104)',
    ],
    terrain: [
      'historians and brokers',
      'HMIs',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h < modbus.log | sort | uniq -c | sort -rn | head -20',
      'zeek-cut ts id.orig_h id.resp_h < modbus.log | sort -k2,3 -k1,1n | awk \'{k=$2" "$3; if (k in p) printf "%s %.1f\\n", k, $1-p[k]; p[k]=$1}\' | sort | uniq -c | sort -rn | head -40',
    ],
    steps: [
      step('Build a per-source interval histogram for each control protocol, not a volume table. A '
        + 'script shows one dominant interval; a person shows none. Diff every source that has one '
        + 'against the baselined master set — the population of pollers is fixed, so a new one is '
        + 'anomalous before you know what it read.',
        'Zeek modbus.log · historian query logs', 'A dominant interval per source, and every source that has one is a baselined master or is named.'),
      step('For each baselined master, check whether it now carries a second interval, reaches '
        + 'controllers it never polled, or uses function codes it never used. A script an adversary '
        + 'runs on the HMI or the historian shares that host\'s address, and this is the only wire '
        + 'evidence it leaves.',
        'Zeek modbus.log · Arkime', 'One interval and the usual target set per master, or a second cadence named against a host.'),
      step('Check the host in the same window for what ran the loop: a new cron entry or systemd '
        + 'timer, a registered scheduled task, a scripting-engine invocation. Collection needs '
        + 'somewhere to run from, and the artefact carries the account and the command line, which '
        + 'the traffic never will.',
        'cron · journalctl · Task Scheduler Operational log · PowerShell 4104', 'A scheduling artefact matched to the cadence, with its account and command line, or its absence stated per host.'),
      step('Where the loop reused a native, already-installed client — the vendor\'s OPC tool, the '
        + 'historian\'s own query utility — the finding is who ran it, from where and when, not the '
        + 'tool. Record the account and host against who normally drives that client.',
        'host logs · Psephos · Evidence', 'Account and host named for the run, and a stated answer on whether either normally drives that client.'),
    ],
    evidenceExpected:
      'An interval histogram per source with every regular source attributed to a baselined '
        + 'master or named, and the scheduling artefact, account and command line for any that is '
        + 'not.',
    doNext:
      'File the cadence and the scheduling artefact together; either alone is a materially '
        + 'weaker finding than the pair. A regular collector that is not a master is a finding '
        + 'whatever it read.',
  },

  T0811: {
    intent:
      'A single document repository can hand over more of the plant than weeks of network '
        + 'reconnaissance would — a network diagram or a set of P&IDs describes the architecture an '
        + 'adversary would otherwise have to reconstruct one connection at a time. Because these '
        + 'repositories are usually a small, nameable set of shares rather than "everything," this '
        + 'is a short list to check rather than a broad search. The evidence is share-side — who '
        + 'opened what, from where — not egress; whether the material then left is a separate '
        + 'question with its own logs.',
    tools: [
      'Zeek',
      'host logs',
    ],
    dataSources: [
      'Zeek smb_files.log',
      'Windows 5145 share-access events on the file server',
      'document-repository audit logs (SharePoint, Confluence, DMS)',
      'Zeek files.log for the transfer itself',
    ],
    terrain: [
      'file shares and document repositories',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h path < smb_files.log | sort | uniq -c | sort -rn | head -40',
      'zeek-cut ts id.orig_h id.resp_h name size < smb_files.log | grep -Ei \'\\.(vsdx?|dwg|pdf|acd|l5[kx]|ap1[45]|zip|bak)\' | head -50',
    ],
    steps: [
      step('Name the repositories that actually hold process-relevant material — network diagrams, '
        + 'P&IDs, vendor manuals, controller project backups — before searching. This is usually a '
        + 'short, specific list rather than every share on the estate, and the site engineer knows '
        + 'it better than the network map does.',
        'Site engineer · Psephos · Network Map', 'A named list of repositories worth checking first.'),
      step('Establish whether each one leaves a record at all before hunting in it. Share-access '
        + 'auditing on a Windows file server is off by default, and a tap sees the SMB session only '
        + 'if it covers the segment the server sits on. A repository with neither is unhuntable, '
        + 'and saying so is the finding.',
        'host logs · Zeek', 'Per repository: an audit log, a smb_files.log view, or a filed statement that neither exists.'),
      step('Count files opened per source per share. A person doing their job opens a handful of '
        + 'documents over a shift; one source opening tens of files across a share in minutes is '
        + 'the bulk shape, and it is worse from a host that is not an engineering workstation or '
        + 'the document owner\'s machine.',
        'Zeek smb_files.log · host logs', 'Every source touching a named repository attributed to a role, and any many-files-in-minutes session identified or filed.'),
      step('Sort what was actually read by file type. The log carries the file name even when it '
        + 'cannot show the content, and controller project files (.acd, .l5k, .ap14) and diagrams '
        + '(.vsd, .dwg) shorten every later step of an intrusion in a way that general '
        + 'documentation does not.',
        'Zeek smb_files.log · host logs', 'Accessed files classed by type, with project files and diagrams listed separately from the rest.'),
    ],
    evidenceExpected:
      'Repository access attributed to an account and a host, with bulk sessions and high-value '
        + 'document types both called out, and a filed statement for any repository that keeps no '
        + 'record.',
    doNext:
      'Confirmed collection of controller project files or network diagrams raises assessed '
        + 'intent and should reweight the hunt toward the controllers those documents describe. '
        + 'Whether the material then left is answered from the egress logs, not from here.',
  },

  T0893: {
    intent:
      'This is the least remarkable-looking technique in the tactic, because a local file read '
        + 'is not a connection or a request a hunter can filter for — it becomes visible only '
        + 'through host-level file-access or process telemetry, which large parts of an OT estate '
        + 'simply do not collect. The honest scope of this task on many hosts is establishing what '
        + 'evidence exists at all, not what it shows. What does leave a mark is the copy: an '
        + 'adversary stages what they take, and a staged project file or archive has a creation '
        + 'time where a read has nothing, so this is hunted as a copy rather than a read wherever '
        + 'timestamps are all you have.',
    tools: [
      'host logs',
    ],
    dataSources: [
      'host file-access auditing where present (Sysmon, Windows object access, auditd)',
      'process-execution logs',
      'file creation and modification timestamps',
      'Zeek files.log and conn.log for any subsequent egress',
    ],
    terrain: [
      'engineering workstations',
      'HMIs',
      'controllers where soft-PLC hosts exist',
    ],
    commands: [
      'find / -newermt "-7 days" -type f \\( -iname "*.acd" -o -iname "*.st" -o -iname "*.ap1[4-9]" -o -iname "*.zip" -o -iname "*.7z" \\) 2>/dev/null | head -40',
      'find /tmp /var/tmp /home -newermt "-7 days" -type f -size +1M 2>/dev/null | head -40',
    ],
    steps: [
      step('Establish what file-level telemetry actually exists per host class before looking for '
        + 'anything. Many OT hosts have no file-access auditing at all, and that gap is itself the '
        + 'finding, the same way it is for logic-change detection.',
        'host logs', 'A stated answer per host class on which of file-access auditing, process telemetry or usable timestamps exist; a named gap is a valid answer.'),
      step('Hunt the copy rather than the read. Most hosts mount with noatime or relatime, so '
        + 'opening a project file leaves nothing dependable, but staging one does: a .acd, .ap1x or '
        + '.st with a fresh creation time outside the engineering software\'s own project directory, '
        + 'or an archive that newly contains one. Where object-access auditing exists — Sysmon '
        + 'event 11 file creates, Windows 4663 with a SACL on the project share, an auditd watch — '
        + 'the shape is the same file touched by anything other than the engineering application: '
        + 'explorer, 7-Zip, PowerShell, xcopy.',
        'host logs · Sysmon · auditd', 'Every recent copy or archive of a project file attributed to a person and a task, or filed.'),
      step('Where local collection is followed by egress from the same host shortly after, treat the '
        + 'pair as one event. Collection that never leaves the host is a much smaller finding than '
        + 'collection that does. files.log only sees files carried on protocols Zeek parses, so '
        + 'check conn.log byte counts from the same host for the TLS case.',
        'Zeek files.log · Zeek conn.log', 'Each candidate copy paired with an egress from the same host within the window, or filed as collection-only.'),
    ],
    evidenceExpected:
      'A stated answer on available local-file telemetry per host class, every recent copy or '
        + 'archive of a project file attributed or filed, and each filed one matched to egress or '
        + 'recorded as collection-only.',
    doNext:
      'Pair a confirmed local copy with the boundary-crossing check already run elsewhere in '
        + 'the bank; do not treat it as resolved until that check is done.',
  },

  T0845: {
    intent:
      'An upload is read-only from the controller\'s point of view — nothing on the device '
        + 'changes — which makes it less consequential than a program download but no less '
        + 'significant, because it is usually the reconnaissance step that makes a later targeted '
        + 'logic change possible. The adversary who has the program can study it offline and come '
        + 'back with a change that looks like it belongs. Treat an upload as a leading indicator '
        + 'for that later change rather than hunting it as an isolated event.',
    tools: [
      'Zeek',
      'Arkime',
      'tcpdump',
    ],
    dataSources: [
      'Zeek conn.log',
      'engineering software access logs',
    ],
    terrain: [
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes < conn.log | awk \'$6+0>50000 && $6>$5\'',
    ],
    steps: [
      step('Look for the mirror image of the download pattern hunted under logic-change detection: a '
        + 'substantial transfer FROM the controller TO an engineering workstation. The engineering '
        + 'tool is almost always the originator of the session, so within one conn.log row a '
        + 'download is large orig_bytes and an upload is large resp_bytes — the same session shape, '
        + 'told apart by which side carried the bytes. An upload also leaves no restart or polling '
        + 'gap behind it, because nothing on the controller changed.',
        'Zeek conn.log', 'Every large controller–workstation session classed as upload or download by byte direction, with no restart following the uploads.'),
      step('Match each upload-shaped transfer to an upload or read-program action in the engineering '
        + 'software logs. Where the site runs a vendor audit or asset-management product it records '
        + 'which operation was requested even when the wire traffic is opaque; where it does not, a '
        + 'freshly written project file on the workstation is the trace an upload leaves. A puller '
        + 'that is not an engineering workstation at all is the finding regardless of what any log '
        + 'says.',
        'host logs', 'Each upload-shaped transfer matched to a logged action or a project file on a known engineering workstation, or filed.'),
      step('An upload changes nothing on the controller, so it does not carry the urgency a write '
        + 'does — but an unattributed one means somebody now has the logic to study. File it as a '
        + 'finding in its own right and raise the priority of every write- and logic-change task '
        + 'for that controller, since that is where the follow-up will land.',
        'Psephos · Evidence · Plan', 'A filed record per unattributed upload, and the affected controller\'s write-detection tasks flagged as higher priority.'),
    ],
    evidenceExpected:
      'Upload-shaped transfers classed by byte direction and matched to an access-log entry or '
        + 'project file, or filed, with a named puller for each.',
    doNext:
      'An unattributed upload is a finding, not an incident: it is filed, and it sharpens '
        + 'attention on that specific controller\'s write- and logic-change tasks rather than being '
        + 'escalated as a change to the process.',
  },

  T0807: {
    intent:
      'Command-line access to an engineering workstation or a Linux HMI is hunted exactly as it '
        + 'is anywhere else — session logons, shell history, process creation with the command line '
        + '— and nothing about the technique changes there. What changes is what the prompt is '
        + 'sitting next to: a shell on a box that can reach an engineering suite or a '
        + 'controller-communication library is a shell away from a process change, which raises the '
        + 'value of every login without altering how you find one. The one thing OT adds is the '
        + 'device console. Controllers, RTUs and control-segment switches expose telnet, SSH or a '
        + 'serial line of their own, and a session on one of those is in no workstation log — only '
        + 'on the wire, or in the device\'s syslog if anybody forwards it.',
    tools: [
      'auth.log',
      'journald',
      'Sysmon',
      'shell history',
      'Zeek',
    ],
    dataSources: [
      'auth.log / journald',
      'Sysmon 1 or Security 4688 with command line on Windows engineering hosts',
      'shell history',
      'Zeek conn.log and ssh.log toward controllers and switches',
      'device syslog where forwarded',
    ],
    terrain: [
      'engineering workstations',
      'HMIs',
      'controllers',
      'control-segment network devices',
    ],
    commands: [
      'journalctl _COMM=sshd --since \'7 days ago\' | tail -50',
      'tail -n 100 /home/*/.bash_history /root/.bash_history 2>/dev/null',
      'zeek-cut ts id.orig_h id.resp_h id.resp_p duration < conn.log | awk \'$4==22||$4==23\' | sort -u | head -40',
    ],
    steps: [
      step('Pull session logons, shell history and process creation for every engineering '
        + 'workstation and Linux HMI in scope, the same collection you would run on any host. On '
        + 'Windows that is Sysmon 1 or 4688 with the command line: cmd.exe or powershell.exe under '
        + 'an interactive or RDP logon, read with its parent, because a shell whose parent is the '
        + 'engineering suite is a different row from one under explorer.exe. On Linux it is sshd '
        + 'logons plus whatever history survived — bash writes it on exit and any shell can unset '
        + 'HISTFILE, so the logon record is the evidence and the history is a bonus, and an empty '
        + 'one is a fact about the host, not absence of activity.',
        'auth.log · journald · Sysmon 1', 'A logon list per host with its shell processes or history attached, and a note wherever history is missing.'),
      step('For each session, establish what the shell could reach from there — an engineering '
        + 'suite, an OPC client, anything that talks to a controller — before deciding how much the '
        + 'session matters.',
        'Analyst · host inventory', 'A stated reach per session, not just a session.'),
      step('Read the wire for consoles on the devices themselves. A telnet or SSH session to a '
        + 'controller, an RTU or a managed switch on the control segment is the CLI use MITRE means '
        + 'by devices, and it leaves nothing on any workstation — only a conn.log row, an ssh.log '
        + 'row where the sensor sees the handshake, and the device\'s own syslog if it is forwarded. '
        + 'Diff the sources reaching port 22 or 23 on a device against the engineering workstations '
        + 'that are supposed to, and treat telnet as a finding about the device even when the '
        + 'session is legitimate.',
        'Zeek conn.log · ssh.log · device syslog', 'Every console session to a device attributed to a workstation whose job it is, or a named source to explain.'),
      step('Match sessions against the maintenance and change schedule. Legitimate engineering work '
        + 'also happens from a command line, and the distinction is attribution, not the presence '
        + 'of a shell.',
        'Psephos · Comms', 'Every session matched to a named person or filed.'),
    ],
    evidenceExpected:
      'Logon, shell and process-creation evidence per in-scope host, every console session to a '
        + 'device attributed to a workstation, and all of it matched against the maintenance '
        + 'schedule.',
    doNext:
      'An unattributed session on a host that can reach a controller, or an unattributed '
        + 'console session on a device, is escalated toward the tasking and mode-change hunts, not '
        + 'closed as a generic host finding.',
  },

  T0823: {
    intent:
      'Process creation and command lines catch what a GUI session launches and nothing it does '
        + 'afterwards: a setpoint changed through an HMI screen or a project opened in an '
        + 'engineering tool leaves no command line, so the session itself — its source, start and '
        + 'duration — is most of the evidence, and its recording, where one exists, is the rest. On '
        + 'an HMI the stakes are higher only because the GUI in question is the operator\'s '
        + 'interface to the process, not because the hunting technique differs from any other '
        + 'remote-desktop or console review.',
    tools: [
      'Zeek',
      'auth.log',
      'Windows Security log',
      'jump host session logs',
    ],
    dataSources: [
      'Zeek conn.log (RDP/VNC ports)',
      'Zeek rdp.log',
      'jump host session recordings',
      'local console logon events (auth.log, Windows 4624 logon type 2 and 10)',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p duration < conn.log | awk \'$4==3389||($4>=5900&&$4<=5910)\' | sort -k5 -rn | head -40',
      'zeek-cut ts id.orig_h id.resp_h cookie client_name result < rdp.log | sort -u | head -40',
      'grep -E \'session opened|Accepted\' /var/log/auth.log | tail -50',
    ],
    steps: [
      step('Enumerate every remote-desktop, VNC and local console session to an HMI or engineering '
        + 'workstation in the window, by source and duration, and diff the sources against the '
        + 'short list of hosts that are supposed to open them. Legitimate sources are a jump host '
        + 'and a few named workstations; anything else is the finding before you know what it did. '
        + 'Where Zeek writes rdp.log, take the username hint and client hostname the client offered '
        + '— it is the only attribution the wire gives you.',
        'Zeek · auth.log · Windows Security log', 'A session list per HMI and workstation — source, start, duration — with every source on the expected list or named for follow-up.'),
      step('Where a jump host records the session, review the recording rather than inferring intent '
        + 'from connection metadata alone; where it does not, say so as a stated coverage gap '
        + 'rather than a clean result. The wire tells you a session happened and how long it '
        + 'lasted, never what was clicked.',
        'jump host', 'Every session reviewed, or its absence of review recorded.'),
      step('Correlate session timing against any operator report of odd on-screen behaviour. A VNC '
        + 'session shares the screen, so the operator watches the cursor move on its own; an RDP '
        + 'logon to a workstation-edition Windows HMI takes the console over and the operator finds '
        + 'the screen locked. Both get remembered, and neither experience is written anywhere, '
        + 'which makes the person at the console better evidence than any log here.',
        'Site operator · Psephos · Comms', 'Operator account recorded, matched or not to a session.'),
    ],
    evidenceExpected:
      'A session inventory per HMI and workstation with every source on the expected list or '
        + 'named, reviewed recordings where they exist, and an operator account where they do not.',
    doNext:
      'An unexplained session on a safety-related HMI is escalated the same way an unexplained '
        + 'project change is under T0832.',
  },

  T0834: {
    intent:
      'Native API abuse is largely invisible to command-line logging by design, so it needs '
        + 'process, module and API-level telemetry rather than a shell transcript — a fact true on '
        + 'any estate. The OT complication is that a vendor SCADA or HMI runtime already calls '
        + 'low-level APIs constantly for legitimate reasons, so a baseline of that specific build\'s '
        + 'normal module loads is a precondition here, not a nice-to-have, before anything can be '
        + 'told apart from routine driver interaction.',
    tools: [
      'Sysmon',
      'ETW',
      'auditd',
    ],
    dataSources: [
      'Sysmon 7 (image load)',
      'Sysmon 8/10 (CreateRemoteThread / ProcessAccess)',
      'auditd execve and ptrace syscall records (Linux HMIs)',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
    ],
    commands: [],
    steps: [
      step('Baseline module loads and process-access behaviour for the vendor SCADA or HMI runtime '
        + 'on a known-clean instance of the same build before judging anything in scope against it. '
        + 'The runtime\'s own API activity is the noise floor, and it differs by build, so a '
        + 'baseline from another version answers a different question.',
        'Sysmon · ETW', 'A per-build list of expected loaded modules and expected process-access sources for the runtime.'),
      step('Look for cross-process access into the runtime from anything outside its own install — '
        + 'an accessing image whose path is not under the vendor install directory and is not a '
        + 'named EDR, backup or monitoring agent. The runtime calling APIs on its own behalf cannot '
        + 'be separated from its baseline; something else reaching into the runtime\'s memory or '
        + 'threads is the one shape that can, and it is the one that ends with '
        + 'controller-communication privileges.',
        'Sysmon 8/10', 'Every ProcessAccess or CreateRemoteThread into the runtime attributed to its own install or a named agent, or one filed with the accessing image path.'),
      step('Where this telemetry does not exist on a given host, say that plainly rather than '
        + 'reporting a clean result the collection could not have produced. Sysmon without a '
        + 'configuration does not log image loads or process access at all, so a host that has '
        + 'Sysmon may still have no evidence for this task; check that events 7 and 10 are actually '
        + 'present for the runtime before reading their absence as clean.',
        'Psephos · Characterization', 'A stated coverage answer per host — events 7 and 10 present for the runtime, or not — positive or negative.'),
    ],
    evidenceExpected:
      'A per-build runtime module/API baseline, every cross-process access into the runtime '
        + 'explained or filed, and a per-host statement of whether the telemetry existed to answer '
        + 'the question.',
    doNext:
      'Confirmed injection into a process with controller-communication privileges is escalated '
        + 'as a precursor to manipulation of control, not closed as a workstation finding.',
  },

  T0853: {
    intent:
      'Scripting is hunted here the way it is hunted anywhere: interpreter invocation, '
        + 'script-block and shell logging, and the content of the command rather than the fact of '
        + 'it. Two things make OT different. Engineering suites ship their own scripting and macro '
        + 'layers — VBA in FactoryTalk View and iFIX, VBScript in WinCC, Cicode in Citect, Jython '
        + 'in Ignition, QuickScript in InTouch — so the accepted population on an engineering '
        + 'workstation is wider than on an office endpoint and has to be enumerated before anything '
        + 'outside it can stand out. And most of those layers execute inside the HMI runtime\'s own '
        + 'process, so a script that changes what an operator sees never appears as a '
        + 'powershell.exe or python.exe launch at all: script-block logging and process creation '
        + 'return a clean result that means nothing, and the only place that script is visible is '
        + 'the project file.',
    tools: [
      'PowerShell script block logging',
      'Sysmon',
      'auditd',
      'host logs',
    ],
    dataSources: [
      'PowerShell Operational log (4104 script block text)',
      'Sysmon 1 where the image or parent is powershell, pwsh, python, wscript or cscript',
      'auditd execve records and bash/python history on Linux engineering hosts',
      'HMI project files and their backups (the script sections)',
    ],
    terrain: [
      'engineering workstations',
      'HMIs',
    ],
    commands: [],
    steps: [
      step('List the scripting and macro layers that ship with the site\'s engineering suites — the '
        + 'interpreter, whether it runs as its own process or inside the vendor runtime, and which '
        + 'vendor tasks call it — and treat that list as the accepted population before hunting '
        + 'anything else. Vendor installers and licence tools that call wscript or cscript belong '
        + 'on it too.',
        'Vendor documentation · Psephos · Comms', 'A named list of expected interpreters and macro layers per suite, each marked in-process or standalone.'),
      step('Pull every standalone interpreter launch in the window from Sysmon 1 and auditd, and the '
        + 'script text itself from 4104, and read the content rather than the fact of invocation. '
        + 'Class each by what it touched: project directories, controller-communication libraries '
        + '(pymodbus, pycomm3, snap7, vendor OPC or COM DLLs), or neither. A script that imports a '
        + 'controller library is a different finding from one that renames files.',
        'PowerShell log · Sysmon · auditd', 'Each invocation classed by what it touched, with the ones reaching project files or controller libraries listed by name.'),
      step('For the layers that run inside the HMI runtime, read the script sections of the project '
        + 'file from the file or its most recent backup — not by opening the running project — and '
        + 'compare against the last commissioned copy. If no earlier copy exists, that is the '
        + 'finding: file the current one as the baseline.',
        'host logs · Psephos · Evidence', 'A stated diff against the commissioned copy per HMI project, or a filed baseline where none existed.'),
      step('Attribute every script outside the accepted population to a named person or a named '
        + 'scheduled job before filing it. On a control estate a script is a planned event with an '
        + 'owner, which is a cheap question with a real chance of being the answer.',
        'Psephos · Evidence · Comms', 'Every out-of-population script tied to a person or a job, or one that is not — that one is the finding.'),
    ],
    evidenceExpected:
      'A baseline of expected scripting and macro layers per engineering suite, every '
        + 'standalone interpreter launch classed by what it touched, the in-process script sections '
        + 'diffed or baselined per HMI project, and every script outside the population attributed '
        + 'or filed.',
    doNext:
      'A script that references controller-communication libraries or changes an HMI project is '
        + 'handled with the same do-not-touch-the-controller discipline as T0821 and T0889: file it '
        + 'and tell the lead, do not run it, revert it, or re-download the project to check.',
  },

  T0863: {
    intent:
      'The delivery half of this technique is hunted the way it is on any endpoint — where the '
        + 'file came from and what opened it — with one OT correction: an engineering workstation '
        + 'often has no mail client and no proxy, so the file arrived on a USB stick or a vendor\'s '
        + 'laptop, and its provenance is a file-create on a removable drive rather than an '
        + 'attachment log. The OT-specific payload is the engineering project itself. A controller '
        + 'project that, once opened, spawns anything beyond the suite\'s own helpers is the closest '
        + 'thing this estate has to a malicious macro, and it lands on the one host that is trusted '
        + 'to talk to the controller rather than on an ordinary desktop.',
    tools: [
      'Sysmon',
      'email/proxy logs where the workstation has them',
    ],
    dataSources: [
      'Sysmon 11 (file create) and 15 (file stream, Zone.Identifier) for how a file arrived',
      'Sysmon 1 (process create) with ParentImage for engineering-suite launches',
      'email or proxy logs, where the workstation has either',
      'project file timestamps',
      'change records',
    ],
    terrain: [
      'engineering workstations',
    ],
    commands: [],
    steps: [
      step('Establish how each project or installer file that reached an engineering workstation '
        + 'arrived. Where there is mail and a proxy, use them; where there is not — the usual case '
        + '— the arrival is a file-create on a removable drive letter or a copy from a vendor '
        + 'share, and the Zone.Identifier stream, if one was written, names the origin.',
        'Sysmon 11 · Sysmon 15 · email/proxy logs', 'An origin for every project or installer file that arrived in the window, or a named file with no origin.'),
      step('Treat the project file itself as the payload vector. Filter process creation for '
        + 'ParentImage equal to the engineering suite and read the child list against a baseline '
        + 'per suite version — suites spawn many helpers of their own, and the baseline is what '
        + 'makes cmd, powershell, wscript or anything outside the suite\'s install directory stand '
        + 'out.',
        'Sysmon 1', 'A child-process baseline per suite, and every launch whose children fall outside it named.'),
      step('Attribute the launches outside the pattern rather than every launch. Engineers open '
        + 'projects to look, so the question is a suite run outside shift hours, under an account '
        + 'that is not an engineer\'s, or against a project whose file was modified with no change '
        + 'record behind it.',
        'Sysmon 1 · change records · Psephos · Comms', 'Every out-of-pattern launch tied to a named person, or filed.'),
    ],
    evidenceExpected:
      'An arrival origin for every project or installer file in the window, a child-process '
        + 'baseline per engineering suite, and every out-of-pattern launch attributed or filed.',
    doNext:
      'A project file producing unexpected child processes is escalated toward T0889 rather '
        + 'than closed as a workstation-only finding — the workstation is the route to the '
        + 'controller, not the target. A file that arrived on removable media with no origin is '
        + 'handed to T0847.',
  },

  T0874: {
    intent:
      'Hooking is found the same way on an HMI as on any Windows host — an unexpected module in '
        + 'the process\'s load list, a hook-installation API call, a patched import table — and the '
        + 'reason to bother here is that a hook in the HMI\'s receive or rendering path is '
        + 'manipulation of view that leaves the wire untouched: Zeek sees the correct value polled, '
        + 'and only the screen lies. The view-versus-wire comparison under T0832 catches that only '
        + 'when the displayed side is read from the screen itself; taken from the HMI application\'s '
        + 'own tag log, as it often is for convenience, a rendering hook sits after the log and the '
        + 'comparison comes out clean.',
    tools: [
      'Sysmon',
      'PowerShell',
      'host logs',
    ],
    dataSources: [
      'Sysmon 7 (Image Load) on HMIs and engineering workstations, filtered to the HMI process image',
      'Sysmon 8 (CreateRemoteThread) and 10 (ProcessAccess) targeting the HMI process',
      'process module lists',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
    ],
    commands: [
      'Get-WinEvent -FilterHashtable @{LogName=\'Microsoft-Windows-Sysmon/Operational\'; Id=7} | Where-Object { $_.Message -match \'Signed: false\' } | Select-Object TimeCreated,Message -First 40',
      'tasklist /m /fi "imagename eq <hmi-client>.exe"',
    ],
    steps: [
      step('Enumerate the modules loaded into the HMI or SCADA client process and diff against a '
        + 'known-clean install of the same build. An unsigned or unfamiliar module is the finding; '
        + 'one loaded into the rendering or the communications path is the finding that matters.',
        'Sysmon 7 · tasklist /m', 'A module diff per HMI build, empty or with each addition explained.'),
      step('Look for the injection that precedes an inline hook — a remote thread created in, or '
        + 'write-capable access to, the HMI process from anything that is not the HMI\'s own vendor '
        + 'stack. Sysmon 7 misses a hook written into memory, and this is the event it leaves '
        + 'instead.',
        'Sysmon 8 · Sysmon 10', 'Every remote-thread and process-access event against the HMI process attributed to a named vendor component.'),
      step('Where continuous telemetry does not exist — common on this host class, and Sysmon 7 is '
        + 'often filtered off even where Sysmon runs — fall back to periodic module snapshots '
        + 'against a documented clean baseline, and record that this is weaker coverage than the '
        + 'continuous case.',
        'tasklist /m · Psephos · Evidence', 'A stated coverage level per HMI build, not an implied one.'),
      step('Treat a confirmed hook in an HMI process as a mechanism for manipulation of view and '
        + 'cross-file it against the T0832 task, noting where that task\'s displayed-side values '
        + 'came from: if they came from the application\'s own log rather than the screen, the '
        + 'comparison did not cover this.',
        'Psephos · Evidence', 'Hook finding cross-filed against the T0832 task, with the comparison\'s blind spot stated.'),
    ],
    evidenceExpected:
      'A module baseline per HMI/workstation build, every injection event against the HMI '
        + 'process attributed, and any hook found treated as manipulation-of-view evidence.',
    doNext:
      'A hook found in a safety-related HMI\'s rendering or receive path is escalated with the '
        + 'same urgency as a confirmed manipulation of view, because it is one: the operator\'s '
        + 'screen is not trustworthy, and they are told so first.',
  },

  T0890: {
    intent:
      'Exploitation for privilege escalation is hunted the same way on an HMI as on an office '
        + 'workstation — crash artefacts, a service spawning a child it has no reason to spawn, a '
        + 'failure in the log just before a privilege change — and what is worth holding is why the '
        + 'OT population differs. Engineering and SCADA software usually runs elevated already, so '
        + 'any bug in it is a privilege-escalation bug, and patching it means an outage nobody '
        + 'wants to schedule, so the vulnerable versions stay installed for years. The other half '
        + 'is that the operator account on many HMIs is already a local administrator, which means '
        + 'an adversary there has nothing to escalate to; on those hosts the technique is moot and '
        + 'the only thing left to hunt is the services holding privileges the operator does not. A '
        + 'successful exploit that does not crash its target leaves nothing in the Application log, '
        + 'so a clean log is not a negative result — the version inventory is.',
    tools: [
      'Sysmon',
      'Windows Event Log',
      'journald',
    ],
    dataSources: [
      'Windows Application log events 1000 and 1001',
      'WER ReportArchive',
      'coredumpctl and kernel segfault lines',
      'Sysmon 1 (User, IntegrityLevel, ParentImage)',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
      'historians and brokers',
    ],
    commands: [
      'wevtutil qe Application "/q:*[System[(EventID=1000 or EventID=1001)]]" /c:50 /rd:true /f:text',
      'dir %ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive /o-d',
      'coredumpctl list 2>/dev/null; journalctl -k --since "30 days ago" | grep -iE "segfault|general protection"',
    ],
    steps: [
      step('Establish, from what is already collected, what the operator session and each '
        + 'engineering or SCADA service actually runs as. Sysmon 1 carries User and IntegrityLevel '
        + 'for every process; if the operator is already a local administrator on an HMI there is '
        + 'nothing on that host for this technique to escalate to, and the hunt narrows to the '
        + 'services running as SYSTEM that the operator cannot reach.',
        'Sysmon 1 · service configuration records', 'A per-host statement of what runs elevated and whether the operator already does.'),
      step('Read the crash records before looking for exploitation directly: Application log events '
        + '1000 and 1001 and the WER ReportArchive on Windows HMIs, coredumpctl and kernel segfault '
        + 'lines on Linux ones. Match each faulting engineering or SCADA binary and version against '
        + 'the public CVEs for that version; a fault in a known-vulnerable version outweighs a '
        + 'clean process log.',
        'Windows Application log · WER · journald', 'Every fault in a control-software binary matched to a CVE for the installed version, or explicitly not.'),
      step('Look for a control-software service — the SCADA runtime, an OPC server, the historian '
        + 'service — spawning cmd.exe, powershell.exe, rundll32 or a shell, especially within '
        + 'minutes of a fault in the same binary. These services have a fixed and documented set of '
        + 'children, and it is short.',
        'Sysmon 1', 'Each child of a control-software service attributed to its documented function, or one filed.'),
      step('Record software version and patch level for every engineering and SCADA install in scope '
        + 'as a filed finding whether or not exploitation is confirmed. On this software class the '
        + 'exposure outlives the hunt, and it can only be fixed on the site\'s outage schedule.',
        'Psephos · Evidence', 'A filed version and patch level per install.'),
    ],
    evidenceExpected:
      'A per-host statement of what already runs elevated, crash records matched against CVEs '
        + 'for the installed versions, and a filed version inventory for engineering and SCADA '
        + 'software in scope.',
    doNext:
      'Confirmed exploitation on a host that talks to controllers is escalated toward the '
        + 'manipulation-of-control response, since privilege there is a step toward exactly that; '
        + 'the host is not touched until the process owner has been told.',
  },

  T0895: {
    intent:
      'Autorun abuse is old, well-understood tradecraft, and it survives here specifically '
        + 'because OT networks are more likely to be air-gapped or slow to patch, which makes '
        + 'removable media the normal way programs and patches move rather than the exceptional '
        + 'one. The population of legitimate USB use on an engineering workstation is larger than '
        + 'on an office machine, which is exactly why the historically simplest version of this '
        + 'technique still works against this environment in particular. The detail that decides '
        + 'how to hunt it: since KB971029 Windows honours autorun.inf only on optical media, so on '
        + 'a maintained host the shape is a mounted ISO or a USB device that enumerates as a '
        + 'CD-ROM, and a plain flash drive only autoruns on the XP-era builds that engineering '
        + 'suites keep alive.',
    tools: [
      'host logs',
      'Sysmon',
      'registry and policy state',
    ],
    dataSources: [
      'setupapi.dev.log or DriverFrameworks-UserMode 2003 (Windows), kernel journal (Linux)',
      'Sysmon 1 or Security 4688 (Process Create)',
      'Explorer NoDriveTypeAutoRun policy value',
      'file timestamps',
    ],
    terrain: [
      'engineering workstations',
      'HMIs',
    ],
    commands: [
      'Select-String -Path C:\\Windows\\inf\\setupapi.dev.log -Pattern \'USBSTOR|CdRom\' | Select-Object -Last 40',
      'Get-ItemProperty \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\' -Name NoDriveTypeAutoRun',
      'Get-WinEvent -FilterHashtable @{LogName=\'Microsoft-Windows-Sysmon/Operational\'; Id=1} | Where-Object { $_.Message -match \'Image: [D-Z]:\\\\\' } | Select-Object TimeCreated,Message -First 40',
      'journalctl -k | grep -iE \'usb-storage|sr[0-9]+: \' | tail -40',
    ],
    steps: [
      step('Establish per host whether autorun.inf can fire at all before hunting for it. Record the '
        + 'build and the NoDriveTypeAutoRun value: 0xFF or 0x95 means only an ISO or a '
        + 'CD-ROM-emulating device gets there, an XP-era build with no policy set means any stick '
        + 'does. Record that state as a finding on its own, independent of whether abuse is found, '
        + 'because it is the thing the site can fix on a schedule.',
        'registry · Psephos · Characterization', 'Per host: build, NoDriveTypeAutoRun value, and a stated yes or no on whether autorun.inf is honoured.'),
      step('Enumerate media-connect events and match each to a documented reason — a program '
        + 'transfer, a firmware update, a named person. setupapi.dev.log persists across reboots '
        + 'and exists on every Windows host whether or not anything is forwarded; the kernel '
        + 'journal names the device on Linux. USB use here is routine, so the baseline is the '
        + 'change record, not suspicion.',
        'setupapi.dev.log · journald', 'Every connect event matched to a documented transfer or a named person, or filed.'),
      step('For each connect, look for a process whose image path is on the removable or optical '
        + 'volume, or whose parent is explorer.exe within seconds of the mount. That process is the '
        + 'execution; autorun.inf is only the pointer to it, and it may never touch local disk.',
        'Sysmon 1 · Security 4688', 'Each process launched from removable or optical media attributed to a transfer, or filed with image path and hash.'),
      step('Where no process telemetry exists — usual on an engineering workstation nobody forwards '
        + 'from — fall back to file timestamps: anything written to local disk in the minute after '
        + 'a connect with no matching transfer. Say plainly that this is the weaker check and why.',
        'file system', 'Writes coincident with each connect listed and attributed, or a filed finding, with the telemetry gap stated.'),
    ],
    evidenceExpected:
      'Per-host autorun state and build, a media-connect inventory matched to documented '
        + 'transfers, and every process launched from removable or optical media attributed or '
        + 'filed.',
    doNext:
      'Unexplained execution from removable media on a host that can reach a controller is '
        + 'escalated toward T0821 and T0889 rather than treated as a standalone malware finding. '
        + 'The stick itself is evidence: it is imaged, not plugged into another host to see what is '
        + 'on it.',
  },

  T0821: {
    intent:
      'Modifying task configuration is a nearer cousin of adding a new program than of editing '
        + 'an existing one, which is why it belongs apart from program-hash baselining: a hash of '
        + 'the main logic file can look untouched while an additional task now runs alongside it on '
        + 'its own schedule, triggered by an event the operator never sees on the HMI. The task '
        + 'list is the thing that has to be baselined here, not just the program body. The nearest '
        + 'IT analogue is a scheduled task, and the discipline is the same one: baseline the '
        + 'scheduler, not the binaries it runs.',
    tools: [
      'host logs',
      'engineering software exports',
      'engineering software access logs',
    ],
    dataSources: [
      'controller task/configuration exports',
      'engineering software access logs',
      'change records',
    ],
    terrain: [
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'find / -iname \'*.l5x\' -o -iname \'*.l5k\' -o -iname \'*.tsproj\' -o -iname \'*.awl\' -o -iname \'*.scl\' 2>/dev/null | head -40',
      'grep -oh \'<Task Name="[^"]*" Type="[^"]*"[^>]*\' *.L5X 2>/dev/null; grep -Eh \'^\\s*TASK \' *.L5K 2>/dev/null; grep -lE \'ORGANIZATION_BLOCK\' *.awl *.scl 2>/dev/null',
    ],
    steps: [
      step('Get two task-configuration records per controller from the engineering workstation, not '
        + 'from the running controller: the export archived at commissioning or the last authorised '
        + 'change, and the most recent export or upload. Note the date of the latest one — it is '
        + 'only as current as the last time somebody uploaded, and that gap is a caveat on the '
        + 'finding, not a reason to close it by going online.',
        'engineering software exports', 'A dated baseline and a dated latest export per controller, or a statement of which one is missing.'),
      step('Diff task count, trigger type — cyclic, periodic, event, interrupt — and priority '
        + 'between the two. On Logix that is a task added beside MainTask, or an event trigger '
        + 'nobody can name; on S7 it is an organisation block not in the baseline — a '
        + 'cyclic-interrupt OB3x or hardware-interrupt OB4x beside OB1 is the shape Stuxnet used. A '
        + 'priority change that lets an added task pre-empt the main one is the same finding. Any '
        + 'of these is the finding even where the program hashes are unchanged.',
        'Psephos · Characterization', 'Task list, trigger types and priorities match the baseline, or a named divergence with the task and the trigger it carries.'),
      step('Check engineering software access logs for a task-configuration change and match it to a '
        + 'change record, the same discipline used for logic changes under T0889. The download that '
        + 'installs a task looks the same on the wire as T0889\'s transfer-then-restart, so that '
        + 'step is not repeated here; what this task adds is the diff of the task list.',
        'host logs · change records', 'Every task-configuration change matched to an authorised one, or an unmatched change filed with its date and source workstation.'),
    ],
    evidenceExpected:
      'A task-configuration baseline per controller, diffed against the latest export, with '
        + 'every change matched to a change record or filed.',
    doNext:
      'An unattributed task addition is not verified by querying the running controller for its '
        + 'current task list — that is a live engineering session with a production device. It goes '
        + 'to the process owner with the evidence already collected.',
  },

  T0858: {
    intent:
      'A mode change is one of a small set of ICS actions that shows up on the wire as a '
        + 'distinct, nameable command rather than a plain register write, and it has a physical '
        + 'fingerprint too: a controller in program mode stops executing logic, so whatever it was '
        + 'tending goes flat or frozen in the historian for the duration. Many controllers also '
        + 'have a physical keyed switch that gates remote changes, so a remote mode-change request '
        + 'against a device the site believes is keyed to local-only says something whichever way '
        + 'it went — rejected means somebody tried, accepted means the key is not where the site '
        + 'thinks — and that is worth more than either signal alone.',
    tools: [
      'Zeek',
      'Historian',
    ],
    dataSources: [
      'Zeek s7comm.log (function_name)',
      'Zeek cip.log from the ICSNPP ENIP parser (cip_service)',
      'historian trends',
      'engineering software logs',
      'site keyswitch policy',
    ],
    terrain: [
      'controllers',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h function_name < s7comm.log 2>/dev/null | grep -Ei \'plc (stop|control)\'',
      'zeek-cut ts id.orig_h id.resp_h cip_service cip_service_code < cip.log 2>/dev/null | grep -Ei \'start|stop|reset|0x4\'',
    ],
    steps: [
      step('Establish which of the protocols in use expose mode-change as something the parser '
        + 'names. S7comm does outright — PLC Stop and PLC Control (start) are distinct functions in '
        + 's7comm.log. CIP has Start, Stop and Reset as common services, but a Logix run/program '
        + 'transition may reach the wire as a vendor-specific service the parser shows only as a '
        + 'code, so read the unnamed service codes to your controllers rather than trusting a grep. '
        + 'Modbus has no mode concept at all. State which controllers this task can and cannot '
        + 'cover before drawing any conclusion.',
        'Zeek s7comm.log · Zeek cip.log', 'A stated coverage answer per controller: named on the wire, visible only as a code, or not visible.'),
      step('Where mode-change is visible, list every event with source and time, and cross-check '
        + 'each against the historian for the corresponding gap or frozen trend and against the '
        + 'engineering software\'s own log on the workstation that would have sent it. A mode change '
        + 'with no process discontinuity is itself worth explaining — it means either the trend is '
        + 'not from that controller or the controller did not actually change mode.',
        'Zeek · Historian · engineering software logs', 'Every mode-change event matched to a trend effect and an engineering-log entry, or filed.'),
      step('Check each event against the site\'s keyswitch policy per controller. Where the policy '
        + 'says a controller\'s key sits in RUN or PROG, a remote request should have been rejected '
        + '— so a rejected one is somebody trying, and an accepted one is a policy violation and a '
        + 'key that is not where the site believes it is. Either is a finding independent of what '
        + 'happened next.',
        'Psephos · Evidence', 'Each mode-change event classified against the keyswitch policy for its controller: permitted, attempted against policy, or succeeded against policy.'),
    ],
    evidenceExpected:
      'A mode-change event list per controller (or a stated coverage gap), each matched against '
        + 'the historian, the engineering software log and the site keyswitch policy.',
    doNext:
      'A mode change that succeeded against the keyswitch policy, or one immediately preceding '
        + 'an unattributed program download, is safety-relevant and goes up immediately.',
  },

  T0871: {
    intent:
      'Where native-API abuse (T0834) is ordinary host tradecraft that happens to run on OT, '
        + 'this is the OT-specific version one layer up: the control-software-to-hardware API — '
        + 'OPC, or a vendor SDK like the Step7 communication library Stuxnet replaced — exists '
        + 'purpose-built to let software command hardware, so a call into it is indistinguishable '
        + 'from the SCADA doing its job. The write still reaches the wire, but it leaves the OPC '
        + 'server or engineering host as its source, and that host is already on the '
        + 'baselined-master list — protocol attribution stops at a box that is meant to be there, '
        + 'and the question moves onto the host: which process made the call. Hunting it means '
        + 'treating the client population of that API as a controlled list, the same discipline '
        + 'already used for control-protocol masters, one level up the stack.',
    tools: [
      'OPC server logs',
      'host logs',
      'Zeek',
    ],
    dataSources: [
      'OPC (or equivalent) server session and audit logs',
      'Sysmon image-load and process-creation logs on the API server host',
      'Zeek conn.log',
      'engineering software client inventory',
      'historian trends',
    ],
    terrain: [
      'OPC servers and gateways',
      'HMIs',
      'historians and brokers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | awk \'$3==4840\' | sort -u',
    ],
    steps: [
      step('Enumerate the API client population against the short list of software meant to be '
        + 'there: SCADA, historian, one or two engineering tools. OPC UA makes this cheap — '
        + 'CreateSession carries the client\'s ApplicationName and ApplicationUri and the server '
        + 'logs them — and where the server logs nothing, the 4840 speakers in conn.log give the '
        + 'same population from the wire.',
        'OPC server logs · Zeek', 'A named client list, each entry matched to expected software or a name to go and ask about.'),
      step('Read the client identification, not just the count. A library default — python-opcua '
        + 'announces itself as "Pure Python Client" — or an ApplicationUri that is not a vendor\'s '
        + 'is a script talking to the process, and that is the signature to chase.',
        'OPC server logs', 'Every client name is a product\'s, or the exception filed.'),
      step('Where the API server is a general-purpose host, hunt the call itself: image-load and '
        + 'process-creation logs for anything other than the SCADA or engineering binary loading '
        + 'the vendor SDK or the OPC client library. This is MITRE\'s Process source, and for OPC DA '
        + '— whose DCOM sessions rarely log per client — it is the only evidence there is.',
        'Sysmon · host logs', 'The SDK library loaded only by the binaries whose job it is, or a process named.'),
      step('Where the server logs writes by client, attribute each one to an expected client. '
        + 'Because the wire shows the write as coming from the API host itself, cross-check the '
        + 'historian for the resulting value change rather than waiting on network evidence to name '
        + 'the caller.',
        'OPC server logs · Historian', 'Each write attributed to an expected client, and each suspect write matched to a value change or its absence noted.'),
    ],
    evidenceExpected:
      'An API client inventory against the expected list, the set of processes loading the SDK '
        + 'on each API host, and each unexplained write matched to a historian value change.',
    doNext:
      'A confirmed write via this path is manipulation of control by another entry point and is '
        + 'escalated exactly as an unattributed protocol write is under T1692.001 — to the lead and '
        + 'the process owner, with nothing reverted.',
  },

  T0884: {
    intent:
      'This bank already argues, under T0866, that unglamorous OT-adjacent Linux boxes get used '
        + 'as staging points because nobody watches them. This is the specific traffic shape that '
        + 'confirms it: a device that is neither the ultimate source nor destination of a flow, '
        + 'sitting between two others and relaying, which shows up as paired connections with '
        + 'correlated timing and volume rather than as any single anomalous session. Neither leg is '
        + 'suspicious on its own, which is why per-session alerting never sees it and a hunter '
        + 'reading conn.log by host can.',
    tools: [
      'Zeek',
      'Arkime',
    ],
    dataSources: [
      'Zeek conn.log',
      'Arkime session graph',
    ],
    terrain: [
      'camera and physical-security segments',
      'the IT/OT boundary',
      'appliances',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h < conn.log | awk \'{o[$1]=1; r[$2]=1} END {for (h in o) if (h in r) print h}\' | sort',
      'zeek-cut ts id.orig_h id.resp_h duration orig_bytes resp_bytes < conn.log | awk -v h=CANDIDATE \'$2==h || $3==h\' | sort -k1 -n | head -60',
    ],
    steps: [
      step('List every host that is both a responder and an originator in the window, then read each '
        + 'one\'s flows side by side by time. The relay signature is an inbound session to the host '
        + 'and an outbound session from it that start within seconds of each other, run for about '
        + 'the same duration, and carry about the same bytes in mirror image — the inbound '
        + 'orig_bytes reappearing as the outbound orig_bytes. Both legs have to be in the capture '
        + 'for this to work; a tap that sees only the boundary shows the far leg and never the near '
        + 'one, and T0842 says whether that is your situation.',
        'Zeek · Arkime', 'A named list of dual-role hosts, each with its paired flows attached or a stated reason no pairing was found.'),
      step('Separate the hosts that are dual-role by design from the ones that are not. A historian, '
        + 'an OPC server, a jump host or a DMZ replication server legitimately takes traffic in '
        + 'from one side and sends it out the other, and they will dominate the list; strike them '
        + 'only once their pairs match their stated function. What is left — a camera, a badge '
        + 'controller, a printer relaying anything — is the population this technique lives in, '
        + 'because a device nobody expects to route traffic is where relaying goes unnoticed '
        + 'longest.',
        'Zeek · Psephos · Network Map', 'Each dual-role host classed as expected-by-function or unexplained, with the unexplained ones named.'),
      step('Where a relay is confirmed, trace both ends. The near end says what is compromised '
        + 'locally; the far end may be the actual command infrastructure worth reporting upstream, '
        + 'and if the far end is outside the estate the relay is also a boundary crossing that the '
        + 'firewall log should be able to account for.',
        'Arkime · Zeek · firewall log', 'Near and far end named for every confirmed relay, with the far end\'s address filed and its boundary crossing matched to a firewall entry or flagged as unmatched.'),
    ],
    evidenceExpected:
      'A dual-role host list for the window, each host classed by function, and near and far '
        + 'end filed for any confirmed relay.',
    doNext:
      'A confirmed relay through an OT-adjacent appliance is reported as a boundary-crossing '
        + 'incident regardless of payload content — the existence of the relay is itself the '
        + 'finding.',
  },

  T0817: {
    intent:
      'OT devices do not browse the web; the population that can fall to a drive-by is the '
        + 'small set of engineering and vendor-support workstations that do, which turns an '
        + 'unbounded enterprise problem into a short list you can watch closely. That list is also '
        + 'homogeneous — it visits the same handful of vendor portals — and a watering-hole '
        + 'adversary compromises exactly those sites because the audience is the target, so a '
        + 'vendor domain is a destination to account for, not an explanation. Everywhere else this '
        + 'is a normal browser-exploitation hunt inherited from the IT side; the value here is '
        + 'entirely in knowing which hosts qualify and which log actually saw them browse.',
    tools: [
      'Zeek',
      'proxy/web logs',
      'host logs',
    ],
    dataSources: [
      'Zeek ssl.log',
      'Zeek http.log',
      'proxy or web gateway logs',
      'DNS query logs',
      'engineering workstation process logs',
    ],
    terrain: [
      'engineering workstations',
      'vendor support workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h server_name < ssl.log | sort -u | head -60',
      'zeek-cut ts id.orig_h host uri status_code < http.log | awk \'$5>=300&&$5<400\' | sort -u | head -40',
    ],
    steps: [
      step('Identify the actual population of OT-adjacent hosts that browse the general internet at '
        + 'all — usually engineering workstations checking vendor portals or forums — and say which '
        + 'log records that browsing. If the segment has no proxy and no sensor sees its egress, '
        + 'the hunt cannot be run there, and that gap is filed under T0842 rather than reported as '
        + 'a negative.',
        'Psephos · Network Map', 'A short, named list of browsing-capable hosts, each with the log that actually sees it browse — proxy, Zeek ssl.log, or nothing.'),
      step('Read that list\'s destinations from whatever saw them. Most browsing is TLS, so the '
        + 'record is the SNI name in ssl.log or the proxy log, not http.log. Look for two shapes: a '
        + 'domain that only one host on the estate has ever resolved, and a redirect chain — a 3xx '
        + 'in http.log, or a burst of first-seen SNI names within seconds of one page visit — that '
        + 'lands somewhere unrelated to the site the user chose.',
        'Zeek · proxy logs', 'Every first-seen destination attributed to a person\'s purpose or filed; a vendor portal that redirected elsewhere is a finding, not a closed question.'),
      step('On any host that visited something unexplained, look for a process spawned by the '
        + 'browser rather than by the user — chrome.exe, msedge.exe or firefox.exe as the parent of '
        + 'cmd, powershell, rundll32, mshta, wscript or regsvr32 in Sysmon event 1 or Windows 4688. '
        + 'That is the exploitation, not the visit, and it is the only part of this technique that '
        + 'leaves host evidence.',
        'host logs', 'Every child process of a browser on the population attributed to a user action or a named updater, or one filed with its parent, command line and time.'),
    ],
    evidenceExpected:
      'A named browsing-capable population with the log that records each one, their first-seen '
        + 'destinations and any redirect chain explained or filed, and every browser-spawned '
        + 'process attributed.',
    doNext:
      'A confirmed browser-spawned process on an engineering workstation is treated as a '
        + 'foothold with a path to OT until the boundary check in T0886 rules it out; it goes to '
        + 'the lead before the queue is finished.',
  },

  T0819: {
    intent:
      'Exploiting a public-facing application is, mechanically, the same hunt whatever industry '
        + 'runs the server; what makes it an ICS concern is whether the exploited application is '
        + 'one that talks to the process — a historian\'s web portal or a vendor\'s remote-HMI '
        + 'interface rather than an ordinary marketing site. That distinction decides whether this '
        + 'is somebody else\'s incident or the start of yours, so it is made first and the rest of '
        + 'the task is spent only on the servers it names.',
    tools: [
      'Zeek',
      'web/app server logs',
      'host logs',
    ],
    dataSources: [
      'web server access and error logs',
      'Zeek http.log',
      'Sysmon or auditd process creation',
      'application inventory',
    ],
    terrain: [
      'internet-facing servers with a path to OT',
      'historians',
      'vendor remote-HMI gateways',
    ],
    commands: [
      'zeek-cut id.orig_h uri status_code < http.log | awk \'$3>=500||$3==404\' | sort | uniq -c | sort -rn | head -30',
      'ausearch -sc execve -ui www-data -i 2>/dev/null | tail -60',
    ],
    steps: [
      step('Confirm which internet-facing applications actually have any path onward to a control '
        + 'segment before spending time on the rest. Most public-facing exploitation in an '
        + 'OT-adjacent estate never gets near the process, and a historian portal or a vendor\'s '
        + 'remote-HMI gateway is a different asset from a corporate website even when the same team '
        + 'runs both.',
        'Psephos · Network Map · application inventory', 'A named, short list of applications worth this attention, each with the segment it reaches written next to it.'),
      step('For those, look for the exploitation signature in the request log itself — one source '
        + 'producing repeated 4xx or 5xx against the same endpoint, paths that do not belong to the '
        + 'application, and a 200 returned to a path that should have been a 404. The last is the '
        + 'one that matters: a probe that failed is noise, a probe that succeeded is the finding.',
        'Zeek http.log · app logs', 'Every repeated-error source and every 200 on an unexpected path attributed to a scanner or a user, or one request to chase.'),
      step('Check whether the web server process spawned anything after an unusual request. A web '
        + 'shell or command injection appears as a shell or interpreter whose parent is the server '
        + 'worker, and it shows up in process-creation logging long before it shows up on the '
        + 'network.',
        'Sysmon EID 1 · auditd execve · journald', 'No child of the web server process other than its own workers, or one spawned shell filed with the request that preceded it.'),
    ],
    evidenceExpected:
      'The short list of applications with a path to OT, and for each a request-log check and a '
        + 'process-creation check with their results stated.',
    doNext:
      'Confirmed exploitation on an application with a path to OT is handed straight to the '
        + 'boundary-crossing check rather than worked to conclusion here: the question is no longer '
        + 'whether the server was exploited but whether it spoke to a control segment afterwards.',
  },

  T0822: {
    intent:
      'This is not the boundary-crossing traffic itself — that belongs to the Remote Services '
        + 'entry — it is the front door that traffic later uses: the VPN, Citrix or jump-host '
        + 'account that let somebody in through a door built for exactly that. A vendor account '
        + 'nobody has used in eight months, or a login at an hour nobody on that account has ever '
        + 'worked, is visible in the authentication log long before anything it does shows up on '
        + 'the wire — and a gateway the site does not know it has is a bigger finding than any '
        + 'account on the one it does.',
    tools: [
      'VPN/jump host auth logs',
      'Zeek',
    ],
    dataSources: [
      'remote-access gateway authentication logs',
      'VPN session logs',
      'account roster for remote access',
      'Zeek conn.log',
    ],
    terrain: [
      'remote-access gateways',
      'jump hosts',
    ],
    commands: [
      'grep -Ei \'accepted|success\' vpn-auth.log | awk \'{print $1,$2,$NF}\' | sort -u | tail -60',
      'grep -Ei \'accepted|success\' vpn-auth.log | awk \'{print $NF}\' | sort | uniq -c | sort -rn',
    ],
    steps: [
      step('Inventory the doors before the keys: every gateway that terminates external sessions '
        + 'into the estate, including the vendor-installed box and the cellular modem in a '
        + 'controller cabinet that the site\'s diagram omits. A gateway the site did not list is a '
        + 'finding before any account on it is examined.',
        'Psephos · Network Map · Zeek conn.log', 'A named list of gateways, each one the site already knew about, or one to explain.'),
      step('Build the roster of accounts actually entitled to external remote access and diff it '
        + 'against who has logged in. An account that exists but has never authenticated is dormant '
        + 'and worth watching; one that authenticates and is not on the roster is a finding on its '
        + 'own.',
        'Psephos · Characterization', 'A reconciled roster, with exceptions named.'),
      step('Look at login time and duration against each account\'s normal pattern. A vendor account '
        + 'that only ever logs in during a scheduled maintenance window logging in outside one is '
        + 'the clearest signal this technique gives you.',
        'auth logs · maintenance records', 'Every session outside an account\'s usual hours matched to a scheduled change, or filed.'),
      step('Where geolocation or source history is available, flag a session from a new location for '
        + 'an account that has only ever connected from one or two. This is one of the few places '
        + 'in OT hunting where that kind of signal is cheap.',
        'auth logs', 'Source consistent with history, or a session to chase.'),
    ],
    evidenceExpected:
      'A gateway inventory the site agrees with, a reconciled remote-access roster, and every '
        + 'active account\'s session pattern reviewed against its own history.',
    doNext:
      'An unexplained session on a dormant or vendor account, or a gateway nobody listed, goes '
        + 'to the lead immediately; disabling the account or the box is the site\'s decision, not '
        + 'the hunter\'s.',
  },

  T0843: {
    intent:
      'A program download is a legitimate engineering act with a fixed, small cast: the '
        + 'engineering workstation and software licensed to programme a given controller, used by '
        + 'the person who normally does it. Treat every download as an event to attribute — who '
        + 'initiated it, from what host, using what software — before asking what the program '
        + 'contains. The sub-techniques differ mainly in whether the controller has to stop to take '
        + 'the transfer, and that one fact is both the process risk and the trace the transfer '
        + 'leaves behind.',
    tools: [
      'Zeek',
      'Arkime',
      'host logs',
    ],
    dataSources: [
      'Zeek conn.log',
      'engineering software logs on the workstation (TIA Portal, Studio 5000 / FactoryTalk Diagnostics, EcoStruxure Control Expert)',
      'Windows event logs on the engineering workstation',
      'change/maintenance records',
    ],
    terrain: [
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes < conn.log | awk \'$4==102||$4==44818||$4==1962||$4==20547||$4==9600\' | sort -k6 -rn | head -40',
      'zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes < conn.log | awk \'$5>5 && $6>10000\' | sort -k6 -rn | head -30',
    ],
    steps: [
      step('List every session from an engineering workstation to a controller\'s programming port, '
        + 'then sort by bytes sent. The ports are vendor-specific — 102 for S7, 44818 for '
        + 'EtherNet/IP, 1962 for PCWorx, 20547 for ProConOS, 9600 for FINS; extend with the site\'s '
        + 'own — and on Schneider gear programming rides on 502 as UMAS, so there the byte sort is '
        + 'what separates it from polling. A full download is long and large and visible even where '
        + 'the payload is opaque; an online edit can be a few kilobytes, which is why the list is '
        + 'built from the port first and the size second.',
        'Zeek · Arkime', 'A dated list of every programming-port session in the window, by source, controller and bytes sent.'),
      step('Attribute each one to a person and a change record. A transfer inside a recorded change '
        + 'window, from the workstation that normally programs that controller, by the engineer '
        + 'named on the change, needs nothing further; anything else does — including a legitimate '
        + 'host at a time nobody booked.',
        'host logs · change records', 'Every download matched to an authorised change, or filed.'),
      step('Classify each session by what the controller did while it ran. A gap in the HMI\'s '
        + 'polling of that controller, or a mode change to STOP or PROGRAM alongside the session, '
        + 'means a full download and a process that was not being controlled for that interval; '
        + 'polling uninterrupted means an online edit or an append. Route to the matching '
        + 'sub-technique with that observation attached.',
        'Zeek · Analyst', 'Each session classified as full download, online edit or append, with the polling gap or its absence cited.'),
    ],
    evidenceExpected:
      'Every programming-port session in the window, attributed to a person, a host and a '
        + 'change record, and classified by whether the controller stopped.',
    doNext:
      'An unattributed download goes to the lead now, not at the end of the queue. What the '
        + 'program now does is T0889\'s question and is not answered by pulling the program off the '
        + 'controller to compare — that is a session to a running controller on a hunter\'s '
        + 'judgement.',
  },

  'T0843.001': {
    intent:
      'A full download is the least stealthy of the three variants because it typically has to '
        + 'stop the controller first: the scan halts, outputs drop to their configured safe state, '
        + 'and anyone watching the historian sees the trend stall — a stop that has to be explained '
        + 'by a name and a maintenance ticket. That operational cost is exactly why this variant is '
        + 'the easiest of the three to catch after the fact: the hunt is a correlation of three '
        + 'records — the transfer, the stall and the ticket — rather than a search of one.',
    tools: [
      'Zeek',
      'Historian',
      'HMI event journal',
    ],
    dataSources: [
      'Zeek conn.log',
      'historian trends and tag quality',
      'HMI/SCADA event journal (controller mode changes, comms-loss alarms)',
      'change/maintenance records',
    ],
    terrain: [
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes < conn.log | awk \'$4==102||$4==502||$4==44818\' | awk \'$5>5 && $6>10000\' | sort -k1 -n',
      'zeek-cut ts id.resp_h conn_state < conn.log | awk \'$3=="S0"||$3=="REJ"\' | sort -k1 -n',
    ],
    steps: [
      step('Look for a stall in the historian that lines up with a long transfer to the controller: '
        + 'values frozen flat, tags going bad-quality, or a short run of failed polls when the '
        + 'controller restarts. A stopped controller usually still answers reads, so the signature '
        + 'is frozen data and a restart blip, not silence.',
        'Historian · Zeek', 'Every stall matched to a transfer and every transfer to a stall, with the unmatched ones listed.'),
      step('Pull the controller\'s mode changes from wherever the site records them. The HMI or SCADA '
        + 'event journal usually logs RUN-to-PROGRAM and the comms-loss alarm, and the engineering '
        + 'software logs the download itself. Modbus carries no run state, so this is the direct '
        + 'evidence and the stall is only the proxy.',
        'HMI event journal · host logs', 'A mode change or comms-loss alarm bracketing each transfer, or a stated absence of that logging.'),
      step('Check the stall\'s length and time against the change record. A scheduled full reload '
        + 'during a maintenance window looks identical on the wire to an unscheduled one; the '
        + 'record is what tells them apart.',
        'change records', 'Every stall accounted for by an authorised change, or filed.'),
    ],
    evidenceExpected:
      'Every stop-and-reload event in the window, correlated with a transfer, a mode-change or '
        + 'comms-loss record, and a change record.',
    doNext:
      'An unexplained stop-and-reload is treated as a program integrity incident and handed to '
        + 'the process owner before anything else is worked. Nobody restores the previous program '
        + 'on their own judgement.',
  },

  'T0843.002': {
    intent:
      'Online edit is the variant that should worry a hunter most, precisely because it was '
        + 'designed not to worry the operator: the controller keeps scanning, the process keeps '
        + 'running, and nothing on the historian trend announces that the logic underneath just '
        + 'changed. With no stop-and-restart to bracket it, the wire shows only an engineering '
        + 'session on the programming port that looks like any other, so this one lives or dies on '
        + 'whether the site can tell you who held the programming session and when.',
    tools: [
      'Zeek',
      'host logs',
    ],
    dataSources: [
      'engineering software session logs',
      'Zeek conn.log',
      'change/maintenance records',
      'program hash records',
    ],
    terrain: [
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes < conn.log | awk \'$4==102||$4==44818\' | sort -k1 -n | head -40',
    ],
    steps: [
      step('Because there is no stop-and-restart to spot, the engineering software\'s own session or '
        + 'audit log is the primary evidence that a live edit happened at all. Where that log does '
        + 'not exist or is not kept, say so and file it — the gap is the honest finding, and it is '
        + 'the thing the site can fix.',
        'host logs', 'A dated list of online-edit sessions from the engineering software\'s log, or a filed statement that no such log exists.'),
      step('Read every session from an engineering workstation to a controller\'s programming port — '
        + '102 for S7, 44818 for EtherNet/IP — and check whether polling of that controller '
        + 'continued through it. A transfer with no gap around it is the shape of an online edit, '
        + 'and it is smaller and shorter than a full download, so the parent task\'s volume filter '
        + 'will miss it.',
        'Zeek · Arkime', 'Each programming-port session timed, with a stated answer on whether polling continued through it.'),
      step('Cross-check each session against the change record with more suspicion than for a full '
        + 'download: this variant needs no outage window, so there is no planned event for the '
        + 'record to have anticipated, and an entry that exists only because someone wrote it up '
        + 'afterwards is worth a question.',
        'change records', 'Every session matched to an authorised change, or filed.'),
      step('Where program hashes are already on file, treat any hash change with no matching stop or '
        + 'full download as evidence the logic was changed live — this variant, or an append that '
        + 'needed no stop. Which of the two matters less than that no session accounts for it; '
        + 'where no hash baseline exists, the T0889 task is where one gets recorded.',
        'Psephos · Evidence', 'Every hash change reconciled against a session record, or filed as unattributed.'),
    ],
    evidenceExpected:
      'Every online-edit session — from the engineering log and from the wire — matched to an '
        + 'authorised change, and any hash change with no stop behind it flagged as a live edit.',
    doNext:
      'An unattributed online edit is the highest-priority of the three variants to escalate, '
        + 'because it is the one that will not have announced itself any other way. It is not '
        + 'verified by uploading the program to compare — that is a write to a running controller — '
        + 'it goes to the process owner with the session and hash evidence already in hand.',
  },

  'T0843.003': {
    intent:
      'An append sits between the other two variants and borrows a signature from each: it may '
        + 'or may not stop the controller, so the historian gap is unreliable, and it goes through '
        + 'the same programming session as an online edit, so the session log is the better lead. '
        + 'What is its own is that it adds logic beside what is already running rather than '
        + 'changing it — the process trends exactly as before, the transfer is a few blocks rather '
        + 'than a project, and the one thing that has definitely changed is the size of the program '
        + 'on the controller. Hunt it with the siblings\' signatures plus that one, rather than '
        + 'inventing a separate method.',
    tools: [
      'Zeek',
      'host logs',
      'Historian',
    ],
    dataSources: [
      'engineering software session logs',
      'engineering project files',
      'controller program signature or checksum where already reported',
      'asset inventory',
      'Zeek conn.log',
      'historian trend gaps',
    ],
    terrain: [
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes < conn.log | awk \'$4==102||$4==44818||$4==1502\' | sort -u | head -40',
    ],
    steps: [
      step('Run both signatures the other two variants use — a stop-and-restart gap on the '
        + 'historian, and the engineering software\'s session log — since an append may show either '
        + 'or neither depending on how the controller handles it. Do not lean on the gap: a '
        + 'controller that accepts appends while running leaves no outage to find, and the session '
        + 'log is then the only host-side evidence.',
        'Historian · host logs', 'Each gap and each programming session in the window matched to a change record, or listed for attribution.'),
      step('Compare the program against baseline using what is already recorded — the project file '
        + 'on the engineering workstation, and any checksum or program signature the controller '
        + 'reports into the engineering software or the asset inventory. Do not pull the program '
        + 'off the controller to hash it; that is a touch on a running device. Any of the three '
        + 'variants changes the artefact, so a mismatch says the logic changed, not which way.',
        'host logs · Psephos · Evidence', 'Recorded hash or signature matches baseline, or a dated change to attribute; where no baseline exists, one filed now.'),
      step('Check whether the program got bigger. An append adds blocks or routines without '
        + 'replacing anything, so block count and used program memory rise where the site records '
        + 'them, and the transfer itself carries a few blocks rather than a whole project — small '
        + 'enough that the parent task\'s byte threshold can miss it. List sessions to the '
        + 'programming port by source, not by volume.',
        'engineering software · asset inventory · Zeek conn.log', 'Block count and program size unchanged since baseline, or growth matched to a change record; every session to a programming port listed regardless of size.'),
    ],
    evidenceExpected:
      'Program hash or signature compared to baseline from existing records, block count and '
        + 'program size checked for growth, with any gap or session evidence attached.',
    doNext:
      'An unattributed hash change or program growth is filed and escalated the same way as the '
        + 'other two variants; which mechanism was used matters less than that logic changed '
        + 'without a name attached. Nothing is uploaded from the controller to confirm it.',
  },

  T0847: {
    intent:
      'Nothing at the IT/OT boundary sees a USB stick; it is carried in a pocket, not routed. '
        + 'That means the network sensor this bank leans on everywhere else is structurally blind '
        + 'to the arrival, and the hunt has to move onto the host — the record it keeps of media '
        + 'plugged in, and whatever procedural log the site keeps of media brought on-site. The '
        + 'media itself is gone by the time you look, so what remains is the host\'s memory of it '
        + 'and what the host did afterwards; the wire only sees the second act.',
    tools: [
      'host logs',
      'Zeek',
    ],
    dataSources: [
      'Windows setupapi.dev.log and the USBSTOR registry key',
      'Windows Partition/Diagnostic event 1006',
      'Linux kernel journal',
      'media control log or sign-in sheet',
      'file creation timestamps on removable-media-facing hosts',
      'Zeek conn.log',
    ],
    terrain: [
      'engineering workstations',
      'HMIs',
    ],
    commands: [
      'findstr /i /c:"USBSTOR" /c:"Section start" C:\\Windows\\INF\\setupapi.dev.log',
      'reg query HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /s | findstr /i "USBSTOR FriendlyName"',
      'wevtutil qe Microsoft-Windows-Partition/Diagnostic /q:"*[System[(EventID=1006)]]" /c:60 /f:text /rd:true',
      'journalctl -b all -k --since "30 days ago" | grep -iE \'usb-storage|new usb device\' | tail -60',
    ],
    steps: [
      step('Pull removable-media history from every host that has a USB port and a reason to use one '
        + '— mainly engineering workstations and HMIs — and say what kind of history each OS '
        + 'actually gives you. Windows keeps every device ever inserted, by serial, in USBSTOR and '
        + 'setupapi.dev.log, but those record the first insertion only; per-insertion events need '
        + 'Partition/Diagnostic 1006 (Windows 10 and later) or a driver-frameworks log that is off '
        + 'by default. A Linux journal that is not persistent holds the current boot and nothing '
        + 'else. Where the OS does not log this, say so; it is a visibility gap, not a clean '
        + 'result.',
        'host logs', 'A per-host list of devices and insertion times, with a stated answer to whether it is every insertion or only first ones, or a stated gap.'),
      step('Cross-reference each device and insertion against the site\'s media control log, where '
        + 'one exists. A device or a time with no matching entry is the finding; one that matches '
        + 'an integrator\'s visit or a logged transfer is a non-event. Where there is no media log '
        + 'at all, that absence is filed as a finding of its own, because nothing else can turn a '
        + 'mount into a decision.',
        'Psephos · Comms', 'Every insertion matched to a logged, authorised use, or a list of the ones that are not.'),
      step('Where an insertion is unexplained, read file creation and modification times on that '
        + 'host in the hour after it, together with any scheduled task, service or run key created '
        + 'in the same window. The media is long gone; what it left behind is the only artefact '
        + 'left to find.',
        'host logs', 'New files or persistence after the insertion identified or ruled out.'),
      step('Check what that host did on the wire after the insertion. The arrival is invisible to '
        + 'the sensor, but a workstation that begins new sessions to controllers, to other hosts, '
        + 'or outbound in the hours that follow is the network\'s only view of this technique, and '
        + 'it is the one that says whether the media mattered.',
        'Zeek', 'No new destinations for that host after the insertion, or a session list to chase.'),
    ],
    evidenceExpected:
      'A per-host insertion history, honest about what each OS records, reconciled against the '
        + 'media control log, with any unexplained insertion\'s host and wire aftermath checked.',
    doNext:
      'An unexplained insertion with new files or new sessions behind it goes to the lead '
        + 'immediately; there is no network evidence of the arrival to fall back on, so the host '
        + 'evidence has to be preserved before anything else touches that machine.',
  },

  T0848: {
    intent:
      'The population of things allowed to speak a control protocol on a given segment is fixed '
        + 'and small by design, which makes a rogue master the rare ICS technique that is anomalous '
        + 'by construction rather than by behaviour — on IT, a new speaker on the network is '
        + 'Tuesday; here it is a finding before you know a single thing about what it sent. The '
        + 'hunt is mostly a diff, not an investigation. The one rogue the diff cannot see is the '
        + 'one that borrows the legitimate master\'s address, and that case has its own tell: two '
        + 'hardware addresses behind one IP, or the real master\'s metronome breaking up while the '
        + 'impostor talks.',
    tools: [
      'Zeek',
      'Arkime',
    ],
    dataSources: [
      'Zeek modbus.log',
      'Zeek dnp3.log',
      'Zeek conn.log',
      'master/outstation baseline roster',
      'outstation and HMI application logs',
    ],
    terrain: [
      'controllers',
      'HMIs',
      'control segments',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h < modbus.log | sort -u',
      'zeek-cut id.orig_h id.resp_h < dnp3.log | sort -u',
      'zeek-cut id.orig_h orig_l2_addr < conn.log 2>/dev/null | sort -u',
      'zeek-cut id.orig_h id.resp_h func < modbus.log | sort | uniq -c | sort -rn',
    ],
    steps: [
      step('Diff the current set of addresses issuing master-role traffic — the TCP originator in '
        + 'modbus.log and dnp3.log — against the baselined roster. The population cannot grow '
        + 'without somebody installing equipment, so any addition is explainable by a name, not by '
        + 'statistics. State which segments the tap covers alongside the diff: a rogue plugged in '
        + 'behind an uplink-only tap never appears in it.',
        'Zeek', 'An empty diff, or an address to go and ask about, with the tap coverage it was drawn under.'),
      step('Check for an impostor behind a known address, which the diff cannot show. Look for a '
        + 'second layer-2 address behind the master\'s IP — Arkime\'s mac.src, or conn.log\'s '
        + 'orig_l2_addr where MAC logging is loaded — and for the legitimate master\'s poll cadence '
        + 'breaking up or its requests going unanswered while the suspect traffic runs; many '
        + 'outstations hold one master connection at a time, so the impostor\'s session surfaces as '
        + 'the real one failing. Where the outstation or HMI logs connections, it names the master '
        + 'it saw.',
        'Arkime · Zeek conn.log · application logs', 'One hardware address per master IP and an unbroken poll cadence, or a second address or a timestamped gap to explain.'),
      step('Where a master appears that should not, profile its function codes per outstation '
        + 'against the legitimate master\'s. The comparison tells you the consequence, not the '
        + 'legitimacy: a rogue master exists to send well-formed, ordinary commands, so a mix that '
        + 'matches the real one clears nothing. It tells you whether the source read, wrote, or '
        + 'issued diagnostics, and to which controllers.',
        'Zeek', 'A per-source function-code profile, with every write or diagnostic code from the new source listed by outstation.'),
      step('Ask about scheduled commissioning or integrator work before escalating further. This '
        + 'population changes only when somebody plans it, so the answer is usually a phone call '
        + 'away.',
        'Psephos · Comms', 'A recorded answer from a named person.'),
    ],
    evidenceExpected:
      'The current master roster per protocol, diffed against baseline under a stated tap '
        + 'coverage, with every addition explained or filed and every known master IP shown to have '
        + 'one hardware address behind it.',
    doNext:
      'An unexplained master is escalated immediately rather than queued: its existence is most '
        + 'of the finding, and what it wrote is the rest. A second hardware address behind the '
        + 'legitimate master\'s IP is an incident, not a hunt task.',
  },

  T0859: {
    intent:
      'A stolen or legitimately-issued credential used by the wrong person looks, to a system '
        + 'that only checks passwords, exactly like the right person — which is why this is hunted '
        + 'by usage pattern rather than by the credential\'s own strength, and why it sits apart '
        + 'from T1694.001 and T1694.002. Those ask whether the password is weak; this asks whether '
        + 'whoever is using it is who they claim to be. OT adds a wrinkle: HMIs commonly run one '
        + 'shared operator login, so for those accounts the question cannot be who and becomes '
        + 'which host and which shift.',
    tools: [
      'host logs',
      'Zeek',
    ],
    dataSources: [
      'HMI and engineering workstation auth logs (Windows Security 4624/4648, auth.log, journald)',
      'engineering software access logs',
      'account roster and role assignments',
      'Zeek conn.log',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
      'controllers',
    ],
    commands: [
      'grep -Ei "accepted|session opened" /var/log/auth.log | tail -60',
      'zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | awk \'$4==22||$4==3389||$4==5900\' | sort -u',
    ],
    steps: [
      step('Build the account-to-role mapping first — who should be able to use engineering '
        + 'software, who should be able to log into an HMI, which accounts belong to a vendor — '
        + 'from the roster rather than from behaviour, since behaviour is what you are about to '
        + 'check it against. Mark the shared accounts: a single operator login on an HMI is normal, '
        + 'and for those the check moves from who to which host.',
        'Psephos · Characterization', 'A named role per account, with shared and vendor accounts marked as such.'),
      step('Look for an account authenticating to a host or a piece of engineering software outside '
        + 'its role, or from a host it has never used before. On Windows that is Security 4624 with '
        + 'the logon type and source workstation; on Linux it is the Accepted line in auth.log with '
        + 'its source address. A network engineer\'s account opening a programming session is the '
        + 'shape worth chasing.',
        'host logs · engineering software access logs', 'Every session matched to the account\'s role and a known source host, or filed.'),
      step('Check named accounts for concurrent sessions from two hosts at once, and any account '
        + 'dormant for months — vendor support logins are the usual case — suddenly active. Skip '
        + 'the concurrency check on shared operator accounts, where two consoles at once is '
        + 'Tuesday; for those, compare the source hosts in conn.log against the consoles that '
        + 'account is expected from.',
        'host logs · Zeek', 'Each concurrent or dormant-reactivated session attributed to a person and a reason, or filed.'),
    ],
    evidenceExpected:
      'An account-to-role mapping with every session checked against it for role and source '
        + 'host, and any concurrent or dormant-reactivated use attributed or filed.',
    doNext:
      'A confirmed out-of-role or concurrent session is treated as a compromised account, not a '
        + 'policy violation, and goes to the lead before the account is used again.',
  },

  T0860: {
    intent:
      'Wireless is the one route into a control segment that never crosses the IT/OT boundary, '
        + 'so the chokepoint the rest of this bank leans on is blind to it by construction. A '
        + 'segment tap still sees the consequence — a wireless client that gets in is just a new '
        + 'speaker on the wire — but it cannot see the compromise itself, which happens at the '
        + 'association layer and is recorded only in the wireless controller\'s own log, if '
        + 'anywhere. And on older estates the wireless that matters is not WiFi at all: serial '
        + 'radio telemetry to outstations, the medium of the Maroochy intrusion, keeps no record of '
        + 'who keyed the radio, and the honest hunt for it is on the wired side of the radio '
        + 'master, said plainly.',
    tools: [
      'wireless controller/WIDS logs',
      'gateway logs',
      'Zeek',
    ],
    dataSources: [
      'wireless controller association and deauthentication logs',
      'WIDS or rogue-AP reports',
      'known-device roster',
      'cellular gateway WAN session and login logs',
      'Zeek conn.log',
    ],
    terrain: [
      'wireless access points',
      'cellular/remote gateways',
      'radio telemetry masters',
    ],
    commands: [
      'grep -Ei "associat|deauth|rogue" wireless-controller.log | tail -60',
      'zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | awk \'$3==502||$3==20000\' | sort -u',
    ],
    steps: [
      step('Diff the current associated-client list against the known-device roster by MAC and '
        + 'identity, not by count. A segment serving a handful of handhelds should have a short, '
        + 'stable list — and because the PSK is usually shared by every handheld and never rotated, '
        + 'a stranger who has it looks like a member on every field except its hardware address.',
        'wireless controller logs · known-device roster', 'An empty diff, or a MAC to go and ask about.'),
      step('List deauthentication bursts and rogue-AP reports from the controller\'s own WIDS. A '
        + 'burst of deauths against a legitimate client is the precondition for both handshake '
        + 'capture and an evil twin, and the controller is the only sensor placed to see it — the '
        + 'wired side sees nothing until the attacker is already on it.',
        'wireless controller logs · WIDS', 'Each burst attributed to roaming or a power cycle, or filed with time and target.'),
      step('For a cellular or remote-site gateway, list the WAN-side peers from the gateway\'s own '
        + 'log and configuration, not by connecting to it. There should be exactly one — the VPN '
        + 'concentrator or SCADA master it tunnels to — so every login, session or tunnel from '
        + 'anywhere else is a finding, and a management interface reachable on the WAN side is one '
        + 'before anybody has used it.',
        'gateway logs', 'A WAN peer list of length one, or the extra peers named.'),
      step('Where the link is serial radio telemetry, say plainly that the compromise cannot be '
        + 'hunted: a keyed radio leaves no association record on most of these links. Hunt what can '
        + 'be seen instead — the traffic the radio master puts on the wire, diffed against the '
        + 'outstations it is supposed to relay for — and file the blind spot as a finding in its '
        + 'own right.',
        'Zeek · Psephos · Evidence', 'A stated per-link answer on whether the wireless layer is observable, and a wired-side speaker diff for each link that is not.'),
    ],
    evidenceExpected:
      'A reconciled client roster per wireless segment, a WAN peer list per gateway, every '
        + 'deauth burst attributed or filed, and an explicit statement of which links have no '
        + 'wireless-layer evidence at all.',
    doNext:
      'An unidentified client on an OT-adjacent wireless segment is escalated the same way an '
        + 'unexplained wired speaker would be — the medium is different, the population is just as '
        + 'fixed. Nobody rotates the PSK mid-hunt: every handheld on site shares it, and changing '
        + 'it is an outage.',
  },

  T0862: {
    intent:
      'This is the technique in the bank least suited to a live wire hunt, because the '
        + 'compromise happens before the product arrives and the wire only ever shows its '
        + 'consequences, if it shows anything at all. The honest version of this task is closer to '
        + 'an audit than a hunt: what came in, from whom, and can any of it be checked against a '
        + 'vendor-published value, rather than a search for traffic that betrays it. What the wire '
        + 'can add is the consequence: a newly arrived product reaching somewhere its vendor never '
        + 'documented.',
    tools: [
      'host logs',
      'vendor advisories',
      'Zeek',
    ],
    dataSources: [
      'software and firmware inventory with source and version',
      'vendor-published hashes or advisories',
      'procurement/change records',
      'Zeek conn.log',
      'Zeek ssl.log',
    ],
    terrain: [
      'engineering workstations',
      'controllers',
      'appliances',
    ],
    commands: [
      'find /opt /srv /var/lib -type f \\( -name \'*.msi\' -o -name \'*.exe\' -o -name \'*.bin\' -o -name \'*.hex\' \\) -exec sha256sum {} + 2>/dev/null | head -40',
      'zeek-cut id.orig_h id.resp_h server_name < ssl.log | sort -u | head -40',
    ],
    steps: [
      step('Build an inventory of software and firmware installed in the OT estate with its source '
        + 'and the date it arrived, from records that already exist rather than by re-deriving it '
        + 'from hosts.',
        'Psephos · Characterization', 'A dated inventory with a named source per item.'),
      step('Where a vendor publishes hashes or advisories for a given release, check the retained '
        + 'installer or firmware image against them — not the installed tree, which the vendor '
        + 'never published a value for. This will usually turn up nothing; that is the expected and '
        + 'useful result, not a wasted step.',
        'sha256sum · vendor advisories', 'Each checkable item matched or flagged.'),
      step('For each item that arrived in the window, check where it has talked to since. A '
        + 'trojanised installer or engineering tool announces itself by calling out on first run, '
        + 'and the destination is the one thing the wire can show about a compromise that happened '
        + 'before delivery.',
        'Zeek conn.log · Zeek ssl.log', 'Every destination reached by a newly installed item is one the vendor documents, or a filed finding.'),
      step('For anything that cannot be checked against a published value, record that plainly as a '
        + 'limit of the audit rather than implying it was cleared. A site cannot act on a check '
        + 'that was never actually possible.',
        'Psephos · Evidence', 'An explicit list of what could and could not be verified.'),
    ],
    evidenceExpected:
      'A dated software/firmware inventory, checked where a vendor value exists, an egress '
        + 'check for each item that arrived in the window, and an explicit statement of what could '
        + 'not be verified.',
    doNext:
      'A confirmed mismatch against a vendor-published value is a vendor-notification event as '
        + 'much as a hunt finding, and goes to the lead rather than being resolved by replacing the '
        + 'artefact locally.',
  },

  T0864: {
    intent:
      'A contractor\'s laptop arrives inside the control network by being carried through a '
        + 'door, and no boundary sensor sees that. But unlike a USB stick it does not stay quiet '
        + 'once it is in: on a segment whose population is fixed by construction it is a new '
        + 'speaker the moment it links up, and a laptop built for an office is noisy in ways '
        + 'nothing that lives on the segment ever is — it asks for a DHCP lease, resolves names it '
        + 'cannot resolve, and tries to reach update and telemetry services that do not exist '
        + 'there. That makes this the easy case of the fixed-population argument, not the exception '
        + 'to it. The site\'s own record of who connected what and when is the baseline; the capture '
        + 'and the engineering hosts are what you reconcile it against. The one case that is '
        + 'genuinely off the wire — a lead straight from the laptop into a hardware controller — is '
        + 'named below rather than argued away.',
    tools: [
      'Zeek',
      'Arkime',
      'host logs',
    ],
    dataSources: [
      'transient-asset check-in/check-out log',
      'Zeek known_hosts.log and dhcp.log',
      'Zeek conn.log and dns.log for the connected window',
      'engineering workstation event logs (logon, process creation, device install)',
    ],
    terrain: [
      'control segments',
      'engineering workstations',
      'controllers',
    ],
    commands: [
      'zeek-cut -d ts host < known_hosts.log | tail -40',
      'zeek-cut -d ts mac host_name assigned_addr msg_types < dhcp.log | sort -u | head -40',
      'zeek-cut id.orig_h id.resp_p proto < conn.log | awk \'$2==5355||$2==5353||$2==137||$2==1900\' | sort | uniq -c | sort -rn | head -20',
    ],
    steps: [
      step('Get the site\'s record of what was connected, by whom, when, and to which port or device, '
        + 'before looking at anything technical. This population is small and known by name, and '
        + 'the record is the baseline everything else is diffed against — without it, every new '
        + 'host you find is merely unexplained rather than unauthorised.',
        'Psephos · Comms', 'A dated list of transient connections, each with a named owner and a stated connection point.'),
      step('List every host the sensor saw for the first time in the window and every DHCP request '
        + 'it recorded, and match each against the record. A laptop set to DHCP broadcasts whether '
        + 'or not a server answers, and dhcp.log keeps the MAC and the hostname it offered — a name '
        + 'like a person\'s initials on a segment of controllers is the whole finding. Check first '
        + 'that the sensor has the control segment declared as local, or known_hosts.log will be '
        + 'empty for a reason that has nothing to do with the estate.',
        'Zeek', 'Every first-seen host and DHCP request in the window matched to an entry in the record, or listed as unrecorded.'),
      step('For each connection, recorded or not, pull what it did while it was up: which '
        + 'controllers and workstations it reached, on which engineering ports, and what IT chatter '
        + 'it produced — LLMNR, mDNS, NetBIOS, DNS for domains the segment cannot reach. The '
        + 'chatter proves the device class; the engineering sessions say what it touched, which is '
        + 'what the site will ask.',
        'Zeek · Arkime', 'A per-asset list of controllers and hosts reached, with the engineering-protocol sessions separated from the noise.'),
      step('Where the asset was plugged into a workstation rather than a switch port, or used one to '
        + 'reach the controllers, read that host\'s logs for the window: device-install events for '
        + 'the lead or adapter, logons, and process creation for engineering software the '
        + 'workstation does not normally run.',
        'host logs', 'The host-side footprint of each such connection, or a stated absence with the logs that were checked.'),
      step('Where the record says the laptop went straight into a hardware controller on a '
        + 'point-to-point lead, say so and stop. The tap did not see it and the controller logged '
        + 'nothing, so there is no evidence to reconcile; the honest output is that the site\'s '
        + 'record is the only control on that connection, filed as a finding about the record '
        + 'rather than the asset.',
        'Psephos · Evidence', 'A filed statement per direct-to-controller connection that it cannot be verified passively and why.'),
    ],
    evidenceExpected:
      'The transient-connection record reconciled against first-seen hosts and DHCP requests, a '
        + 'per-asset list of what each reached while connected, and a filed statement for every '
        + 'connection that bypassed the tap.',
    doNext:
      'An unrecorded connection — a first-seen host or a DHCP request with no entry in the '
        + 'check-in log — is a process failure and a security finding together, and both go to the '
        + 'lead with the list of what it reached.',
  },

  T0865: {
    intent:
      'An OT network that is genuinely airgapped from email cannot be spearphished directly, '
        + 'which means this technique\'s real target is a specific, findable subset of IT users: the '
        + 'engineering and vendor-support staff whose compromise would actually matter to the '
        + 'process. Everything else about hunting it is an ordinary mail-security problem already '
        + 'covered on the IT side; the OT-specific work is naming that subset before the mainstream '
        + 'hunt even starts, and putting any engineering workstation that has a mail client at the '
        + 'top of it.',
    tools: [
      'mail security logs',
      'host logs',
    ],
    dataSources: [
      'mail gateway/attachment logs',
      'list of personnel with OT access or engineering-software licenses',
      'host process logs for the named subset',
    ],
    terrain: [
      'engineering workstations',
      'vendor support workstations',
    ],
    commands: [],
    steps: [
      step('Name the subset of mail recipients whose compromise reaches OT — holders of '
        + 'engineering-software licenses, vendor support contacts, anyone with credentials good on '
        + 'a control segment. This list is short and it is the whole point of doing this here '
        + 'rather than leaving it to the enterprise hunt.',
        'Psephos · Characterization', 'A named, short recipient list, each name tied to the OT access that put them on it.'),
      step('For that subset only, pull attachment delivery and open events and read them for the '
        + 'lure that works on engineering staff: a sender resembling the vendor, carrying what a '
        + 'vendor would send — a project file, a firmware bundle, a manual — or active content '
        + '(macro-enabled Office, ISO, LNK, HTA) under that cover. The enterprise hunt has no '
        + 'reason to rank a vendor-shaped sender above any other; here it is the shape that '
        + 'matters.',
        'mail gateway logs', 'Every attachment to the subset either matched to an expected sender and a business reason, or listed by recipient for the host check.'),
      step('Where an attachment was opened, check that user\'s host for what the mail client or '
        + 'document viewer spawned in the following minutes. Outlook, Word, Excel and the PDF '
        + 'reader do not launch cmd, powershell, wscript, mshta, rundll32 or regsvr32 in ordinary '
        + 'use, and a child like that is the finding regardless of what the attachment claimed to '
        + 'be.',
        'host logs', 'Every child of the mail client or viewer named and attributed to normal application behaviour, or a specific interpreter child to escalate.'),
    ],
    evidenceExpected:
      'The named OT-relevant recipient subset, their attachment history reviewed against '
        + 'expected senders, and any resulting host process named and attributed.',
    doNext:
      'A confirmed open by anyone in the named subset is escalated as a potential path to OT '
        + 'and handed to the IT/OT boundary check, not closed out as an ordinary phishing case.',
  },

  T0867: {
    intent:
      'This is not the programming-specific transfer covered under Program Download — it is the '
        + 'more mundane movement of adversary tooling, installers or scripts between hosts inside '
        + 'the control network once a foothold exists, over an admin share, a file share or a '
        + 'remote-desktop session. Because so few legitimate file transfers happen between OT hosts '
        + 'at all, and the ones that do are a short list of engineering pushes, almost any transfer '
        + 'outside that list is worth a look — the residual is small enough to read one by one.',
    tools: [
      'Zeek',
      'host logs',
    ],
    dataSources: [
      'Zeek smb_files.log',
      'Zeek files.log',
      'host file-creation logs (Sysmon event 11, auditd)',
      'engineering software deployment logs',
    ],
    terrain: [
      'controllers',
      'HMIs',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h action path name size < smb_files.log | grep -E \'WRITE|OPEN\' | sort -u | head -40',
      'zeek-cut ts id.orig_h id.resp_h mime_type filename total_bytes < files.log | grep -Ei \'x-dosexec|x-executable|x-msi|x-sh|x-python|powershell|x-bat\' | head -30',
      'zeek-cut ts id.orig_h id.resp_h total_bytes mime_type < files.log | sort -k4 -rn | head -30',
    ],
    steps: [
      step('Establish which host-to-host transfers are part of a known engineering workflow — '
        + 'pushing a project file from a workstation to an HMI, for instance — so that the residual '
        + 'is small.',
        'Psephos · Characterization', 'A named list of expected transfer pairs.'),
      step('Read the residual: SMB writes and file transfers between OT hosts outside that list, '
        + 'particularly executables, installers or scripts landing on a host that does not run '
        + 'engineering software. Attribute each to a source host, an account and a file name. Where '
        + 'SMB3 is encrypted or the copy went over RDP drive redirection the wire shows you a '
        + 'session and a byte count and nothing else — there you only have the host-side arrival.',
        'Zeek smb_files.log · Zeek files.log · host logs', 'Every transfer outside the list attributed to a source, an account and a file name, or filed as unexplained.'),
      step('Where removable media might be the actual path rather than the network, check host-side '
        + 'file-creation timestamps for a matching arrival even if no network transfer explains it '
        + '— this technique and Replication Through Removable Media share a blind spot.',
        'host logs', 'File arrival explained by a network transfer, a media event, or filed.'),
    ],
    evidenceExpected:
      'Every host-to-host transfer outside the known engineering workflow list identified and '
        + 'either explained or filed.',
    doNext:
      'An unexplained binary or script arriving on a controller-adjacent host is treated as '
        + 'active tooling staging and escalated immediately, not queued behind lower-priority '
        + 'tasks.',
  },

  T0883: {
    intent:
      'This is deliberately not the boundary or the VPN — it is what happens when a device gets '
        + 'an internet path that skips the intended door entirely: a dual-homed engineering laptop '
        + 'with a hotel WiFi connection left live, a vendor\'s remote-monitoring box with its own '
        + 'cellular modem, an HMI somebody exposed for convenience during commissioning and never '
        + 'revisited. The hunt has to look for internet reachability that has no route through '
        + 'anything this bank already watches, and it has to be honest that the worst of these '
        + 'paths never touch the tapped wire at all.',
    tools: [
      'Zeek',
      'firewall/border logs',
      'device inventory',
      'host logs',
    ],
    dataSources: [
      'boundary and border firewall logs',
      'device network-interface inventory',
      'Zeek conn.log from a sensor inside the control segment',
      'device logon records — HMI, RDP/VNC, web console',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
      'controllers',
      'remote/outstation gateways',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | awk \'$1 ~ /^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\./ && $2 !~ /^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\./\' | sort -u | head -40',
      'zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | awk \'$1 !~ /^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\./ && $2 ~ /^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\./\' | sort -u | head -40',
    ],
    steps: [
      step('Inventory every device in or adjacent to OT with more than one network interface, or '
        + 'with any cellular, satellite or dial-up capability, regardless of whether it is '
        + 'currently in use. A path that exists but is unused today is still the finding, and for a '
        + 'device with its own modem this inventory is most of the evidence you will ever get: '
        + 'traffic on that modem never crosses the tapped wire.',
        'Psephos · Characterization', 'A named list of multi-homed or independently-connected devices, each with the second path stated.'),
      step('From a sensor inside the control segment, list every session between a site address and '
        + 'a public one, in both directions, and look for each in the border firewall log. A '
        + 'session the segment sensor saw and the border did not took a path this bank does not '
        + 'otherwise watch. Inbound from a public source matters more than outbound: an exposed '
        + 'device is found by what arrives at it.',
        'Zeek · firewall logs', 'Every public-address session matched to a border record, or named as boundary-skipping.'),
      step('Read the logon records already kept on each device from the inventory — HMI application '
        + 'logs, RDP and VNC session logs, the web console\'s access log — for sessions whose source '
        + 'is not a site address or a known gateway. This is the only place a session over a '
        + 'device\'s own modem leaves a trace, and it is where an exposed HMI shows its visitors.',
        'host logs · HMI application logs', 'Every logon source is a site address or a known gateway, or a logon to explain.'),
      step('Treat a confirmed boundary-skipping path as a standing exposure independent of whether '
        + 'anything has used it maliciously yet — the finding is the exposure, not an intrusion, '
        + 'and unplugging it is the site\'s decision.',
        'Psephos · Evidence', 'A filed record per device with an unmonitored internet path.'),
    ],
    evidenceExpected:
      'A named list of internet-capable devices with a second path, every public-address '
        + 'session from inside the segment matched to the border or named, and a filed record for '
        + 'every path that skips the monitored boundary.',
    doNext:
      'A live session on a boundary-skipping path, or a logon on an exposed device from an '
        + 'address nobody can name, is escalated immediately as an active, unmonitored point of '
        + 'entry; a dormant but exposed path still goes to the site as a standing finding.',
  },

  T1694: {
    intent:
      'Default and hardcoded credentials, covered under .001 and .002, are each about where a '
        + 'specific credential came from; this entry is about the carelessness around credentials '
        + 'generally — sent in cleartext over a protocol that never encrypted them, left in a '
        + 'script or a project file, or shared across a whole device class as one group password. '
        + 'None of it requires stealing anything, because it was never protected in the first '
        + 'place, and the passive sensor a hunter relies on is usually logging the same credentials '
        + 'an adversary on the wire would read.',
    tools: [
      'Zeek',
      'host logs',
    ],
    dataSources: [
      'Zeek conn.log',
      'Zeek ftp.log, http.log and snmp.log',
      'engineering project files and scripts',
      'shared/group account roster',
    ],
    terrain: [
      'HMIs',
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | awk \'$3==21||$3==23||$3==80||$3==161\' | sort -u | head -40',
      'zeek-cut id.orig_h id.resp_h user < ftp.log | sort -u | head -40',
      'zeek-cut id.orig_h id.resp_h username < http.log | awk \'$3!="-"\' | sort -u | head -40',
      'zeek-cut id.orig_h id.resp_h version community < snmp.log | sort | uniq -c | sort -rn | head -40',
      'grep -rEil \'password|passwd|pwd=\' --include=\'*.ini\' --include=\'*.xml\' --include=\'*.cfg\' --include=\'*.bat\' --include=\'*.ps1\' --include=\'*.py\' --include=\'*.csv\' . 2>/dev/null | head -40',
    ],
    steps: [
      step('Identify the protocols in use that carry authentication in the clear — Telnet, plain '
        + 'FTP, HTTP Basic, SNMP v1/v2c — from the sensor\'s own logs rather than by port alone: '
        + 'ftp.log records the user, http.log the Basic-auth username, snmp.log the community '
        + 'string, and each is a credential the sensor already holds. Telnet has no Zeek log, so it '
        + 'is a port-23 session and the credential inside it is readable only in the pcap. The '
        + 'username is enough for the finding; do not reconfigure the sensor to capture passwords.',
        'Zeek', 'A list of client, server and protocol for every session that carried a credential in the clear, or an empty list.'),
      step('Search the engineering project files, scripts and configuration exports already '
        + 'collected for embedded credentials — OPC and historian connection strings, HMI '
        + 'tag-server logons, backup scripts. They get pasted in at commissioning and are rarely '
        + 'removed, and a workstation image taken for another task already holds them.',
        'engineering workstation files · grep', 'A list of files carrying an embedded credential, each named with what it authenticates to, or an empty list.'),
      step('Check whether any account is shared across a whole device class rather than issued per '
        + 'person or per device — one operator logon for every HMI, one community string for every '
        + 'switch. A group password compromised anywhere is compromised everywhere it is used, and '
        + 'a successful logon with it attributes to a class of devices, never to a person.',
        'Psephos · Characterization · host logs', 'Account-to-scope mapping stated for each credential found, with every shared account named.'),
    ],
    evidenceExpected:
      'Cleartext-auth sessions listed by client, server and protocol; embedded credentials '
        + 'listed by file and what they authenticate to; and shared-account scope stated for each.',
    doNext:
      'Findings here are filed for the site to remediate on its own schedule; a credential '
        + 'found in a script or a capture is never tested against a live device to confirm it '
        + 'works, and one the sensor logged is cited by username, never copied into the record.',
  },

  'T1694.002': {
    intent:
      'A default credential can, in principle, be changed at commissioning even if nobody '
        + 'bothered; a hardcoded one is compiled into the firmware or software and the site has no '
        + 'way to change it at all short of a vendor patch, which makes this the worse case of the '
        + 'two and the one where a hunt finding cannot become a fix on any timeline the hunter '
        + 'controls. The useful output here is naming which devices carry this exposure so their '
        + 'authentication activity gets watched harder, not looking for a way to close it.',
    tools: [
      'vendor advisories',
      'Zeek',
      'Arkime',
      'host logs',
    ],
    dataSources: [
      'vendor and CISA ICS advisories naming affected products',
      'device/firmware inventory',
      'Zeek conn.log',
      'Zeek http.log',
      'authentication logs on affected devices where any exist',
    ],
    terrain: [
      'controllers',
      'appliances',
      'HMIs',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p service < conn.log | awk \'$5=="ssh"||$5=="telnet"||$5=="ftp"||$5=="http"\' | sort -u',
      'zeek-cut ts id.orig_h id.resp_h username < http.log | awk \'$4!="-"\' | sort -u',
    ],
    steps: [
      step('Cross-reference the device and firmware inventory against vendor and CISA ICS advisories '
        + 'that name a hardcoded credential (CWE-798) for that product line, and note for each the '
        + 'account name and the service it opens — telnet, SSH, FTP, a web console. This is a '
        + 'lookup against a fixed inventory, not a search, and the service is what you will hunt '
        + 'on.',
        'vendor advisories · Psephos · Characterization', 'Every affected device in the estate named, with the account and the service the credential opens.'),
      step('For each named device, pull every session to that service from conn.log and attribute it '
        + 'to the station whose job it is to manage the device. Where the protocol is cleartext — '
        + 'telnet, FTP, HTTP basic auth — the account name is on the wire and a match against the '
        + 'advisory\'s account is a direct hit; where it is SSH or TLS you get the session and not '
        + 'the account, and a session from anywhere but the engineering station is the finding. '
        + 'Treat a successful authentication as unattributable by the credential alone — it proves '
        + 'nothing about who used it.',
        'Zeek · host logs', 'Every session to the affected service attributed to a known management source, or filed.'),
      step('File the exposure per device even where no logging exists to check further. "This device '
        + 'cannot prove who is using it" is the finding, and it is actionable as a monitoring or '
        + 'network-isolation decision even though the credential itself cannot be changed.',
        'Psephos · Evidence', 'A filed exposure record per affected device.'),
    ],
    evidenceExpected:
      'Every device matching a hardcoded-credential advisory named with the service it opens, '
        + 'every session to that service attributed or filed, and the exposure recorded per device.',
    doNext:
      'A hardcoded-credential exposure goes to the site as a standing risk needing compensating '
        + 'controls; nobody attempts to patch or reflash the device during the hunt.',
  },

  T0806: {
    intent:
      'Brute Force I/O is a real activity, not an assessed outcome: writing the same coil or '
        + 'register over and over — cycling a valve, chattering a relay — until the process '
        + 'destabilises or a safety trip results, or sweeping writes across a range of addresses to '
        + 'hit something without knowing which point matters. It is distinguished from Modify '
        + 'Parameter (T0836) by repetition rather than a single changed value, and the tell is '
        + 'shape rather than content: a legitimate master does not write one point tens of times in '
        + 'a minute, nor walk a run of addresses it never touches in normal polling, and a capture '
        + 'of either is most of the finding.',
    tools: [
      'Zeek modbus.log',
      'Zeek dnp3.log',
      'Arkime',
    ],
    dataSources: [
      'Zeek modbus.log',
      'Zeek dnp3.log',
      'historian trends',
    ],
    terrain: [
      'controllers',
      'HMIs',
    ],
    commands: [
      'zeek-cut -d ts id.orig_h id.resp_h func < modbus.log | grep -Ei \'write\' | awk \'{print substr($1,1,16), $2, $3}\' | sort | uniq -c | sort -rn | head -40',
      'zeek-cut -d ts id.orig_h id.resp_h register < modbus_register_change.log | awk \'{print substr($1,1,16), $2, $3, $4}\' | sort -u | uniq -c | sort -rn | head -40  # register detail needs track-memmap.zeek',
    ],
    steps: [
      step('Count writes per address per controller in one-minute buckets rather than across the '
        + 'whole capture. A repetitive write is only visible against a tight window; a day-long '
        + 'average buries it in ordinary polling. The address column comes from the ICSNPP Modbus '
        + 'parser\'s detailed log — base Zeek\'s modbus.log carries only the function code, and if '
        + 'that is all you have, writes per source per minute by function code is the coarser '
        + 'fallback.',
        'Zeek modbus.log', 'A per-minute, per-address write count per controller, with the top buckets either explained or flagged.'),
      step('Count distinct addresses written per source per minute as well. MITRE names the other '
        + 'shape — walking a range of points to hit something without knowing which one matters — '
        + 'and it never trips a per-address rate check, because each address is written once or '
        + 'twice.',
        'Zeek modbus.log', 'A per-minute count of distinct addresses written per source, with any source writing addresses the baselined master never writes flagged.'),
      step('Cross-check a flagged window against the historian trend for the affected point. '
        + 'Chattering an output usually shows as a rapid oscillation in the corresponding process '
        + 'value, which is independent confirmation the writes had a physical effect rather than '
        + 'being a logging artefact. A flat trend does not clear it: scan rates and deadband '
        + 'compression can smooth out a chatter faster than the historian\'s scan, so the wire '
        + 'evidence stands on its own.',
        'Historian', 'Trend oscillates in step with the writes, or it does not and the historian\'s scan rate and compression for that point are recorded alongside the negative.'),
      step('Attribute the source the same way as any other control write: known master, in shift, '
        + 'expected — or filed. A high write rate from the normal master running a genuinely fast '
        + 'supervisory loop is not this technique; the rate has to sit outside the process\'s own '
        + 'control behaviour, and the site engineer can state what that is for a given point.',
        'Zeek · Historian · Site engineer', 'Source attributed, and legitimate fast control loops ruled out by asking rather than assumed.'),
    ],
    evidenceExpected:
      'A flagged high-frequency or range-sweep write pattern per source, corroborated by the '
        + 'historian trend where its scan rate allows, with the source attributed or filed.',
    doNext:
      'A confirmed unattributed pattern on a safety-relevant point is escalated immediately; '
        + 'otherwise it is filed and the site is asked what physically happened to the actuator. A '
        + 'trend that chatters while the capture stays quiet is not a negative: a controller '
        + 'toggling its own outputs from modified logic never puts a write on the wire, and that '
        + 'question belongs to T0889.',
  },

  T0813: {
    intent:
      'Denial of Control is an outcome you assert once you know why an operator lost the '
        + 'ability to command a controller, not a signature you match on the wire. The '
        + 'distinguishing fact is temporariness — command is expected to work again once whatever '
        + 'severed it clears — which is what separates this from Loss of Control (T0827), where '
        + 'command does not return on its own. It also has two shapes that leave different '
        + 'evidence: the channel to the controller drops, which the wire shows, or the HMI itself '
        + 'stops taking input while its polls carry on, which the wire does not. Hunt the '
        + 'interruption in both places, not a label for it.',
    tools: [
      'Zeek modbus.log',
      'Arkime',
      'host logs',
    ],
    dataSources: [
      'Zeek conn.log',
      'Zeek modbus.log',
      'HMI alarm history',
      'HMI session logs',
    ],
    terrain: [
      'controllers',
      'HMIs',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h < modbus.log | sort -k2,3 -k1,1n | awk \'{k=$2" "$3; if (k in last && $1-last[k]>60) print k, last[k], $1, $1-last[k]; last[k]=$1}\'',
      'zeek-cut ts id.orig_h id.resp_h id.resp_p conn_state < conn.log | awk \'$4==502 && ($5=="S0"||$5=="REJ")\' | head -40',
      'zeek-cut ts id.orig_h id.resp_h func < modbus.log | grep DIAGNOSTICS | head -40',
    ],
    steps: [
      step('Find the gap in the polling record before looking for a cause: a stretch where one '
        + 'master\'s requests to one controller stop, per pair, longer than the poll interval. Then '
        + 'read the conn.log states across it, because they say which side went quiet — S0 means '
        + 'the controller answered nothing at all, REJ means its TCP stack was up and refused, and '
        + 'no attempts at all means the master stopped asking. That gap is the observable; the '
        + 'technique name is your reading of it.',
        'Zeek modbus.log · Zeek conn.log', 'A bounded start and end per master–controller pair with the side that went quiet named, or no gap longer than the poll interval.'),
      step('Read the HMI\'s comms-loss alarms and its session log for the same window. The alarm '
        + 'history bounds the outage as the operator lived it; the session log says whether anyone '
        + 'was at the console. An operator-side outage with no gap on the wire is the second shape '
        + 'of this technique — a hung runtime, a locked screen, a session somebody else was driving '
        + '— and the polling record will look healthy throughout.',
        'HMI alarm history · HMI session logs', 'The operator-side window per HMI, stated as matching the wire gap or as a denial with no gap on the wire.'),
      step('Establish why the channel dropped by checking for the mechanisms that produce it. A '
        + 'DIAGNOSTICS function code (FC 08) to the controller just before the gap is the first '
        + 'thing to read — the two-byte sub-function after it is 0x0001 for Restart Communications '
        + 'Option, which is a channel reset dressed as a diagnostic and is the command-message '
        + 'technique (T1692.001) if it did not come from the baselined master. A flood is T0814\'s '
        + 'procedure, not this one: hand the window to it. A plain device fault with nothing on the '
        + 'wire beforehand is a fault until T0814\'s fault-versus-attack call says otherwise.',
        'Zeek modbus.log · Arkime', 'A named cause with its source, or an explicit statement that none was found.'),
    ],
    evidenceExpected:
      'An interruption window per controller bounded from the wire and from the HMI, with a '
        + 'candidate cause, sufficient to write "operators lost command of X between time A and '
        + 'time B, because of C, and it recovered on its own."',
    doNext:
      'If command did not resume once the apparent cause cleared, re-open this as Loss of '
        + 'Control (T0827) instead of closing it here. A Restart Communications Option from '
        + 'anything but the baselined master is an unattributed command message and goes to the '
        + 'lead under T1692.001.',
  },

  T0827: {
    intent:
      'Loss of Control is the same interruption as Denial of Control (T0813) carried past the '
        + 'point where it should have cleared: the disrupting cause is gone and operators still '
        + 'cannot issue commands, sometimes because the process has run away in the meantime. '
        + 'Establishing it means proving persistence, not finding a new signature — go back to the '
        + 'same gap and ask whether it ever closed. Two things make that harder than it sounds: a '
        + 'channel that is back up but answering every command with an exception looks recovered in '
        + 'a poll count, and the obvious way to settle the question — send a command and see — is '
        + 'the one thing a hunter must not do.',
    tools: [
      'Zeek modbus.log',
      'Historian',
    ],
    dataSources: [
      'Zeek modbus.log',
      'Zeek conn.log',
      'historian trends',
      'operator/shift logs',
      'alarm history',
    ],
    terrain: [
      'controllers',
      'HMIs',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h func exception < modbus.log | awk \'$5!="-"\' | sort -k2,3 -k1,1n | tail -40',
      'zeek-cut id.orig_h id.resp_h exception < modbus.log | awk \'$3!="-"\' | sort | uniq -c | sort -rn | head -20',
    ],
    steps: [
      step('Take the interruption window already established under T0813 and check whether command '
        + 'authority returned once its apparent cause ended. On the wire, returned means the '
        + 'baselined master\'s requests get ordinary responses again, not merely that traffic '
        + 'resumed: a controller that answers polls but returns SLAVE_DEVICE_BUSY or '
        + 'SLAVE_DEVICE_FAILURE to every write is up and still not under command, and a poll count '
        + 'alone will call that a recovery. If T0813 found the operator-side shape — polls healthy, '
        + 'HMI not taking input — the wire cannot answer this and the answer comes from the shift '
        + 'log instead.',
        'Zeek modbus.log · Zeek conn.log', 'A stated answer per controller: command resumed by a given time, or has not resumed, with the shape named — channel down, channel up but refusing, or operator-side.'),
      step('Check the historian trend across the same window for a runaway — a value moving '
        + 'unopposed in one direction with no operator or automatic correction visible. A value '
        + 'that overshoots and comes back is a loop still running; one that keeps going is a '
        + 'controller that is no longer executing, or executing something else. A runaway with no '
        + 'working command channel is the worst case of this technique and is safety-relevant on '
        + 'its own.',
        'Historian', 'Trend behaviour during the outage characterised as controlled, drifting, or runaway, per loop.'),
      step('Read the shift log and alarm history across the same window for what the operators did '
        + 'about it. A recorded switch to local or manual control at the panel, or a manual trip, '
        + 'is the human-side evidence that remote command never came back, and on the operator-side '
        + 'shape it is the only evidence there is. It also closes the window: when, and by what '
        + 'path, command was regained.',
        'operator/shift logs · alarm history', 'A dated record of when and how operators regained command — remote restored, local panel, or trip — or a statement that they have not.'),
    ],
    evidenceExpected:
      'A dated statement per controller of whether command authority has returned and by what '
        + 'path, with the trend behaviour during the gap characterised.',
    doNext:
      'A runaway with no restored command channel is escalated immediately, not queued; this is '
        + 'one of the few outcomes here where the assessment itself is time-critical. Whether '
        + 'command has returned is never settled by issuing one — a test write to a controller '
        + 'nobody can command is the incident, not the hunt.',
  },

  T0829: {
    intent:
      'Loss of View is Denial of View that did not clear on its own: the reporting channel '
        + 'stayed broken long enough, or broke in a way durable enough, that somebody had to go and '
        + 'touch equipment — restart a service, power-cycle a device, reseat a connection — before '
        + 'the operator could see the process again. The distinguishing fact is the intervention, '
        + 'not the length of the outage by the clock, and it is a fact you establish from records '
        + 'after the event rather than from the capture. There is no wire signature of this '
        + 'technique that T0815 does not already carry; what this task adds is the classification, '
        + 'and the classification changes the consequence.',
    tools: [
      'Zeek modbus.log',
      'host logs',
    ],
    dataSources: [
      'Zeek modbus.log',
      'HMI host logs',
      'maintenance/shift records',
    ],
    terrain: [
      'controllers',
      'HMIs',
    ],
    commands: [],
    steps: [
      step('Take the gap already bounded under T0815 and check the maintenance or shift record for '
        + 'what closed it. A ticket, a restart, a site visit closing the gap is the signature of '
        + 'this technique; a connection that resumed by itself is not, and goes back to T0815.',
        'Maintenance records · Psephos · Comms', 'A named hands-on action, by a named person, tied to the end of the gap — or a stated finding that no record accounts for it.'),
      step('Where the HMI itself was what got restarted, read its System event log for the restart '
        + 'rather than trusting the ticket time: 1074 gives the shutdown reason and the account '
        + 'that asked for it, 6006 and 6005 bracket the reboot, 6008 marks a crash rather than a '
        + 'chosen restart, and 7036 catches a service recovered without a reboot. View should '
        + 'return in the capture shortly after the intervention, not before it. If view came back '
        + 'before anyone touched anything, the record does not explain the recovery.',
        'host logs · Zeek modbus.log', 'The intervention precedes view restoration in the capture by an interval consistent with a restart, and the restart is attributed to a person.'),
    ],
    evidenceExpected:
      'A gap in the reporting channel closed by a documented hands-on action, with the record, '
        + 'the host log and the capture agreeing on the order of events.',
    doNext:
      'If no record explains how view returned, that absence is itself worth filing — either '
        + 'the record is missing or the recovery was not what it appears. Classifying the outcome '
        + 'says nothing about the cause: that goes back to whatever broke the channel — T1691.002, '
        + 'T0814, T0816 — and a loss of view during which the process kept running unwatched is '
        + 'escalated on the process, not the outage.',
  },

  T0826: {
    intent:
      'Loss of Availability is written at the level of the service the site delivers, not at '
        + 'the level of any one screen or command channel: it is the finding that essential '
        + 'components were disrupted enough to affect delivery of product or service, and it is '
        + 'usually the roll-up of several narrower outcomes — a denial of control, a denial of '
        + 'view, a downed historian — rather than a thing with its own signature. Name which '
        + 'components failed and how that maps to delivery before calling it this; without that '
        + 'mapping it is a list of outages, not a finding.',
    tools: [
      'Historian',
      'operator/shift logs',
    ],
    dataSources: [
      'historian trends',
      'operator/shift logs',
      'production or throughput records',
    ],
    terrain: [
      'controllers',
      'HMIs',
      'historians and brokers',
    ],
    commands: [],
    steps: [
      step('List the component-level outages already established elsewhere in the hunt — command '
        + 'gaps, view gaps, a historian outage — that fall inside the window under review, rather '
        + 'than looking for a new one.',
        'Psephos · Evidence', 'A consolidated list of component disruptions with their windows.'),
      step('Check throughput or production records across the same window for an actual drop in '
        + 'delivery. Availability is about the service, so a component outage that never touched '
        + 'output does not support this finding by itself.',
        'Historian · production records', 'A stated link, or absence of one, between the outage and delivery.'),
      step('Read the operator and shift logs for the recorded cause of each delivery drop. Most '
        + 'drops on a working site are a failed pump, a planned outage or a trip, and those are '
        + 'logged; this finding needs the drop to trace to the component outages already attributed '
        + 'to activity, not to an ordinary cause the shift wrote down.',
        'operator/shift logs · Psephos · Comms', 'Each delivery drop matched to a recorded ordinary cause, or left standing for the component-level findings to explain.'),
    ],
    evidenceExpected:
      'A named set of essential components disrupted, a stated effect (or lack of one) on '
        + 'delivery of product or service, and ordinary causes for the delivery drop ruled in or '
        + 'out from the shift record.',
    doNext:
      'Where delivery was affected, this becomes the headline finding for the incident report; '
        + 'the component-level outages become its supporting evidence rather than separate '
        + 'findings.',
  },

  T0828: {
    intent:
      'This is the event set already established under Loss of Availability (T0826) or a '
        + 'manipulation finding (T0831, T0836) read in a different currency: not "which components '
        + 'went down" or "what was changed" but "what did it cost" — downtime, scrapped product, '
        + 'contractual penalty. It covers integrity as well as availability, so product scrapped '
        + 'because of a bad setpoint counts with nothing ever offline. It belongs in a hunt report '
        + 'only as a figure attached to a technical finding already established elsewhere, and a '
        + 'hunter should not manufacture one without input from the people who own that number.',
    tools: [],
    dataSources: [
      'production/output records',
      'quality and scrap records',
      'maintenance and downtime logs',
    ],
    terrain: [],
    commands: [],
    steps: [
      step('Hand the disruption or manipulation window already established for T0826 or another '
        + 'technical finding to the process or business owner and ask what it cost in output, '
        + 'scrap, or penalty. This is not a number a hunter should estimate from logs alone.',
        'Process owner · Psephos · Comms', 'A recorded cost figure attributed to a named person, or a recorded statement from that person that none can be given yet and why.'),
      step('File the figure against the technical finding it belongs to rather than as a standalone '
        + 'entry, so a reader sees cause and cost together.',
        'Psephos · Evidence', 'The cost figure attached to its originating finding, not filed on its own.'),
    ],
    evidenceExpected:
      'A sourced cost figure tied to a specific technical disruption or manipulation, not a '
        + 'standalone estimate.',
    doNext:
      'Nothing further from the hunt side; this figure feeds the business-impact section of the '
        + 'report and does not change the technical queue.',
  },

  T0837: {
    intent:
      'Protection here means the equipment-protection layer — relays, interlocks, trip logic '
        + 'designed to contain a fault before it becomes damage — and Loss of Protection is the '
        + 'finding that this layer has been disabled, bypassed or knocked offline, not that it has '
        + 'fired. It sits one step upstream of Damage to Property (T0879) and is a different system '
        + 'from the one behind Loss of Safety (T0880), which guards people and the environment '
        + 'rather than equipment; conflating the two misstates who is actually at risk. It is an '
        + 'outcome, not an activity, so nothing on the wire is labelled loss of protection. It is '
        + 'assessed from three things that are visible — a settings divergence, a bypass write, a '
        + 'protective device that stops answering — and every one of them is read from what has '
        + 'already been collected, because connecting to a relay to check its settings is itself a '
        + 'change to a live protective device.',
    tools: [
      'Zeek conn.log',
      'Zeek modbus.log',
      'Zeek dnp3.log',
      'alarm history',
    ],
    dataSources: [
      'relay settings archive on the engineering workstation',
      'relay event and sequence-of-events records',
      'Zeek conn.log',
      'Zeek modbus.log',
      'Zeek dnp3.log',
      'alarm history',
      'maintenance records',
    ],
    terrain: [
      'protective relays and interlocks',
      'controllers',
      'engineering workstations',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | awk \'$4==20000||$4==102||$4==2404||$4==50000\' | sort -u | head -40',
      'zeek-cut id.orig_h id.resp_h func < modbus.log | grep -Ei \'write.*coil\' | sort | uniq -c | sort -rn | head -40',
    ],
    steps: [
      step('Identify which protective functions exist on the process in scope — overcurrent, '
        + 'over-pressure, interlock logic — and compare their enable/bypass state and thresholds '
        + 'against the engineering record, using the settings file the engineering workstation '
        + 'already holds and the events the relay has already reported. Never a fresh read from the '
        + 'device: that is the same approach as Modify Parameter (T0836), and the same rule.',
        'Engineering record · relay settings archive · event records', 'Each protective function confirmed enabled and at its designed threshold, or a divergence filed with the archived file\'s timestamp.'),
      step('Look for protective devices going quiet. A relay that stops answering its master\'s '
        + 'polls, or a burst of traffic to its management port just before it does, is how '
        + 'Industroyer took SIPROTEC relays offline, and it shows in conn.log and the SCADA '
        + 'comms-fail alarms without decoding the protocol. Relays speak DNP3, IEC 61850 or IEC 104 '
        + 'rather than Modbus, and 61850 and 104 need an add-on parser — say so if you only have '
        + 'conn.log.',
        'Zeek conn.log · Zeek dnp3.log · alarm history', 'Every gap in polling to a protective device matched to a maintenance record or a comms-fail alarm somebody acted on, or filed.'),
      step('Read the writes to controllers carrying interlock logic for bypass or force bits. A '
        + 'bypass is a single coil, so it is a one-line write in modbus.log rather than a trend, '
        + 'and it is the same address every time; a point forced through engineering software goes '
        + 'over the programming protocol instead and leaves its trace in the workstation log, not '
        + 'on the Modbus wire.',
        'Zeek modbus.log · controller I/O map · engineering workstation logs', 'Every write to a bypass or force address attributed to a logged operator action, or filed.'),
      step('Check alarm history for the protective function\'s own alarms being shelved, suppressed '
        + 'or acknowledged with no corresponding operator action. A disabled protection layer stays '
        + 'quiet, and the suppression is often the only record that it was disabled.',
        'Alarm history · HMI logs', 'Every shelved or suppressed protection alarm matched to a named operator and a reason, or filed.'),
    ],
    evidenceExpected:
      'A per-function statement of whether the protective layer was enabled, set correctly and '
        + 'answering through the window in question, with each divergence, polling gap and '
        + 'suppressed alarm accounted for or filed.',
    doNext:
      'A disabled, bypassed or unresponsive protective function is escalated immediately — it '
        + 'is a standing exposure even if no fault has yet occurred to test it. Nobody re-enables '
        + 'it or reconnects to the relay on a hunter\'s judgement; that is the process owner\'s call.',
  },

  T0880: {
    intent:
      'Loss of Safety is the safety instrumented system failing to do the one thing it exists '
        + 'for — emergency shutdown, fire and gas, high-high trips — when a dangerous condition is '
        + 'already underway. It is graver than Loss of Protection (T0837) because its failure is '
        + 'measured in people and the environment rather than in equipment, and the two should not '
        + 'be written up as interchangeable even though they are built from the same kind of parts. '
        + 'It is also an outcome, not an activity: absent a demand on the function, nothing on the '
        + 'wire says safety has been lost. What can be hunted is the precursors — a bypass nobody '
        + 'authorised, a safety controller left in PROGRAM, a logic change reaching it from '
        + 'anything but the safety engineering station — and a controller left in PROGRAM is the '
        + 'state the best-known public case of this technique depended on.',
    tools: [
      'Zeek modbus.log',
      'Zeek conn.log',
      'SIS event log',
      'HMI/SIS host logs',
    ],
    dataSources: [
      'SIS sequence-of-events log',
      'bypass and override register',
      'Zeek modbus.log',
      'Zeek conn.log',
      'alarm history',
      'operator report',
    ],
    terrain: [
      'safety instrumented systems',
      'safety engineering workstations',
      'controllers',
    ],
    commands: [],
    steps: [
      step('Name the safety functions in scope — emergency shutdown, fire and gas, high-high trips — '
        + 'and read each one\'s bypass and override state from the SIS event log or the site\'s '
        + 'bypass register, not from the process trend. A bypassed function looks identical to an '
        + 'armed one until there is a demand.',
        'SIS event log · bypass register · engineering record', 'Every bypass in the window matched to an authorised entry, or filed.'),
      step('Where the safety controller has a program/run key switch, check its recorded position '
        + 'across the window. A safety controller left in PROGRAM accepts logic from the network, '
        + 'and that is the state the best-known public case of this technique depended on.',
        'SIS event log · HMI/SIS host logs', 'Key switch in RUN throughout, or each excursion into PROGRAM matched to a change record.'),
      step('Attribute every write that reached the SIS over its DCS interface — bypass, reset and '
        + 'override commands commonly arrive as Modbus writes from the DCS — using the T1692.001 '
        + 'approach applied to the safety system\'s addresses. Logic does not travel this way: it '
        + 'goes over the vendor engineering protocol, which Zeek rarely parses out of the box, so '
        + 'hunt that as any session to the SIS from something other than the safety engineering '
        + 'station, and as the transfer-then-restart shape from T0889.',
        'Zeek modbus.log · Zeek conn.log', 'Every Modbus write to the SIS attributed, and every non-Modbus session to it from a named safety engineering station, or filed.'),
      step('Check the SIS event log for any demand in the window and whether the function acted. A '
        + 'demand the function did not answer is the loss itself, not a precursor, and it goes up '
        + 'before anything else is read.',
        'SIS event log · alarm history · operator report', 'Every demand in the window answered by its function, or an incident declared.'),
    ],
    evidenceExpected:
      'Bypass, key-switch and demand state for every named safety function in scope, and every '
        + 'write or session reaching the SIS attributed.',
    doNext:
      'Any suspected compromise of a safety function is escalated in person immediately, ahead '
        + 'of everything else in the queue; this is the one place in the matrix where reporting '
        + 'latency is itself the hazard.',
  },

  T0879: {
    intent:
      'Damage to Property is the physical consequence you confirm after the fact — equipment '
        + 'breakdown, environmental release, structural harm — and it is reached by asking what '
        + 'drove a process outside its safe limits while nothing caught it: a manipulated setpoint '
        + '(T0836), a command outside design tolerance (T0831), repetitive actuation (T0806), or a '
        + 'protective layer already found disabled (T0837). Damage takes two failures, the '
        + 'excursion and the layer that should have contained it, and the second is where an '
        + 'adversary is most likely to show. There is no wire signature for "damage"; there is only '
        + 'the mechanism and its trace in the trend.',
    tools: [
      'Historian',
      'Zeek modbus.log',
      'maintenance records',
    ],
    dataSources: [
      'historian trends',
      'maintenance and inspection records',
      'alarm history',
      'Zeek modbus.log',
      'operator report',
    ],
    terrain: [
      'controllers',
      'field equipment',
    ],
    commands: [],
    steps: [
      step('Get the physical finding from the site first — what broke, was inspected, or was found '
        + 'out of tolerance — since this technique starts from a maintenance fact, not a log.',
        'Site engineer · Psephos · Comms', 'A dated physical finding with its location, or a recorded statement from the site that there is none in the window.'),
      step('Work backward through the historian trend from the finding to the point the equipment '
        + 'was driven outside its design limits, and record that timestamp. Then check whether a '
        + 'mechanism already hunted under its own task — Modify Parameter, Manipulation of Control, '
        + 'Brute Force I/O, Loss of Protection — accounts for that window.',
        'Historian · Zeek modbus.log', 'The excursion timed from the trend and matched to a specific mechanism task, or left open with the window recorded.'),
      step('Check the alarm history and the protective layer for the same window. Equipment rarely '
        + 'reaches the point of damage without a trip or alarm firing first, so establish whether '
        + 'it fired and was ignored, was suppressed (T0878), or never fired because the function '
        + 'was bypassed (T0837). That is what separates a process accident from this technique.',
        'Alarm history · engineering record', 'A stated answer on whether the containing layer acted, was suppressed, or was absent.'),
    ],
    evidenceExpected:
      'A physical damage finding linked to the excursion window in the trend and to the '
        + 'mechanism that produced it, with a stated answer on why the protective layer did not '
        + 'contain it — or an explicit statement that no mechanism was found.',
    doNext:
      'Confirmed adversary-driven damage is a safety and business incident simultaneously; it '
        + 'goes to the lead and to the process owner together, not sequentially.',
  },

  T1692: {
    intent:
      'Unauthorized Message is the general class covering any message a device acts on that it '
        + 'should not have — because the sender was not who it claimed, or because a legitimate '
        + 'sender issued a command the process had no business receiving. The children are the '
        + 'specific events: a spoofed or improper command is T1692.001, spoofed telemetry is '
        + 'T1692.002. What is left at the parent is the channel itself: a protocol with no session '
        + 'state, no source check and no message integrity accepts whatever speaks it, and that '
        + 'posture is a finding before any single message has been found. It is not the whole story '
        + '— a channel that authenticates its master still trusts a compromised master, which is '
        + 'why T1692.001 attributes every write rather than checking where it came from.',
    tools: [
      'Zeek dnp3.log',
      'Zeek conn.log',
      'Zeek modbus.log',
    ],
    dataSources: [
      'Zeek dnp3.log',
      'Zeek conn.log',
      'Zeek modbus.log',
      'device configuration records',
    ],
    terrain: [
      'controllers',
      'HMIs',
      'brokers and historians',
    ],
    commands: [
      'zeek-cut id.resp_p service < conn.log | awk \'$1==502||$1==802||$1==20000||$1==1883||$1==8883\' | sort | uniq -c',
      'zeek-cut fc_request fc_reply < dnp3.log | grep -ci authenticate',
    ],
    steps: [
      step('Establish from the capture whether each control protocol in use carries any source '
        + 'authentication. Plain Modbus/TCP on 502 has none by design; Modbus/TCP Security is TLS '
        + 'on 802 and is rare. DNP3 has Secure Authentication, and where it is on the AUTHENTICATE '
        + 'function codes appear in dnp3.log — a count of zero across the window means every '
        + 'outstation is trusting whatever addresses it. The common finding is \'this channel '
        + 'accepts anything that speaks the protocol\' rather than a specific message.',
        'Zeek conn.log · Zeek dnp3.log · Psephos · Characterization', 'A per-protocol statement of authenticated exchanges seen in the window, or none, with the port and function-code evidence attached.'),
      step('Where a specific unauthorized message is suspected, route it to the sub-technique it '
        + 'actually is rather than treating this parent as its own procedure. A command the process '
        + 'was not supposed to receive is T1692.001 whether it came from a stranger or from the '
        + 'usual HMI; telemetry the process did not really report is T1692.002.',
        'Analyst', 'The suspected event reclassified under one child technique, with the reason recorded.'),
    ],
    evidenceExpected:
      'A stated authentication posture per control protocol in scope, backed by port and '
        + 'function-code counts from the capture, and any specific incident routed to the correct '
        + 'child technique.',
    doNext:
      'An unauthenticated channel carrying safety-relevant traffic is filed as a standing '
        + 'exposure regardless of whether any abuse of it has been found. It goes to the site with '
        + 'the outage window a change would need; the hunt does not switch authentication on.',
  },

  'T1692.002': {
    intent:
      'Spoofing a reporting message puts false telemetry onto the wire itself — a fabricated or '
        + 'replayed sensor value reaching the historian, the HMI, a controller that acts on it, or '
        + 'any other consumer — which is a different attack surface from Manipulation of View '
        + '(T0832): that technique compromises the HMI\'s own display logic, this one compromises '
        + 'what the HMI and everything downstream is being told before it ever renders anything. '
        + 'How the false value gets onto the wire decides where it can be caught. On a publish or '
        + 'unsolicited protocol — MQTT, a DNP3 unsolicited response — the spoof is a second '
        + 'reporter and shows up as one; on request-response Modbus the reporting message is the '
        + 'reply to a poll, so the spoof has to ride the real session, and what leaks is a broken '
        + 'transaction, a second MAC behind the controller\'s address, or telemetry that has lost '
        + 'the noise a live sensor has. A consumer that only checks whether a value looks plausible '
        + 'cannot tell any of these from the truth.',
    tools: [
      'Zeek modbus.log',
      'Zeek mqtt_publish.log',
      'Zeek dnp3.log',
      'Arkime',
    ],
    dataSources: [
      'Zeek modbus.log',
      'Zeek mqtt_publish.log',
      'Zeek dnp3.log',
      'historian trends',
      'MQTT broker logs',
    ],
    terrain: [
      'controllers',
      'historians and brokers',
    ],
    commands: [
      'zeek-cut topic id.orig_h < mqtt_publish.log | sort -u | cut -f1 | uniq -d',
      'zeek-cut id.orig_h id.resp_h fc_reply < dnp3.log | grep UNSOLICITED | sort | uniq -c | sort -rn',
      'zeek-cut ts id.orig_h id.resp_h tid pdu_type < modbus.log | awk \'$5=="RESPONSE"{print $2,$3,$4}\' | uniq -d | head -40',
    ],
    steps: [
      step('On MQTT and DNP3, list who reports each point. A topic with two publishing sources, or '
        + 'an unsolicited response arriving from an address that is not the outstation of record, '
        + 'is the second voice a stable population makes easy to notice: the publisher set per '
        + 'topic should be as fixed as the device set, and a new one is anomalous before you know '
        + 'what it said.',
        'Zeek mqtt_publish.log · Zeek dnp3.log', 'One attributable publisher per topic and one outstation per point, or an extra one to explain.'),
      step('On Modbus there is no second voice at the IP layer: the reply rides the poll\'s own TCP '
        + 'session, so a spoof either hijacks that session or answers for the controller from '
        + 'another interface. Look for two responses to one transaction id back to back — the '
        + 'injected reply racing the real one — and, in Arkime, for the controller\'s address '
        + 'answering from more than one MAC in the window. A redundant CPU pair failing over is the '
        + 'benign answer to the second, and a planned event somebody can confirm. Both checks need '
        + 'a Zeek that logs tid and pdu_type (6.1 or later) or the ICSNPP modbus_detailed.log.',
        'Zeek modbus.log · Arkime', 'Every transaction id answered once and one MAC per controller address, or a session to pull the capture for.'),
      step('Where the broker or historian is the target rather than the wire between controller and '
        + 'HMI, check for publishes under a topic or tag the legitimate device does not normally '
        + 'use, and for values arriving faster or slower than the device\'s known reporting cadence. '
        + 'A device that publishes every second does not start publishing every 800 ms on its own.',
        'Zeek mqtt_publish.log · broker logs · Historian', 'Cadence and topic ownership per device match the baseline, or a topic or interval to explain.'),
      step('Read the trend for the shape a replay leaves before asking anyone for corroboration: a '
        + 'live sensor carries noise and a replayed or constant spoof does not, so a flat line '
        + 'where the process should wander, or a window that repeats an earlier window sample for '
        + 'sample, is the signature — it is what Stuxnet\'s recorded-and-replayed values would have '
        + 'shown. Then compare the suspect value against an independent second source for the same '
        + 'physical point where one exists — a redundant sensor, a downstream mass balance, a '
        + 'physical reading — since a convincing spoof is indistinguishable from the truth on the '
        + 'trend alone.',
        'Historian · site engineer', 'Independent corroboration obtained, or the value flagged as unverifiable from available evidence.'),
    ],
    evidenceExpected:
      'A per-point attribution of reporting sources on every protocol in scope; any duplicate '
        + 'response, second MAC, extra publisher or out-of-cadence reporter identified; and '
        + 'independent corroboration of the suspect value where one exists.',
    doNext:
      'A confirmed spoofed reporting message is an incident on two fronts. Everything the '
        + 'affected consumer has displayed or logged since the spoof began is suspect and the '
        + 'operator is told so directly, as under T0832; and if a controller rather than a screen '
        + 'consumed the value, the process may already have acted on it, which is worked with the '
        + 'operators as T0831 before the queue is finished.',
  },

  T0820: {
    intent:
      'The one procedure MITRE records for this technique is Triton disabling the Tricon\'s own '
        + 'firmware consistency check, which settles two things: the defence being evaded need not '
        + 'be an agent, it can be the controller\'s integrity check itself, and nothing passive sees '
        + 'that exploit — only the firmware write behind it. So this task splits by host class. On '
        + 'controllers there is no procedure to invent; route to the transfer-then-restart shape '
        + 'and the safety system\'s own diagnostics. On the general-purpose hosts that do carry '
        + 'monitoring — HMIs, historians, engineering workstations — the visible symptom is not a '
        + 'captured exploit but the monitor itself crashing or going quiet at a moment nobody '
        + 'scheduled, and a host whose defences have just been beaten is exactly the host whose '
        + 'self-report you can no longer trust.',
    tools: [
      'host logs',
      'Zeek',
    ],
    dataSources: [
      'monitoring or EDR service logs',
      'Windows System and Application event logs',
      'syslog',
      'Zeek conn.log',
      'Zeek stats.log',
      'safety system diagnostic alarms',
    ],
    terrain: [
      'HMIs',
      'historians and brokers',
      'engineering workstations',
      'controllers',
    ],
    commands: [
      'grep -Ei \'segfault|core dump|watchdog|restarted\' /var/log/syslog | tail -50',
      'wevtutil qe System /q:"*[System[(EventID=7031 or EventID=7034)]]" /c:50 /f:text',
      'zeek-cut ts peer pkts_dropped bytes_recv < stats.log | tail -20',
    ],
    steps: [
      step('Sort the hosts in scope by what there is to evade. A hardware controller\'s defence is '
        + 'its own firmware integrity check, and the exploit that beats it leaves nothing on the '
        + 'wire but the firmware write that follows — so controllers route to T1693.001 and to the '
        + 'safety system\'s own diagnostic alarms rather than getting a procedure here. Hunt here on '
        + 'the general-purpose hosts that carry an agent, an allowlisting product or a log '
        + 'forwarder.',
        'Psephos · Characterization', 'A per-host list of what there is to evade, each marked huntable here or routed.'),
      step('On those hosts, look for the monitoring process itself crashing or restarting '
        + 'unscheduled rather than for a payload: a 7034 or an application-error 1000 against the '
        + 'agent\'s service, a segfault line in syslog, a crash dump on disk. A clean stop and a '
        + 'crash look nothing alike, and the crash is the tell.',
        'host logs', 'A restart timeline for every monitored process, each entry matched to a patch, a reboot, or nobody.'),
      step('Cross-check the crash window against the wire, and first confirm the wire was watching: '
        + 'a stats.log interval with drops or zero bytes means the sensor went quiet too and the '
        + 'view is not independent. Then compare — the host\'s sessions in conn.log carrying on '
        + 'after its agent died while its forwarded logs stop is the divergence; the two accounts '
        + 'agreeing is the clean result.',
        'Zeek', 'Sensor healthy through the window, and either the host\'s forwarded logs and its wire sessions agree or a named divergence to escalate.'),
      step('Where a monitoring process died unexplained, treat everything that host says about '
        + 'itself after that moment as unverified rather than absent-of-findings.',
        'Psephos · Evidence', 'An explicit trust boundary recorded for the affected host, dated from the crash.'),
    ],
    evidenceExpected:
      'A crash-and-restart timeline for every host that carries something to evade, '
        + 'cross-checked against a sensor shown to have stayed up, and a stated routing for the '
        + 'controllers where the exploit itself cannot be seen.',
    doNext:
      'An unexplained crash of a security-relevant process goes to the lead immediately, and '
        + 'nothing that host reports afterward is treated as a clean bill until it is independently '
        + 'confirmed. A suspected firmware-level evasion on a safety controller is an incident and '
        + 'a vendor conversation, not a hunt task.',
  },

  T0849: {
    intent:
      'Masquerading in a control system aims at a person\'s eye at least as much as at a '
        + 'scanner. A service, a process, or a PLC rung named to sit unremarkably next to what is '
        + 'already there defeats an operator glancing at a screen far more reliably than it defeats '
        + 'a log — and where a log exists at all, the name in it is a field the adversary chose, so '
        + 'matching a baseline by name is exactly the check a competent masquerade has already '
        + 'passed.',
    tools: [
      'host logs',
    ],
    dataSources: [
      'host process, service and scheduled-job inventories',
      'engineering project exports',
      'file hashes against baseline',
    ],
    terrain: [
      'HMIs',
      'engineering workstations',
      'controllers',
    ],
    commands: [
      'ps -eo pid,ppid,comm,args --sort=comm 2>/dev/null | head -60',
      'sha256sum /usr/bin/* /opt/*/bin/* 2>/dev/null | sort -k2',
      'ls -l /etc/cron.d /etc/cron.daily /etc/systemd/system 2>/dev/null | head -60',
    ],
    steps: [
      step('Diff running processes, installed services and scheduled jobs against baseline by path '
        + 'and hash, not by name. A masquerading binary chooses its own name for exactly this '
        + 'reason, and a scheduled job is the cheapest place to park one where nobody looks.',
        'host logs', 'Every process, service or job matched to a known path and hash, or filed.'),
      step('On engineering workstations, diff program organisation unit and function-block names in '
        + 'the project against a saved-good export. The same trick applies one layer down, and no '
        + 'host-based tool will ever see it — it lives in a proprietary project format, not in a '
        + 'process list.',
        'Psephos · Characterization', 'Project object names matched to a known-good baseline.'),
      step('Ask the operator whether anything on the HMI or a panel has looked slightly off without '
        + 'being wrong enough to report. This technique targets a person\'s threshold for suspicion, '
        + 'and the near-miss usually lives in someone\'s head rather than in a log.',
        'Site operator · Psephos · Comms', 'A recorded answer, possibly empty.'),
      step('Treat a name that disagrees with its own path or hash as the finding regardless of what '
        + 'the file does when run. The whole point of the technique is to never look interesting '
        + 'enough to be examined, so waiting for behaviour is waiting for the technique to work.',
        'Psephos · Evidence', 'A filed record per mismatch.'),
    ],
    evidenceExpected:
      'A baseline-diffed process, service and scheduled-job inventory by hash and path, a '
        + 'project object name check, and a recorded operator conversation.',
    doNext:
      'A name/hash mismatch on a controller-adjacent host or inside a project file goes to the '
        + 'lead before further analysis; do not wait for the file to do something to take it '
        + 'seriously.',
  },

  T0872: {
    intent:
      'Many controllers have barely anything to remove: a small ring buffer that overwrites '
        + 'itself in hours or days is already indistinguishable from tampering by the time anyone '
        + 'looks, so the useful question is not "were logs deleted" but "did coverage stop or roll '
        + 'over earlier than the buffer size predicts." The answer that actually holds up is '
        + 'external — what the collector received and what the network saw, independent of what the '
        + 'device is willing to say about itself — because a host that has had its indicators '
        + 'removed is the one host whose own account you can no longer take at face value.',
    tools: [
      'host logs',
      'Zeek',
    ],
    dataSources: [
      'host audit or application logs where they exist',
      'Windows Security and System event logs on HMIs',
      'syslog/forwarder shipment records at the collector',
      'Zeek conn.log',
    ],
    terrain: [
      'HMIs',
      'historians and brokers',
      'engineering workstations',
      'controllers',
    ],
    commands: [
      'journalctl -o short-unix --no-pager 2>/dev/null | awk \'{t=int($1); if (p && t-p>1800) printf "%s -> %s  %dm\\n", strftime("%FT%T",p), strftime("%FT%T",t), (t-p)/60; p=t}\'',
      'grep -Ei \'rsyslogd|syslog-ng|filebeat|nxlog\' /var/log/syslog* 2>/dev/null | grep -Ei \'start|stop|exit|shut|reload|kill\'',
      'zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | awk \'$4==514||$4==6514||$4==5044\' | sort -k2,2 -k1,1n',
    ],
    steps: [
      step('On hosts that keep real logs, look for a hole rather than for a suspicious entry. '
        + 'Windows event record numbers and journald boot ids give you a sequence to check for '
        + 'skips; plain syslog gives you only timestamps, so there the tell is a silence longer '
        + 'than the host\'s usual chatter. On Windows HMIs the clearing itself is logged — Security '
        + '1102 and System 104 are written after the clear and survive it — so search for those '
        + 'before searching for holes.',
        'host logs', 'A gap list per host with start, end and duration, each gap explained by a reboot or maintenance record or filed; any 1102/104 event filed outright.'),
      step('Compare local coverage against what the collector received from the same host in the '
        + 'same window. A forwarded copy is outside the adversary\'s reach once sent, so a gap only '
        + 'on the local copy bounds the tampering precisely. Zeek gives the same answer from the '
        + 'wire: the forwarding flow — 514, 6514 or 5044 to the collector — going quiet from one '
        + 'host while its neighbours keep shipping is the gap, whatever the host says.',
        'Zeek · forwarder records', 'Local, collector and wire coverage compared per host; any window present in one and absent from another stated with its bounds.'),
      step('For the controllers themselves, state plainly what logging capacity the device has — '
        + 'diagnostic buffer depth, volatile-only, no persistent store — before concluding anything '
        + 'from its silence. Absence is often just how the device behaves, and a buffer that rolled '
        + 'over on schedule is not evidence of anything.',
        'Psephos · Characterization', 'A per-controller statement of native logging capacity and roll-over period.'),
      step('Treat a change to the forwarder\'s own configuration or service state as seriously as a '
        + 'deleted log. Disabling shipment is a cheaper way to erase history than editing it after '
        + 'the fact, and a restart of the shipper that lines up with a gap in step 1 is the whole '
        + 'story.',
        'host logs', 'Forwarder config mtime and every service start, stop or reload in the window listed, each matched to a change record or filed.'),
    ],
    evidenceExpected:
      'A gap analysis per host across local, collector and wire views, and an explicit '
        + 'statement of each controller\'s native logging capacity.',
    doNext:
      'A gap that appears only in the local copy of a log, a shipper restart that lines up with '
        + 'one, or a 1102/104 clear event is filed and escalated rather than read as inconclusive.',
  },

  T0873: {
    intent:
      'An infected project file survives exactly the action meant to fix things: reflashing or '
        + 'redownloading a "clean" program sourced from an infected project reintroduces the '
        + 'infection on the next legitimate deployment. The object worth hashing here is not the '
        + 'running logic on the controller — that is Modify Program — but the source file sitting '
        + 'on an engineer\'s disk or in a repository, which is exactly the artefact a hunt of the '
        + 'controller itself will never look at.',
    tools: [
      'host logs',
    ],
    dataSources: [
      'engineering workstation file hashes and timestamps',
      'project repository or version-control history',
      'change-control records',
    ],
    terrain: [
      'engineering workstations',
    ],
    commands: [
      'find / \\( -iname \'*.acd\' -o -iname \'*.s7p\' -o -iname \'*.zap*\' -o -iname \'*.ap[12][0-9]\' \\) 2>/dev/null | head -40',
      'for p in $(find / -iname \'*.s7p\' -o -iname \'*.ap[12][0-9]\' 2>/dev/null); do find "$(dirname "$p")" -type f -exec sha256sum {} +; done',
      'find / \\( -iname \'*.acd\' -o -iname \'*.zap*\' \\) -type f -exec sha256sum {} + 2>/dev/null',
    ],
    steps: [
      step('Hash every project held on engineering workstations and in any repository, and compare '
        + 'against the last known-good check-in. Hash the whole project tree, not the file the '
        + 'engineer double-clicks: a Step 7 .s7p or a TIA Portal .ap1x is an index into a directory '
        + 'beside it, and the Stuxnet-era infection lived in that directory while the index file '
        + 'stayed the same. Where no known-good exists, the set you record is the baseline, and '
        + 'that is the honest output.',
        'host logs', 'Every project tree matching its known-good hash, or a named mismatch; where there was no known-good, a filed baseline per project.'),
      step('Check whether the project format supports embedded scripts, macros or add-ins — several '
        + 'vendor formats do — and treat that as a separate attack surface from the ladder logic '
        + 'itself. Such content can run on the engineer\'s workstation the moment the file is '
        + 'opened, before anything reaches a controller.',
        'vendor documentation · Psephos · Characterization', 'A stated answer, per format in use, on whether it carries executable content beyond logic.'),
      step('Review file access and modification timestamps against the change-control record for '
        + 'legitimate engineering sessions. An edit outside a documented session is the anomaly, '
        + 'however small it looks.',
        'host logs', 'Every modification matched to a documented session, or filed.'),
      step('Where a repository exists, read its check-in history the way source code is read '
        + 'elsewhere in a hunt: who committed, and whether an older version was reintroduced. A '
        + 'rollback to an infected prior version looks identical to a routine one, so the question '
        + 'is whether the person and the change record account for it.',
        'version control · Psephos · Evidence', 'Every check-in attributed to a person and a change, and each reintroduction of a prior version explained or filed.'),
    ],
    evidenceExpected:
      'A hash and timestamp inventory of project trees against known-good or a filed baseline, '
        + 'and a stated answer on whether the format carries executable content beyond logic.',
    doNext:
      'Nothing is downloaded to a controller from a project file under question, and nothing is '
        + 'cleaned by the hunter either. The affected version goes to the process owner and the '
        + 'vendor, who decide how the next legitimate download is sourced.',
  },

  T0894: {
    intent:
      'OT general-purpose hosts patch rarely, which is exactly why application allowlisting is '
        + 'the common compensating control on HMIs and historians — it can be deployed without '
        + 'touching the process. That makes this technique more relevant here than most evasion '
        + 'methods: proxying execution through a binary the allowlist already trusts is the direct '
        + 'way around the one control the site actually put in. It is also more huntable here than '
        + 'on IT, because the set of parents that legitimately launch a script host or installer '
        + 'engine on an HMI is short enough to enumerate and baseline, which is never true of an '
        + 'office workstation.',
    tools: [
      'host logs',
      'Sysmon',
      'Zeek',
    ],
    dataSources: [
      'AppLocker EXE and DLL log (8002 allowed, 8004 blocked) where deployed',
      'WDAC CodeIntegrity operational log (3076 audit, 3077 enforced) where deployed',
      'Sysmon 1 or Security 4688 with command line (Process Create)',
      'Sysmon 3 (Network Connection)',
      'Zeek conn.log',
    ],
    terrain: [
      'HMIs',
      'historians and brokers',
      'engineering workstations',
    ],
    commands: [
      'Get-WinEvent -FilterHashtable @{LogName=\'Microsoft-Windows-AppLocker/EXE and DLL\'; Id=8002,8003,8004} | Where-Object { $_.Message -match \'mshta|regsvr32|rundll32|certutil|wscript|cscript|msiexec|installutil\' } | Select-Object TimeCreated,Id,Message -First 40',
      'Get-WinEvent -FilterHashtable @{LogName=\'Microsoft-Windows-Sysmon/Operational\'; Id=1} | Where-Object { $_.Message -match \'Image: .*\\\\(mshta|regsvr32|rundll32|certutil|wscript|cscript|msiexec|installutil)\\.exe\' } | Select-Object TimeCreated,Message -First 40',
      'Get-WinEvent -FilterHashtable @{LogName=\'Microsoft-Windows-Sysmon/Operational\'; Id=3} | Where-Object { $_.Message -match \'Image: .*\\\\(mshta|regsvr32|rundll32|certutil|wscript|cscript|msiexec|installutil)\\.exe\' } | Select-Object TimeCreated,Message -First 40',
      'zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | sort -u | head -40',
    ],
    steps: [
      step('Establish, per host, what evidence exists before hunting this: allowlisting logs, '
        + 'process-creation logging with the command line (Sysmon 1, or 4688 with command-line '
        + 'auditing switched on — without it 4688 names the binary and nothing else), or neither. '
        + 'Which you have decides the approach, and a host with neither goes straight to the last '
        + 'step.',
        'Psephos · Characterization', 'A stated allowlisting and process-logging posture per host.'),
      step('Where allowlisting exists, read its own log first. AppLocker records allowed executions '
        + 'as 8002 and blocked ones as 8004, so the proxy binaries appear there whether or not they '
        + 'got through; WDAC logs only what it blocked, so allowed executions come from '
        + 'process-creation logs instead. For every script host, installer engine or signed '
        + 'utility, check the parent and the command line against what launches it on that build — '
        + 'on an HMI that list is short, and a parent not on it is the finding.',
        'AppLocker log · Sysmon 1 · Security 4688', 'Every proxy-binary execution matched to its parent and a legitimate task, or filed.'),
      step('Attribute outbound connections to the process that made them where Sysmon 3 exists, and '
        + 'list any whose image is a script host, installer engine or certutil. An HMI\'s outbound '
        + 'set is fixed and small, and those images should contribute nothing to it. Where only '
        + 'conn.log exists, diff the host\'s destinations against baseline instead and say plainly '
        + 'that the wire cannot name the binary.',
        'Sysmon 3 · Zeek', 'Every outbound connection made by a proxy binary explained or filed; without Sysmon 3, a destination diff and a stated attribution gap.'),
      step('Where neither allowlisting nor command-line logging exists, say so and stop at the '
        + 'destination diff. Nothing on the wire answers "which binary executed", and a task that '
        + 'pretends otherwise reports silence as a negative.',
        'Psephos · Evidence', 'An explicit statement of what cannot be checked and why.'),
    ],
    evidenceExpected:
      'Per-host allowlisting and process-logging posture, every proxy-binary execution '
        + 'attributed to a parent and a legitimate task or filed, and any connection made by one '
        + 'explained.',
    doNext:
      'An unattributed proxy-binary execution on an HMI or historian is treated as compromise '
        + 'of that host, not a policy exception, until shown otherwise. Nobody tightens the '
        + 'allowlist mid-hunt — a rule change on an HMI is a change to a production device and goes '
        + 'to the site.',
  },
});
