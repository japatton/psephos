/**
 * Expansion layer over the team's uploaded hunt plan.
 *
 * Everything here is marked source:"expanded" so an analyst can always tell
 * which procedure the team wrote and which came from a standards reference.
 * The team's own cells are never rewritten.
 *
 * Two kinds of addition:
 *
 *  1. Steps under existing tasks. The uploaded plan says WHAT to hunt and
 *     often gives a query; it rarely says how to scope it, what normal looks
 *     like, or when to stop. That is what the steps supply.
 *
 *  2. Three new phases. The uploaded plan has no coverage of Linux or OT/ICS
 *     — no Modbus, PLC, HMI, MQTT, BACnet, journald, cron or rootkit content
 *     anywhere in 31 tasks — and next week is weighted to exactly that. The
 *     OT phases are written for analysts who have not hunted ICS before, so
 *     they explain why a technique that is routine on IT is dangerous here.
 *
 * References: MITRE ATT&CK for ICS and NIST SP 800-82r3. Written against an
 * estate whose OT sits behind a single IT/OT boundary router; adjust the
 * terrain hints to your own.
 */

const step = (text, tooling, expect) => ({ text, tooling, expect, source: 'expanded' });

// ---------------------------------------------------------------------------
// Steps for the team's existing tasks, keyed by task key.
// ---------------------------------------------------------------------------

const STEPS = {
  'P1-validate-administrative-account-baseline': [
    step('Enumerate every account in Domain Admins, Enterprise Admins and the local Administrators group on every domain controller. Write the list down; it is the baseline everything else is judged against.',
      'PowerShell / LDAP', 'A fixed, short list. Anything added later is an event, not a coincidence.'),
    step('Pull 4624 for those accounts across the estate and group by logon type. Type 3 (network) and 10 (RemoteInteractive) on a workstation are what you are looking for.',
      'Kibana · winlogbeat', 'Admin accounts should touch servers, not client subnets.'),
    step('Cross-check 4672 (special privileges) against the baseline list. A 4672 for an account not on it means privilege was granted somewhere you have not looked.',
      'Kibana', 'Only baseline accounts appear.'),
    step('KNOWN GAP: 4625, 4720, 4728/4732/4756 and 4740 are absent estate-wide. Do not conclude "no failed logons" or "no group changes" from silence — record the gap as the finding.',
      'Kibana', 'Explicitly state which conclusions the audit policy cannot support.'),
  ],
  'P1-host-discovery-and-network-baseline': [
    step('Reconcile against the surveyed terrain already in Psephos rather than starting from the spreadsheet. It carries presence per host and flags nine that are alive with no DNS and no AD object.',
      'Psephos · Network Map', 'Your discovery agrees with the map, or you have found drift.'),
    step('DO NOT run nmap into 10.20.x, 10.124.x or 10.125.x. Those are OT. Active scanning of PLCs is a recognised cause of process upset; the OT baseline is passive and is covered in phase 6.',
      '—', 'IT ranges scanned, OT ranges untouched.'),
    step('For IT ranges, prefer -sT -Pn over -O and -sV against anything you cannot identify. Version and OS probes send malformed input by design.',
      'nmap', 'Host and port list with no service disruption.'),
    step('Feed anything unmapped into the map as a discovered host and record it. Live addresses inside a workstation range that answer to no name are the ones to chase first.',
      'Psephos', 'Every live address is either inventory or a recorded finding.'),
  ],
  'P2-password-spraying': [
    step('4625 is not collected on this estate, so host-side spray detection is unavailable. Pivot to network: authentication volume per source in Zeek, and Kerberos pre-auth failures (4771) if present.',
      'Zeek · Kibana', 'A source touching many accounts, few attempts each.'),
    step('Spray is wide and shallow. Group by source address and count DISTINCT accounts, not total attempts — the total will look unremarkable.',
      'Kibana', 'One source, many usernames, low per-account count.'),
    step('Check any password pattern already seen to work in this intrusion — doubled dictionary words are common. If it worked once, spray it against the rest of the enclave in your own head before the adversary does.',
      'Analyst', 'A list of accounts to force-reset.'),
  ],
  'P4-credentials-from-password-store': [
    step('LSASS access is the higher-value signal: Sysmon 10 with TargetImage lsass.exe. A confirmed injection into LSASS on any one host makes this estate-wide work.',
      'Kibana · Sysmon', 'Any non-system process opening LSASS.'),
    step('Check whether RunAsPPL was ever configured; where it was not, LSASS is unprotected estate-wide. Then treat every credential used on a compromised host as burned, not just the ones you can prove were dumped.',
      'Analyst', 'A reset list, not a "was it dumped" debate.'),
    step('Check for procdump, comsvcs.dll MiniDump, and rundll32 against lsass in 4688 and Sysmon 1 command lines.',
      'Kibana', 'Named tooling, or its absence recorded as a gap.'),
  ],
  'P5-exfiltration': [
    step('Port 21 is one path. Also check 22 (scp/sftp), 445 outbound, DNS TXT volume, and HTTP POST body sizes — outbound SMB to an address outside the estate is a strong candidate.',
      'Arkime · Zeek', 'Ranked list of egress candidates by bytes out.'),
    step('For each candidate, establish direction and volume before calling it exfil. A large inbound transfer is tool ingress, which is a different finding.',
      'Arkime', 'Bytes out clearly exceeds bytes in.'),
    step('An exfil destination often turns out to be an ordinary domain workstation being used as a staging hop, not an address outside the estate. Internal hops look like normal traffic; do not filter to egress-only.',
      'Psephos · Arkime', 'Internal destinations are in scope.'),
  ],
};

/** Tasks with no bespoke steps still get a usable loop built from their own cells. */
function defaultSteps(task) {
  const q = task.commands?.[0];
  return [
    step(`Scope it: decide which hosts and which time window this applies to before running anything. ${
      task.dataSources?.length ? `Data: ${task.dataSources.join(', ')}.` : ''}`,
    task.tools?.join(' · ') || 'Kibana', 'A named host set and a time range you can defend.'),
    step(q ? `Run the query from the plan and read the result count first: ${q}`
      : 'Build the query from the data sources named in the plan, and read the result count before reading rows.',
    task.tools?.join(' · ') || 'Kibana', 'A count you can reason about. Zero is a result; say why.'),
    step('Triage: separate range emulation from adversary. Range user-emulation traffic and orchestrated binary drops from C:\\Windows\\Temp\\<staging-directory>\\ are exercise content — assign them to Thread R rather than deleting them.',
      'Analyst', 'Remaining hits are candidates, not noise.'),
    step('Record what you found AND what you looked at and did not find. A negative with a stated scope is a finding; silence is not.',
      'Psephos · Evidence', 'A record filed, or an explicit no-result note.'),
  ];
}

// ---------------------------------------------------------------------------
// New phases: OT/ICS and Linux.
// ---------------------------------------------------------------------------

const OT_FOUNDATIONS = {
  key: 'P6',
  name: 'OT/ICS foundations and visibility',
  source: 'expanded',
  intent:
    'Before hunting the OT estate, understand why it is not an IT network. The priority order is ' +
    'safety, then availability, then integrity, then confidentiality — the reverse of what you are ' +
    'used to. A PLC is a real-time device with a small stack: a port scan or a malformed probe that ' +
    'an IT server shrugs off can fault it, and a faulted PLC is a physical process that stopped. ' +
    'Nothing in this phase sends unsolicited traffic to a controller.',
  tasks: [
    {
      key: 'P6-ot-orientation', title: 'Orient on the OT estate and the rules of engagement',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent: 'Everyone hunting OT this week should be able to draw the estate from memory before touching it.',
      mitre: [], tools: ['Psephos · Network Map'],
      terrain: ['10.20.20.0/24', '10.20.30.0/24', '10.20.40.0/24', '10.20.50.0/24', '10.124.10.0/24', '10.125.10.0/24'],
      references: ['NIST SP 800-82r3 §3', 'ATT&CK for ICS'],
      steps: [
        step('Walk the six OT segments on the map and name what lives in each: Power North and South (HMI + three OpenPLCs each), Services (FUXA fire-alarm HMI, MQTT broker, VMS), Access Control (RFID reader), Cameras (six RTSP), Building Automation (two Windows BAS emulators).',
          'Psephos · Network Map', 'You can state which segment does what without looking.'),
        step('Note the one asymmetry that matters: the entire OT estate is Ubuntu except 10.20.50.11 and .12. Windows-centric tradecraft will find almost nothing here, and the absence of Sysmon is not the absence of activity.',
          'Psephos', 'You stop expecting 4688s.'),
        step('Find the boundary. Everything crossing IT to OT passes through it, which makes it both the chokepoint you monitor and the thing an adversary must traverse.',
          'Network Map · Zeek', 'You can name the path from a compromised IT host to a PLC.'),
        step('Agree the ROE in writing: passive collection only, no active scanning, no writes, no Modbus function codes issued by anyone hunting. If a task seems to need active probing, escalate to the Cyber Crew Lead instead of improvising.',
          'Analyst', 'Written ROE the whole element has read.'),
      ],
      evidenceExpected: 'A one-page estate sketch and a signed-off ROE.',
    },
    {
      key: 'P6-passive-collection', title: 'Stand up passive collection on the OT segments',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent: 'You cannot hunt what you cannot see, and in OT you may only watch.',
      mitre: ['T0842'], tools: ['Zeek', 'Arkime', 'tcpdump'],
      references: ['NIST SP 800-82r3 §6.2'],
      steps: [
        step('Confirm where the OT sensor tap sits and which of the six segments it actually covers. A tap on the OT uplink sees IT-to-OT traffic but may miss PLC-to-PLC inside a segment.',
          'Zeek · Arkime', 'A written list of covered and uncovered segments.'),
        step('Verify Zeek is parsing the industrial protocols rather than logging them as generic TCP. Check for modbus.log; if it is absent, Modbus traffic is invisible as Modbus no matter how much you capture.',
          'Zeek', 'modbus.log exists and is populating.'),
        step('Record uncovered segments as a visibility finding straight away. "We could not see Power South" is a real result and belongs in the case file before the week ends, not after.',
          'Psephos · Evidence', 'A filed record naming each blind segment.'),
      ],
      evidenceExpected: 'Sensor coverage map, and a filed finding for every uncovered segment.',
    },
    {
      key: 'P6-protocol-baseline', title: 'Baseline OT protocols and polling cadence',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent:
        'This is the single highest-value thing a new OT hunter can do. Control traffic is machine-generated ' +
        'and near-deterministic: the same master polls the same registers at the same interval all day. ' +
        'Once you know the cadence, anomalies are obvious in a way they never are on an IT network.',
      mitre: ['T0842', 'T0885'], tools: ['Zeek', 'Arkime'],
      terrain: ['10.124.10.0/24', '10.125.10.0/24', '10.20.20.0/24', '10.20.40.0/24', '10.20.50.0/24'],
      references: ['ATT&CK for ICS T0842', 'NIST SP 800-82r3 §6'],
      steps: [
        step('For each PLC (10.125.10.110-112 and 10.124.10.110-112), record over a full hour: which addresses talk to it on 502/tcp, the poll interval, and the function codes seen. Expect one or two masters and a metronome.',
          'Zeek modbus.log', 'A per-PLC table: master, interval, function codes.'),
        step('Do the same for MQTT on 10.20.20.100:1883 — which clients connect, which topics they publish and subscribe to. The RFID reader at 10.20.30.12 is a known client; anything else needs explaining.',
          'Zeek · Arkime', 'A client-to-topic map.'),
        step('Baseline RTSP on the six cameras (10.20.40.10-60:554) and BACnet on the BAS pair (10.20.50.11-12:47808). Cameras should stream to the VMS at 10.20.20.200 and essentially nowhere else.',
          'Arkime', 'Camera traffic terminates at the VMS.'),
        step('Write the baseline into the case file as a filed record per segment. Next week it is the thing you compare against, and a baseline that lives only in someone notebook is not a baseline.',
          'Psephos · Evidence', 'One filed baseline record per OT segment.'),
      ],
      evidenceExpected: 'Per-segment baseline records: masters, cadence, function codes, topics.',
    },
    {
      key: 'P6-it-ot-boundary', title: 'Map and watch the IT/OT boundary',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent: 'Every OT intrusion in this scenario has to cross INTRTR. Watch the door.',
      mitre: ['T0886'], tools: ['Zeek', 'Arkime', 'Firewall log'],
      terrain: ['the IT/OT boundary'],
      references: ['NIST SP 800-82r3 §5 (Purdue)'],
      steps: [
        step('Enumerate every flow that crossed from IT into an OT segment in the last seven days, by source, destination and port. This list should be short and boring.',
          'Zeek · Arkime', 'A small set of known engineering workstations and jump paths.'),
        step('Any IT host reaching 502, 1883 or 47808 directly is a finding regardless of what it is. Control protocols should originate from HMIs and engineering stations, not from a file server or a workstation.',
          'Zeek', 'Zero unexpected IT-to-control-protocol flows, or a filed record.'),
        step('Cross-reference against the known compromised IT hosts — patient zero and anything that held credential theft. If any of them has ever spoken to OT, that is the pivot and it is the most important thing you will find this week.',
          'Psephos · Arkime', 'An explicit yes or no, with the query and window stated.'),
      ],
      evidenceExpected: 'A boundary-crossing inventory, and an explicit finding on whether known-compromised IT hosts reached OT.',
    },
  ],
};

const OT_HUNT = {
  key: 'P7',
  name: 'OT/ICS threat hunting',
  source: 'expanded',
  intent:
    'Hunting for adversary effect on the process. These map to ATT&CK for ICS rather than enterprise ' +
    'ATT&CK. The thing to hold onto: in IT the adversary wants data, in OT they want the process to do ' +
    'something it should not. A single well-formed write can matter more than a thousand reads.',
  tasks: [
    {
      key: 'P7-unauthorized-command', title: 'Unauthorized Modbus command or parameter change',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent: 'The highest-consequence OT event: someone told a controller to change the process.',
      mitre: ['T1692.001', 'T0836', 'T0831'], tools: ['Zeek modbus.log', 'Arkime'],
      terrain: ['10.124.10.0/24', '10.125.10.0/24'],
      references: ['ATT&CK for ICS T1692.001, T0836, T0831'],
      steps: [
        step('Split observed Modbus function codes into reads and writes. Reads (1,2,3,4) are the normal polling traffic. Writes — 5 Write Single Coil, 6 Write Single Register, 15 and 16 the multiple variants — change the process.',
          'Zeek modbus.log', 'A clean read/write split per PLC.'),
        step('Every write is a candidate. Identify the source of each and check it against the baselined master from P6. A write from the usual HMI during a shift may be legitimate; a write from anywhere else is not.',
          'Zeek', 'Each write attributed to a known master, or filed.'),
        step('Check function code 8 (Diagnostics) and 43 (Encapsulated Interface). Sub-function 1 of code 8 is Restart Communications Option, which is a denial-of-service primitive dressed as a diagnostic.',
          'Zeek', 'No unexpected code 8 traffic.'),
        step('If you find a write you cannot attribute, do not undo it. File it, tell the Cyber Crew Lead, and let process owners decide — reverting a setpoint blind can be more dangerous than the change.',
          'Psephos · Evidence', 'A filed record and a notified lead.'),
      ],
      evidenceExpected: 'Every Modbus write in the window, attributed or filed.',
    },
    {
      key: 'P7-rogue-master', title: 'Rogue master or unexpected client on control protocols',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent: 'A new speaker on a control protocol is anomalous by construction; the population is fixed.',
      mitre: ['T0846', 'T0886', 'T1694.001'], tools: ['Zeek', 'Arkime'],
      references: ['ATT&CK for ICS T0846'],
      steps: [
        step('Diff the set of addresses speaking 502, 1883, 554 and 47808 against the P6 baseline. In OT this set changes when someone installs equipment, which is a planned event you can ask about.',
          'Zeek', 'An empty diff, or a name to chase.'),
        step('Look for sequential connections to many PLCs from one source — that is discovery, and it looks nothing like the steady per-PLC polling of a real master.',
          'Zeek · Arkime', 'No fan-out pattern.'),
        step('Check for authentication with default or vendor credentials on HMIs and the MQTT broker. OT devices ship with them and they frequently survive commissioning.',
          'Arkime · host logs', 'Default accounts disabled, or a filed finding.'),
      ],
      evidenceExpected: 'The current speaker set, diffed against baseline.',
    },
    {
      key: 'P7-hmi-integrity', title: 'HMI compromise and manipulation of view',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent:
        'An HMI is the operator sense of what the process is doing. Compromise it and you can make ' +
        'a dangerous process look normal — the operator is then part of the attack rather than a defence.',
      mitre: ['T0832', 'T0831'], tools: ['Zeek', 'host logs', 'Kibana'],
      terrain: ['10.125.10.10', '10.124.10.10', '10.20.20.5'],
      references: ['ATT&CK for ICS T0832'],
      steps: [
        step('The three HMIs are Ubuntu, so hunt them as Linux hosts: SSH sessions, sudo use, new processes, changed files under the HMI application directory. Phase 8 has the technique.',
          'auth.log · journald', 'A session and change history per HMI.'),
        step('Compare what the HMI is displaying against what the PLC is actually reporting on the wire. A divergence between polled register values and the operator view is manipulation of view, and it is invisible from either side alone.',
          'Zeek modbus.log', 'Displayed values match polled values.'),
        step('FUXA at 10.20.20.5 is the fire alarm panel HMI. Treat any unexplained change there as safety-relevant and escalate immediately rather than finishing your queue first.',
          'Analyst', 'Escalation path exercised if anything is found.'),
      ],
      evidenceExpected: 'Per-HMI session and change history; a stated view-versus-wire comparison.',
    },
    {
      key: 'P7-mqtt-abuse', title: 'MQTT broker abuse',
      source: 'expanded', priority: 'medium', team: 'Alpha',
      intent: 'The broker at 10.20.20.100 is a hub: subscribe to the right topic and you see much of the estate.',
      mitre: ['T0885', 'T0882'], tools: ['Zeek', 'Arkime'],
      terrain: ['10.20.20.100', '10.20.30.12'],
      steps: [
        step('List clients and their subscribed topics. A client subscribing to a wildcard (# or +) is collecting everything, which is rarely what a purpose-built device does.',
          'Arkime', 'No wildcard subscribers you cannot name.'),
        step('Check whether the broker allows anonymous connections. Mosquitto defaults to it, and an anonymous subscriber is an unauthenticated tap on the process.',
          'Arkime · host logs', 'Anonymous access disabled, or a filed finding.'),
        step('Watch for publishes from clients that should only subscribe. The RFID reader publishing badge events is expected; the RFID reader publishing to a control topic is not.',
          'Zeek · Arkime', 'Publish and subscribe roles match device function.'),
      ],
      evidenceExpected: 'Client-topic-role table with anomalies filed.',
    },
    {
      key: 'P7-camera-pivot', title: 'Cameras and VMS as a pivot or collection point',
      source: 'expanded', priority: 'medium', team: 'Alpha',
      intent: 'Six Linux hosts nobody patches, on a segment that reaches the rest of OT.',
      mitre: ['T0882', 'T0866'], tools: ['Arkime', 'Zeek'],
      terrain: ['10.20.40.0/24', '10.20.20.200'],
      steps: [
        step('Confirm each camera streams only to the VMS at 10.20.20.200. A camera with an outbound session anywhere else is either misconfigured or repurposed.',
          'Arkime', 'All RTSP terminates at the VMS.'),
        step('Look for non-RTSP traffic from cameras: SSH, HTTP to unexpected hosts, DNS. These are general-purpose Linux boxes and an adversary will treat them as such.',
          'Zeek', 'Cameras speak RTSP and little else.'),
        step('Check the VMS for outbound transfers. It aggregates video from the whole site, which makes it the single best place to steal operational information from.',
          'Arkime', 'No unexplained bulk egress from 10.20.20.200.'),
      ],
      evidenceExpected: 'Per-camera flow summary and a VMS egress check.',
    },
    {
      key: 'P7-plc-program-change', title: 'PLC program or firmware modification',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent: 'Changing the logic is more durable than changing a value, and far harder to spot afterwards.',
      mitre: ['T0889', 'T1693.001'], tools: ['Zeek', 'host logs'],
      terrain: ['10.124.10.110', '10.124.10.111', '10.124.10.112', '10.125.10.110', '10.125.10.111', '10.125.10.112'],
      references: ['ATT&CK for ICS T0889'],
      steps: [
        step('These are OpenPLC on Ubuntu, so a logic change leaves host-side evidence a real PLC would not give you. Check the OpenPLC web interface access log and the timestamps on the program files.',
          'host logs', 'No unexplained program upload or file change.'),
        step('A program download is a distinctive traffic pattern: a long transfer to the controller, then a restart, quite unlike steady register polling. Look for the shape even if you cannot decode it.',
          'Zeek · Arkime', 'No transfer-then-restart pattern.'),
        step('Record the current program hash for each PLC now, so that next time this question is asked it can be answered in minutes rather than argued about.',
          'Psephos · Evidence', 'Six hashes filed as a baseline record.'),
      ],
      evidenceExpected: 'Program hashes filed; any upload pattern investigated.',
    },
  ],
};

const LINUX_HUNT = {
  key: 'P8',
  name: 'Linux host hunting',
  source: 'expanded',
  intent:
    'Most of the defended estate is Linux and none of it has EDR, so the Windows playbook does not ' +
    'transfer. There is already a confirmed LKM rootkit on the compromised webserver, which has a specific ' +
    'consequence worth stating plainly: on a host running an ftrace rootkit, everything userland tells ' +
    'you is suspect. Collect, then verify from outside the host.',
  tasks: [
    {
      key: 'P8-auth-review', title: 'Authentication and session review',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent: 'The Linux equivalent of the 4624 sweep, on hosts with no Sysmon.',
      mitre: ['T1078', 'T1021.004'], tools: ['journald', 'auth.log', 'Kibana'],
      steps: [
        step('Pull Accepted and Failed entries from /var/log/auth.log and journalctl -u sshd. Unlike Windows here, failed authentication IS logged on Linux — this is one place you have visibility the IT side lacks.',
          'auth.log · journald', 'A source-and-account picture per host.'),
        step('Check for public-key logons you cannot account for and read ~/.ssh/authorized_keys for every account including service accounts. An added key is quiet, durable persistence.',
          'host', 'Every authorized key maps to a named person.'),
        step('Review sudo use in auth.log. Look for sudo to root from accounts that have no operational reason, and for NOPASSWD entries added to /etc/sudoers.d/.',
          'auth.log', 'Sudo use matches role.'),
      ],
      evidenceExpected: 'Per-host session summary and an authorized_keys inventory.',
    },
    {
      key: 'P8-persistence-sweep', title: 'Linux persistence sweep',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent: 'The known intrusion used cron. Cron is one of roughly a dozen places to look.',
      mitre: ['T1053.003', 'T1543.002', 'T1546.004'], tools: ['host', 'Kibana'],
      references: ['any cron persistence already confirmed in the case file'],
      steps: [
        step('cron: /etc/crontab, /etc/cron.d/, cron.{hourly,daily,weekly}, and every user crontab via crontab -l -u. Removing one line from /etc/crontab is not remediation on its own; removing one line does not clear the others.',
          'host', 'Every scheduled entry accounted for.'),
        step('systemd: list unit files and timers, and diff against a known-good host. systemctl list-timers --all and list-unit-files --state=enabled. A timer is cron that most people forget to check.',
          'systemctl', 'No unexplained unit or timer.'),
        step('Shell and loader: ~/.bashrc, ~/.profile, /etc/profile.d/, /etc/ld.so.preload and the LD_PRELOAD environment. ld.so.preload in particular is a rootkit staple.',
          'host', 'These files match a clean baseline.'),
        step('Check for setuid binaries outside the expected set: find / -perm -4000 -type f 2>/dev/null. Compare against a clean host of the same build rather than against intuition.',
          'host', 'setuid set matches the baseline image.'),
      ],
      evidenceExpected: 'A completed checklist per host, with each location named and its result recorded.',
    },
    {
      key: 'P8-kernel-integrity', title: 'Kernel integrity and rootkit detection',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'A loadable kernel module rootkit is assessed on the compromised webserver. This task exists because ' +
        'every other Linux task on that host is untrustworthy until this one is resolved.',
      mitre: ['T1014', 'T1547.006'], tools: ['host', 'external verification'],
      references: ['any loadable-kernel-module rootkit assessed in the case file'],
      steps: [
        step('List loaded modules (lsmod, /proc/modules) and compare against a clean host of the same build. Note that a competent rootkit hides itself from exactly this, so a clean result proves little.',
          'host', 'A module list, and an explicit note that it may be filtered.'),
        step('Check for ftrace hooking: /sys/kernel/debug/tracing/enabled_functions, and kernel taint via /proc/sys/kernel/tainted. A non-zero taint value on a host that should run only distro modules is a finding.',
          'host', 'Taint value recorded and explained.'),
        step('Verify from outside the host. Compare what the host claims about its own processes and connections against what the network sensor sees. A connection Zeek shows and the host denies is the rootkit answering for it.',
          'Zeek · Arkime', 'Host view and network view agree, or you have your proof.'),
        step('Do not clear it in place. Image it. Where the dropped binary has not been collected yet, rebuilding the host destroys the only copy.',
          'Analyst', 'Image and implant captured before any remediation.'),
      ],
      evidenceExpected: 'Module list, taint value, and a documented host-versus-network comparison.',
    },
    {
      key: 'P8-process-network', title: 'Process and network anomalies without EDR',
      source: 'expanded', priority: 'medium', team: 'Bravo',
      intent: 'No agent means you compare against normal instead of against a detection.',
      mitre: ['T1059.004', 'T1071.001'], tools: ['host', 'Zeek'],
      steps: [
        step('Enumerate listening sockets and their owning process: ss -tulpn. Anything listening that is not part of the host role is a finding.',
          'host', 'Listener set matches host function.'),
        step('Look for processes running from writable or temporary paths — /tmp, /var/tmp, /dev/shm. The known implant was /var/tmp/main, launched from a cron script that masqueraded as a log-sync utility.',
          'host', 'No execution from temporary directories.'),
        step('Check for deleted-but-running binaries: ls -l /proc/*/exe and look for "(deleted)". Running from an unlinked file is a deliberate anti-forensic choice.',
          'host', 'No deleted executables running.'),
      ],
      evidenceExpected: 'Listener and process inventory per host, with exceptions filed.',
    },
  ],
};

// ---------------------------------------------------------------------------

export function expandPlan(plan) {
  for (const phase of plan.phases) {
    for (const task of phase.tasks) {
      task.steps = STEPS[task.key] ?? defaultSteps(task);
      // Whether the procedure is bespoke or the generic loop, say which.
      task.stepsSource = STEPS[task.key] ? 'authored' : 'standard-loop';
    }
  }

  plan.phases.push(OT_FOUNDATIONS, OT_HUNT, LINUX_HUNT);

  // Normalise the added tasks to the same shape as imported ones.
  for (const phase of plan.phases.filter(p => p.source === 'expanded')) {
    for (const t of phase.tasks) {
      t.assignees = t.assignees ?? [];
      t.tools = t.tools ?? [];
      t.dataSources = t.dataSources ?? [];
      t.commands = t.commands ?? [];
      t.mitre = t.mitre ?? [];
      t.references = t.references ?? [];
      t.terrain = t.terrain ?? [];
      t.stepsSource = 'authored';
      t.ttpText = t.mitre.join(', ');
      t.analysis = t.analysis ?? '';
      t.doNext = t.doNext ?? '';
      t.original = null;
    }
  }
  return plan;
}
