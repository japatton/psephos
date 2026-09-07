/**
 * Authored depth for ATT&CK for ICS, keyed by technique id.
 *
 * Generalised out of plans/expansion.mjs, which argues this ground well but
 * argues it against one estate's addresses. The bank outlives an engagement, so
 * what travels here is the reasoning — why a technique that is routine on IT is
 * dangerous on OT — and the terrain hints are roles rather than subnets.
 *
 * Two rules run through every entry, and they are the reason this file reads
 * differently from enterprise.mjs:
 *
 *   Everything is passive. Active scanning of a controller is a recognised
 *   cause of process upset, so a command that probes a PLC is not a hunting
 *   technique here, it is the incident. Every command below reads a capture or
 *   a log that already exists. test/bank.test.js enforces this rather than
 *   trusting it.
 *
 *   The population is fixed. An IT estate gains and loses hosts hourly; a
 *   control segment gains one when somebody installs equipment, which is a
 *   planned event you can go and ask about. That is what makes diffing against
 *   a baseline the highest-value thing an OT hunter does, and it is why almost
 *   every entry here ends up comparing against one.
 *
 * Three of the ids the OT doctrine used to name — T0855, T0812, T0857 — were
 * revoked upstream into the T16xx series. The live numbers are used here and
 * plans/expansion.mjs has been migrated to match; store/coverage.js reports a
 * dead id wherever a plan still carries one, which is how these were found.
 */
const step = (text, tooling, expect) => ({ text, tooling, expect, source: 'bank' });

/* Passive collection is the precondition for everything else in this file. */
const PASSIVE = ['Zeek', 'Arkime', 'tcpdump'];

/**
 * Who stands behind an entry.
 *
 * `authored` means a person on this engagement wrote the argument and it was
 * reviewed against this estate. `drafted` means it was written here from
 * general practice and nobody has checked it against anything. Both beat a
 * stub; only one of them is tradecraft, and after a few weeks nothing else
 * distinguishes them.
 *
 * Stamped by a wrapper rather than repeated on every entry, so the file itself
 * says which block is which and a drafted entry cannot quietly acquire the
 * flattering value by being edited next to an authored one.
 */
const authored = (m) => Object.fromEntries(
  Object.entries(m).map(([id, d]) => [id, { ...d, provenance: 'authored' }]));

/*
  Generalised out of plans/expansion.mjs, which a person on this engagement
  wrote and which was reviewed against this estate.
*/
export const overlays = authored({
  // --- seeing anything at all -------------------------------------------------------

  T0842: {
    intent:
      'You cannot hunt what you cannot see, and on OT you may only watch. The failure this '
      + 'guards against is not missing traffic but mis-parsing it: a sensor logging Modbus as '
      + 'generic TCP on port 502 produces a capture that looks complete and answers no question '
      + 'worth asking. Establish that the industrial protocols are being decoded as themselves '
      + 'before any task downstream claims a negative result, because otherwise every one of '
      + 'those negatives is a blind spot wearing the clothes of a finding.',
    tools: PASSIVE,
    dataSources: ['Zeek modbus.log', 'Zeek conn.log', 'span/tap placement notes', 'sensor inventory'],
    terrain: ['control segments', 'the IT/OT boundary'],
    commands: [
      'ls -l $(zeek-config --logdir 2>/dev/null || echo /opt/zeek/logs/current)',
      'zeek-cut -d ts id.orig_h id.resp_h id.resp_p proto < conn.log | sort | uniq -c | sort -rn | head -40',
    ],
    steps: [
      step('Find out which segments the tap actually covers before trusting any absence. A tap on the OT uplink sees IT-to-OT traffic and can miss controller-to-controller traffic inside a segment entirely.',
        'Zeek · sensor inventory', 'A written statement of what is and is not in view, per segment.'),
      step('Confirm the industrial protocols are being parsed rather than counted. If modbus.log is absent, Modbus is invisible as Modbus no matter how much you capture — and the same holds for MQTT, BACnet and DNP3.',
        'Zeek', 'A protocol log per protocol you intend to hunt, or a named gap.'),
      step('File each gap as a finding in its own right. A segment nobody can see is a fact about the estate, not a footnote about the hunt, and it is the thing the site can actually fix.',
        'Psephos · Evidence', 'One filed record per unmonitored segment.'),
      step('Say which downstream tasks depend on the coverage you just established, so a later negative result carries the caveat with it instead of losing it.',
        'Psephos · Plan', 'Dependent tasks annotated or re-scoped.'),
    ],
    evidenceExpected:
      'A per-segment statement of what the sensor sees and which protocols are decoded, and a filed finding for each gap.',
    doNext:
      'Any OT task depending on a protocol that is not being parsed is marked unrunnable before somebody works it and reports silence.',
  },

  T0846: {
    intent:
      'Discovery on a control segment does not look like discovery on IT, because the normal '
      + 'traffic does not look like IT traffic. A real master polls a fixed set of controllers on '
      + 'a metronome; a survey touches many devices once each and moves on. That shape is obvious '
      + 'in a capture and almost invisible in a per-device view, which is why this is hunted '
      + 'across the segment rather than device by device.',
    tools: PASSIVE,
    dataSources: ['Zeek conn.log', 'Zeek modbus.log', 'boundary firewall log'],
    terrain: ['control segments'],
    commands: [
      "zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | awk '$3==502||$3==1883||$3==47808||$3==20000' | sort -u",
      "zeek-cut id.orig_h id.resp_h < conn.log | sort | uniq -c | awk '$1<4' | head -40",
    ],
    steps: [
      step('Diff the set of addresses speaking each control protocol against the baseline. The population is fixed by construction, so a new speaker is anomalous before you know anything else about it.',
        'Zeek', 'An empty diff, or a name to go and ask about.'),
      step('Look for one source reaching many controllers with few connections each. Fan-out is the signature; volume is not, and a survey can be quieter in total bytes than a single legitimate poller.',
        'Zeek · Arkime', 'No fan-out pattern, or one source identified.'),
      step('Check the boundary log for the same shape arriving from IT. Discovery usually starts on the side of the house where the adversary already is.',
        'Firewall log · Zeek', 'Boundary crossings accounted for.'),
      step('Before escalating, ask whether an integrator or a commissioning task was scheduled. In OT this is a cheap question with a real chance of being the answer.',
        'Psephos · Comms', 'A recorded answer from a named person.'),
    ],
    evidenceExpected: 'The current speaker set per protocol, diffed against baseline, with each addition explained or filed.',
    doNext: 'An unexplained speaker on a control protocol is a finding regardless of what it did next.',
  },

  T0885: {
    intent:
      'Control protocols are identified by port far more than by content, and that cuts both '
      + 'ways: it makes a baseline cheap to build, and it makes a familiar port a good place to '
      + 'hide. The question is not whether traffic is on 502 or 1883 but whether what is on it '
      + 'behaves like the protocol it claims — a session that stays open for hours on a port '
      + 'whose protocol is request-response is worth more attention than an unfamiliar port ever '
      + 'was.',
    tools: PASSIVE,
    dataSources: ['Zeek conn.log', 'Zeek modbus.log', 'Zeek mqtt.log'],
    terrain: ['control segments', 'the IT/OT boundary'],
    commands: [
      "zeek-cut id.resp_p service duration orig_bytes resp_bytes < conn.log | sort -k3 -rn | head -40",
      "zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | awk '$4==\"-\"' | sort -u | head -40",
    ],
    steps: [
      step('List every session on a control port whose analyser could not identify the protocol. On a segment this stable that list should be empty, and each entry is a question.',
        'Zeek', 'An empty unparsed list, or a session to explain.'),
      step('Compare session duration and byte ratio against the baseline for that protocol. Control traffic is machine-generated and boringly regular; anything with a human or a tunnel behind it is not.',
        'Zeek · Arkime', 'Sessions consistent with the protocol they run on.'),
      step('Check both directions across the boundary. A control port used outbound from OT toward IT or beyond is a different and worse finding than the same port used inbound.',
        'Zeek', 'Direction stated for every boundary-crossing control session.'),
    ],
    evidenceExpected: 'A per-port session profile against baseline, and every unparsed session on a control port accounted for.',
    doNext: 'A long-lived or high-volume session on a request-response control port goes to the lead before the queue is finished.',
  },

  // --- getting in, and across ----------------------------------------------------------

  T0886: {
    intent:
      'Almost every OT intrusion has to cross the IT/OT boundary, which makes that boundary both '
      + 'the chokepoint worth watching and the shortest path to an answer. The list of flows '
      + 'crossing it should be short and boring, and the value of this task is that a short '
      + 'boring list can be read by a person in an afternoon — there are very few places left in '
      + 'security where that is true.',
    tools: [...PASSIVE, 'Firewall log'],
    dataSources: ['boundary firewall log', 'Zeek conn.log', 'jump host session logs'],
    terrain: ['the IT/OT boundary', 'engineering workstations'],
    commands: [
      "zeek-cut ts id.orig_h id.resp_h id.resp_p service < conn.log | sort -u",
      "zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | awk '$3==22||$3==3389||$3==5900' | sort -u",
    ],
    steps: [
      step('Enumerate every flow that crossed from IT into a control segment in the window, by source, destination and port. Read the whole list rather than sampling it; it is short for a reason.',
        'Firewall log · Zeek', 'A complete boundary-crossing inventory.'),
      step('Treat any IT host reaching a control protocol directly as a finding regardless of what it did. Control traffic should originate from HMIs and engineering stations, not from a file server or a workstation.',
        'Zeek', 'Every control-protocol source is a device whose job it is.'),
      step('Cross-reference the crossing list against hosts already known to be compromised in this engagement. If any of them has ever spoken to OT, that is the pivot and it is the most important thing you will find.',
        'Psephos · Evidence', 'An explicit stated answer, yes or no, on whether compromise reached OT.'),
      step('Check remote-access services on the OT side specifically — SSH, RDP, VNC. These are how the boundary is crossed legitimately, which is exactly why they are how it is crossed otherwise.',
        'Zeek · host logs', 'Every remote session attributed to a person and a change.'),
    ],
    evidenceExpected:
      'A boundary-crossing inventory, and an explicit finding on whether any known-compromised host reached a control segment.',
    doNext:
      'A confirmed IT-to-OT pivot stops being a hunt task and becomes an incident: notify the lead before continuing.',
  },

  T0866: {
    intent:
      'The unglamorous devices are the ones worth checking. Cameras, badge readers and video '
      + 'recorders are general-purpose Linux boxes that nobody patches, sitting on a segment that '
      + 'reaches the rest of OT, and an adversary will treat them as the servers they are rather '
      + 'than as the appliances the site thinks they are. They also fail quietly: nobody notices '
      + 'a camera doing something unusual, because nobody watches the camera.',
    tools: PASSIVE,
    dataSources: ['Zeek conn.log', 'Zeek http.log', 'Zeek ssl.log', 'device firmware inventory'],
    terrain: ['camera and physical-security segments', 'building automation'],
    commands: [
      "zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | grep -v ':554' | sort -u | head -40",
      "zeek-cut id.orig_h server_name < ssl.log | sort -u | head -40",
    ],
    steps: [
      step('Establish what each appliance is supposed to talk to, then look for anything else. A camera should reach its recorder and essentially nothing; a badge reader should reach its controller.',
        'Arkime', 'A per-device flow summary matching its stated function.'),
      step('Look specifically for the traffic these devices have no business generating: SSH outbound, HTTP to unfamiliar hosts, DNS. They are Linux, and an adversary who lands there will use them as such.',
        'Zeek', 'Appliances speak their own protocol and little else.'),
      step('Check the aggregation point — the recorder, the controller, the historian. It reaches everything by design, which makes it both the best pivot and the best place to collect from.',
        'Arkime', 'No unexplained bulk egress from any aggregator.'),
      step('Record firmware versions against known-vulnerable lists as a finding, not as a fix. Patching these is a site decision with an outage attached, and the hunt owes them the fact, not the remediation.',
        'Psephos · Evidence', 'A filed record of exposure per device class.'),
    ],
    evidenceExpected: 'Per-device flow summaries, an aggregator egress check, and filed firmware exposure.',
    doNext: 'An appliance with an unexplained outbound session is treated as a compromised host, not as a misconfiguration, until shown otherwise.',
  },

  'T1694.001': {
    intent:
      'OT devices ship with vendor credentials and they frequently survive commissioning, because '
      + 'changing them means touching a running process and nobody wants to be the person who did '
      + 'that. The result is an estate where the most valuable credential in the building is in a '
      + 'manual on the internet. This is worth hunting even when nothing has used them, because '
      + 'the finding is actionable during a planned outage and useless during an incident.',
    tools: [...PASSIVE, 'host logs'],
    dataSources: ['HMI and broker auth logs', 'Zeek conn.log', 'vendor documentation'],
    terrain: ['HMIs', 'brokers and historians', 'appliances'],
    commands: [
      "zeek-cut id.orig_h id.resp_h id.resp_p user < conn.log 2>/dev/null | sort -u | head -40",
      'grep -Ei "accepted|failed" /var/log/auth.log | tail -50',
    ],
    steps: [
      step('Establish which accounts exist on each HMI, broker and appliance from what is already collected, rather than by authenticating to them. Logging in to check is a change to a production device.',
        'host logs · Psephos · Characterization', 'An account inventory per device class.'),
      step('Check whether the broker or the historian accepts anonymous connections. Several common brokers default to it, and an anonymous subscriber is an unauthenticated tap on the process.',
        'host logs · Arkime', 'Anonymous access disabled, or a filed finding.'),
      step('Look for successful authentications from sources that are not the device that normally manages it. A vendor account used from a workstation is the shape worth chasing.',
        'host logs · Zeek', 'Each administrative session attributed.'),
      step('File surviving default credentials as a finding even where nothing has used them. It is a real exposure and it can only be fixed on the site\'s schedule, so it needs to be on their list now.',
        'Psephos · Evidence', 'A filed record per device carrying vendor credentials.'),
    ],
    evidenceExpected: 'An account inventory per device class, and a filed finding for every surviving default or anonymous access.',
    doNext: 'Nothing is remediated during the hunt. Defaults go to the site with the outage window they would need.',
  },

  // --- effect on the process ------------------------------------------------------------

  'T1692.001': {
    intent:
      'The highest-consequence event on the estate: somebody told a controller to change the '
      + 'process. In IT the adversary wants data and volume is a signal; here a single well-formed '
      + 'write matters more than a thousand reads, and it is indistinguishable from legitimate '
      + 'control except by who sent it and when. That is the whole hunt — not finding writes, but '
      + 'attributing every one of them.',
    tools: ['Zeek modbus.log', 'Arkime'],
    dataSources: ['Zeek modbus.log', 'Zeek dnp3.log', 'HMI application logs', 'shift and change records'],
    terrain: ['controllers', 'HMIs'],
    commands: [
      "zeek-cut ts id.orig_h id.resp_h func < modbus.log | sort | uniq -c | sort -rn",
      "zeek-cut ts id.orig_h id.resp_h func < modbus.log | grep -E 'WRITE|_COIL|_REGISTER'",
    ],
    steps: [
      step('Split observed function codes into reads and writes. Reads are the polling traffic and are almost all of it; the writes are the population worth reading one by one.',
        'Zeek modbus.log', 'A clean read/write split per controller.'),
      step('Attribute every write to a source and check it against the baselined master. A write from the usual HMI inside a shift may be routine; the same write from anywhere else, or at 03:00, is not.',
        'Zeek', 'Each write attributed to a known master, or filed.'),
      step('Check the diagnostic function codes as carefully as the write codes. Restart Communications Option is a denial-of-service primitive dressed as a diagnostic, and it will not look like an attack in a summary by code.',
        'Zeek', 'No unexpected diagnostic traffic.'),
      step('If you find a write you cannot attribute, do not undo it. File it, tell the lead, and let the process owners decide — reverting a setpoint blind can be more dangerous than the change was.',
        'Psephos · Evidence', 'A filed record and a notified lead.'),
    ],
    evidenceExpected: 'Every control write in the window, each attributed to a known master or filed.',
    doNext:
      'An unattributed write is an incident, not a finding. It goes to the lead and to the process owner immediately, and nobody reverts it on their own judgement.',
  },

  T0836: {
    intent:
      'A parameter change is quieter than a command and lasts longer. Nothing alarms, the process '
      + 'keeps running, and the setpoint it is running to is no longer the one the engineers '
      + 'chose — which is why this is hunted by comparing against a recorded baseline rather than '
      + 'by looking for anomalies. Without a baseline of what the values should be, a changed '
      + 'setpoint and a correct one are the same number on a screen.',
    tools: ['Zeek modbus.log', 'Arkime'],
    dataSources: ['Zeek modbus.log', 'historian trends', 'engineering setpoint records'],
    terrain: ['controllers'],
    /*
      Base Zeek's modbus.log carries ts, uid, the connection tuple, func and
      exception — not the register address. Address-level detail needs
      policy/protocols/modbus/track-memmap.zeek, which writes its own
      modbus_register_change.log; a command reading `address` off the base log
      returns nothing and reads like an empty result rather than a missing
      script. So the first command works everywhere and the second says what it
      depends on.
    */
    commands: [
      "zeek-cut ts id.orig_h id.resp_h func < modbus.log | grep -Ei 'write' | head -40",
      "zeek-cut ts id.orig_h id.resp_h register new_val < modbus_register_change.log  # needs track-memmap.zeek",
    ],
    steps: [
      step('Get the engineering record of what the setpoints are supposed to be before looking at the wire. Without it this task cannot produce a finding, only a list of numbers.',
        'Site engineer · Psephos · Comms', 'A recorded, dated set of intended values.'),
      step('Read the register addresses written to, not just the fact of the write. A write to a holding register carrying a limit or an alarm threshold is a different event from one carrying a command — and if the sensor runs base Zeek only, say so, because the address is not in modbus.log and the absence is a coverage gap rather than a clean result.',
        'Zeek modbus_register_change.log', 'Each write mapped to what that address controls, or the gap stated.'),
      step('Compare against historian trends across the same window. A parameter changed and changed back leaves nothing on the wire at the time you look, and a trend will still show the excursion.',
        'Historian', 'Trend and wire agree, or a window to investigate.'),
      step('Record the current parameter set as a baseline so the next person can answer this in minutes rather than reconstructing it.',
        'Psephos · Evidence', 'A filed baseline record per controller.'),
    ],
    evidenceExpected: 'Intended versus observed parameters per controller, and a filed baseline for next time.',
    doNext: 'A divergence goes to the process owner with the trend attached; the hunt does not decide which value is correct.',
  },

  T0831: {
    intent:
      'Manipulation of control is the objective the rest of the ICS matrix serves, and it is the '
      + 'one technique here that is defined by its effect rather than its mechanism. Hunt it by '
      + 'asking whether the process did anything it was not told to do, which means talking to the '
      + 'people who run it — a hunter reading captures alone can see every command on the wire and '
      + 'still not know that the outcome was wrong.',
    tools: ['Zeek modbus.log', 'Arkime', 'Historian'],
    dataSources: ['historian trends', 'operator logs', 'alarm history', 'Zeek modbus.log'],
    terrain: ['controllers', 'HMIs'],
    commands: [],
    steps: [
      step('Ask the operators what the process has done that surprised them in the window, before analysing anything. They notice excursions that no log names, and the conversation costs ten minutes.',
        'Site operator · Psephos · Comms', 'A recorded list of unexplained process behaviour, possibly empty.'),
      step('For each surprise, establish whether a command on the wire accounts for it. A commanded change that surprised the operator is a process or comms problem; an uncommanded one is this technique.',
        'Zeek · Historian', 'Each excursion matched to a command, or not.'),
      step('Check the alarm history for suppressed or acknowledged alarms around the same window. An adversary who can change control can usually also stop you hearing about it.',
        'Alarm history · HMI logs', 'Alarm behaviour consistent with the trend.'),
      step('Escalate anything safety-relevant immediately rather than finishing the queue first. This is the one place in a hunt where the reporting latency itself is a risk.',
        'Analyst · Psephos · Comms', 'Escalation path exercised if anything is found.'),
    ],
    evidenceExpected: 'A stated answer on whether the process behaved as commanded, with the operator conversation recorded.',
    doNext: 'Anything safety-relevant goes up immediately and in person, not as a filed record somebody reads tomorrow.',
  },

  T0832: {
    intent:
      'An HMI is the operator\'s sense of what the process is doing. Compromise it and a dangerous '
      + 'process can be made to look normal, which turns the operator from a defence into part of '
      + 'the attack. The detection has to compare two things neither of which is suspicious alone: '
      + 'what the screen says and what the controller is actually reporting on the wire. From '
      + 'either side by itself this is invisible.',
    tools: ['Zeek modbus.log', 'host logs', 'Kibana'],
    dataSources: ['Zeek modbus.log', 'HMI host logs', 'HMI application and project files', 'screenshots or operator report'],
    terrain: ['HMIs'],
    commands: [
      'journalctl -u ssh --since "7 days ago" | tail -50',
      'find /opt /srv /var/lib -newermt "-7 days" -type f 2>/dev/null | head -40',
    ],
    steps: [
      step('Hunt the HMI as the general-purpose host it is: sessions, privilege use, new processes, and changes under the application and project directories. Most HMIs on a modern estate are ordinary Linux or Windows boxes.',
        'auth.log · journald · Sysmon', 'A session and change history per HMI.'),
      step('Compare displayed values against polled register values for the same instant. A divergence between the operator view and the wire is manipulation of view and there is no other way to see it.',
        'Zeek modbus.log · operator', 'Displayed values match polled values.'),
      step('Check the project file and its timestamps. Changing what a screen maps to is quieter and more durable than changing what it currently shows.',
        'host logs', 'No unexplained project change, or one filed.'),
      step('Treat any unexplained change on a safety-related HMI — fire, gas, emergency shutdown — as safety-relevant and escalate before continuing.',
        'Analyst', 'Escalation path exercised if anything is found.'),
    ],
    evidenceExpected: 'Per-HMI session and change history, and an explicit stated view-versus-wire comparison.',
    doNext: 'A confirmed divergence is an incident. The operator must be told their screen is not trustworthy before anything else happens.',
  },

  T0882: {
    intent:
      'Operational information is worth stealing before it is worth acting on: process layouts, '
      + 'setpoints, alarm lists and video tell an adversary what the plant does and where it is '
      + 'fragile. This is the technique that precedes the ones that matter, which makes it the '
      + 'earliest place a hunt can catch an intrusion — and it leaves ordinary egress evidence, '
      + 'unlike almost everything else in this matrix.',
    tools: PASSIVE,
    dataSources: ['Zeek conn.log', 'Zeek files.log', 'broker subscription state', 'aggregator logs'],
    terrain: ['historians and brokers', 'video and physical security', 'engineering workstations'],
    commands: [
      "zeek-cut id.orig_h id.resp_h resp_bytes < conn.log | sort -k3 -rn | head -30",
      "zeek-cut ts id.orig_h id.resp_h mime_type total_bytes < files.log | sort -k5 -rn | head -30",
    ],
    steps: [
      step('Find the aggregation points first — historian, broker, video recorder, engineering workstation. They hold the whole picture, which is what makes them worth one visit instead of many.',
        'Psephos · Network Map', 'A named list of aggregators.'),
      step('Check subscription and query patterns on the broker or historian. A client subscribed to a wildcard topic is collecting everything, which is rarely what a purpose-built device does.',
        'Arkime · broker state', 'No wildcard or unexplained subscriber.'),
      step('Look for bulk egress from each aggregator, in either direction across the boundary. This is one of the few OT techniques that produces a byte count large enough to sort by.',
        'Zeek · Arkime', 'No unexplained bulk transfer.'),
      step('Check engineering workstations for project archives leaving. A plant\'s control project is the most useful single file an adversary can take from it.',
        'Zeek files.log · host logs', 'No project archive egress, or a filed finding.'),
    ],
    evidenceExpected: 'A client-and-topic table for each aggregator, and an egress check per aggregation point.',
    doNext: 'Confirmed operational-information theft raises the assessed intent of the whole intrusion, and the plan should be re-weighted toward the process rather than the network.',
  },

  // --- durable changes ------------------------------------------------------------------

  T0889: {
    intent:
      'Changing the logic outlasts changing a value and is far harder to spot afterwards. A '
      + 'setpoint reverts at the next shift handover; a modified program keeps doing what it was '
      + 'told through every restart, and the operator sees a controller behaving exactly as its '
      + 'program says it should. Almost no site records program hashes, which means the honest '
      + 'output of this task is often a baseline rather than a finding — and that baseline is what '
      + 'makes the question answerable next time.',
    tools: [...PASSIVE, 'host logs'],
    dataSources: ['engineering software access logs', 'controller program files', 'Zeek conn.log'],
    terrain: ['controllers', 'engineering workstations'],
    commands: [
      'sha256sum /opt/*/st_files/* /var/lib/*/programs/* 2>/dev/null',
      'find / -name "*.st" -o -name "*.acd" -o -name "*.ap1[45]" 2>/dev/null | head -30',
    ],
    steps: [
      step('Establish whether the controllers give you host-side evidence at all. Soft-PLCs on a general-purpose OS leave access logs and file timestamps that a hardware controller never would, and the whole approach depends on which you have.',
        'host logs', 'A stated answer on what evidence exists per controller.'),
      step('Look for the traffic shape of a program download even where you cannot decode it: a long transfer to the controller followed by a restart, quite unlike steady register polling.',
        'Zeek · Arkime', 'No transfer-then-restart pattern.'),
      step('Check engineering software access logs and program file timestamps against the change record. A logic change is a planned event on a working site, so the record should account for it.',
        'host logs · change records', 'Every change matched to an authorised one.'),
      step('Record the current program hash for every controller now, whatever you found. It costs minutes and it converts this question from an argument into a comparison for everyone who asks it after you.',
        'Psephos · Evidence', 'One filed hash per controller, as a baseline record.'),
    ],
    evidenceExpected: 'Program hashes filed for every controller, and any transfer-then-restart pattern investigated.',
    doNext:
      'A suspected logic change is not verified by uploading the program to compare — that is a write to a running controller. It goes to the process owner with the evidence you already have.',
  },

  'T1693.001': {
    intent:
      'Firmware is the most durable foothold available on the estate and the least likely to be '
      + 'looked at. It survives reimaging, reconfiguration and replacement of everything above it, '
      + 'and on most controllers there is no way to verify it that does not involve taking the '
      + 'device out of service. That asymmetry is the point: hunt for the update rather than the '
      + 'artefact, because the moment of change is visible on the wire and the result is not.',
    tools: [...PASSIVE, 'host logs'],
    dataSources: ['Zeek conn.log', 'Zeek files.log', 'vendor advisories', 'maintenance records'],
    terrain: ['controllers', 'appliances', 'building automation'],
    commands: [
      "zeek-cut ts id.orig_h id.resp_h total_bytes mime_type < files.log | sort -k4 -rn | head -30",
    ],
    steps: [
      step('Get the maintenance record before looking. Firmware updates are planned, scheduled and documented on a working site, so the baseline for this technique is a piece of paper rather than a capture.',
        'Site engineer · Psephos · Comms', 'A dated list of authorised firmware activity.'),
      step('Look for large transfers to a controller or appliance followed by a reboot or a gap in polling. That shape is the update, and it is visible even where the payload is not.',
        'Zeek · Arkime', 'Every such event matched to a maintenance record.'),
      step('Check reported firmware versions where the device already publishes them into an inventory or a monitoring system. Reading what has been collected is safe; interrogating the device is not.',
        'Psephos · Characterization', 'A version inventory from existing collection.'),
      step('Where a device offers no evidence either way, record that as the finding. "This class of controller cannot be verified without an outage" is a real and useful thing to hand a site.',
        'Psephos · Evidence', 'An explicit statement of what cannot be checked and why.'),
    ],
    evidenceExpected:
      'Firmware activity matched against maintenance records, and an explicit statement of which devices cannot be verified passively.',
    doNext:
      'Suspected firmware modification is an incident and a vendor conversation, not a hunt task. Nothing gets reflashed on a hunter\'s judgement.',
  },
});
