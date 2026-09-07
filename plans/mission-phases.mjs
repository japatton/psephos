/**
 * Mission-phase frame over the hunt plan.
 *
 * The uploaded HuntPlan.xlsx (P1-P5) and the OT/Linux expansion (P6-P8) run on
 * a kill-chain axis: baselining, initial access, execution, escalation, exfil.
 * The frame this file encodes runs on a different axis entirely — the mission
 * phases a defensive cyber team is tasked in: prepare, characterize, hunt,
 * clear, enable/harden.
 *
 * They are not competing views. Everything in P1-P8 happens INSIDE mission
 * phase M2. So this file deliberately does not restate the hunt; it adds the
 * two ends the plan never had — getting the sensors and scans right before the
 * hunt, and handing hardening back to the mission partner after it — plus the
 * actor-driven hunt tasks that APT29 and APT33 imply and P1-P8 does not cover.
 *
 * THE ADVERSARY. A named exercise construct typically simulates real actors;
 * the worked example throughout is APT29
 * (Russia, SVR — stealth, identity abuse, long dwell) and APT33 (Iran —
 * energy and defense targeting, destructive endgame). Where those two
 * converge is where this plan is weighted, and they converge hard on password
 * spraying. That drives M2 and it drives the M4 hardening priorities.
 *
 * KEYS. Tasking of this shape numbers its tactical tasks TT1..TTn and restarts
 * the numbering in each section, so the literal key "TT1" would appear eight
 * times. task_key is NOT NULL UNIQUE, so keys here are namespaced
 * M<phase>-tt<n>-<slug>. The TT number stays in the title because that is how
 * a team briefs it.
 *
 * These phases and objectives are a worked example, not anybody's tasking:
 * write your own from the document you were actually given, and keep the key
 * scheme so two sections cannot collide.
 *
 * CROSS-REFERENCES. Several characterization tasks restate work P1-P8 already
 * tracks. Those are carried at priority "low" with an intent that names the
 * task actually holding the work, so the doctrinal list stays complete for
 * briefing without splitting completion across two entries.
 *
 * References: MITRE ATT&CK (enterprise and ICS), NIST SP 800-82r3, CISA
 * advisories on APT29 identity abuse and APT33/Peach Sandstorm spraying.
 */

const step = (text, tooling, expect) => ({ text, tooling, expect, source: 'expanded' });

/**
 * A doctrinal TT already tracked elsewhere. Listed so the frame is whole.
 *
 * Still carries a step, because "every task carries steps" is an invariant of
 * this plan and a task that tells you nothing about how to do it is exactly
 * what that invariant exists to prevent. For a cross-reference the how is
 * "go and do it over there", which is worth one line.
 */
const xref = (key, tt, title, holder, note) => ({
  key, title: `${tt} — ${title}`,
  source: 'expanded', priority: 'low',
  intent: `Tracked under ${holder}. Complete it there; this entry exists so the ` +
    `tactical task list is whole for briefing.${note ? ' ' + note : ''}`,
  steps: [
    step(`Do not work this entry. Open ${holder} and work it there, so completion and evidence stay in ` +
      `one place.${note ? ' ' + note : ''}`,
    'Psephos · Plan', `${holder} carries the status and the evidence.`),
  ],
  evidenceExpected: `Cross-reference only. Evidence lands on ${holder}.`,
});

// ---------------------------------------------------------------------------
// M0 — Preparation of the environment
// ---------------------------------------------------------------------------

const M0 = {
  key: 'M0',
  name: 'M0 · Prepare the environment',
  source: 'expanded',
  intent:
    'Tactical Objective 1: employ the hunt platform effectively across the whole estate you were ' +
    'asked to defend. MOE1 — visibility into horizontal and vertical communications on all mission-critical ' +
    'paths. MOE2 — visibility into malicious activity on mission-critical hosts and anything directly ' +
    'connected to them. MOE3 — collection is employed without giving the adversary indications and ' +
    'warning. These are measures, not checkboxes: they are how the phase is judged, and the tasks below ' +
    'are what you actually do.',
  tasks: [
    {
      key: 'M0-tt1-network-sensors', title: 'TT1 — Employ and configure network sensors',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent: 'Sensor placement decides what the whole mission can see. A hunt cannot recover from a tap in the wrong place.',
      mitre: [], tools: ['Zeek', 'Suricata', 'Arkime'],
      terrain: ['enclave boundary routers', 'IT/OT boundary', 'each enclave core'],
      references: ['NIST SP 800-82r3 §6 (network monitoring in OT)'],
      steps: [
        step('Map every mission-critical path first, then place taps. Horizontal is peer-to-peer inside a segment; vertical is the path up through the boundary. MOE1 asks for both, and a sensor that only sees north-south traffic satisfies neither.',
          'Terrain map · Psephos', 'A tap list justified against the path map, not against convenience.'),
        step('On the OT side collect passively. SPAN or TAP only — no active discovery, no agent, no scan. This is a hard constraint, not a preference, and it is the same one P6-passive-collection sets.',
          'SPAN/TAP', 'OT visibility with zero packets injected.'),
        step('Verify the sensor sees both directions of a known conversation before you trust the segment. An asymmetric tap silently halves your evidence and looks identical to a quiet network.',
          'Zeek conn.log', 'Both directions present for a known flow.'),
        step('MOE3: confirm collection is passive from the adversary\'s point of view. Active scanning from an address the hunt team owns is an indication and warning that you are there.',
          'Arkime', 'No probe traffic from the team\'s own addresses in the capture.'),
      ],
      evidenceExpected: 'A tap list mapped to mission-critical paths, with coverage confirmed bidirectionally.',
    },
    {
      key: 'M0-tt2-endpoint-agents', title: 'TT2 — Employ and configure endpoint host agents',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent: 'IT estate only. Agents do not go on PLCs, HMIs or field devices, and pretending otherwise leaves this task permanently open.',
      mitre: [], tools: ['winlogbeat', 'Velociraptor', 'auditd'],
      terrain: ['every IT enclave', 'OT segments (agents excluded)'],
      steps: [
        step('Scope the deployment explicitly: which hosts get an agent, which cannot take one, and why. The OT estate is almost entirely Ubuntu appliances and embedded controllers — most of it is in the second list.',
          'Asset list · Psephos map', 'A written scope with the exclusions named.'),
        step('For hosts that cannot take an agent, say what covers them instead. Usually that is network sensor coverage plus whatever the device logs natively. An uncovered host is a finding, not an omission.',
          'Psephos · Evidence', 'Every excluded host has a named compensating source.'),
        step('KNOWN GAP: endpoint sensors on this range were deployed host-by-host DURING the intrusion. Record each host\'s sensor start time. Absence of telemetry before that timestamp is not absence of activity, and every conclusion drawn from this estate depends on knowing the line.',
          'winlogbeat · agent inventory', 'A per-host sensor start time you can cite.'),
      ],
      evidenceExpected: 'Agent coverage map, exclusions justified, per-host sensor start times recorded.',
    },
    {
      key: 'M0-tt3-verify-collection', title: 'TT3 — Confirm log type, volume and accuracy are sufficient',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'The most important task in M0 and the one most often waved through. On this range the answer is ' +
        'already partly known and it is bad: several event IDs the hunt plan depends on do not exist.',
      mitre: [], tools: ['Kibana', 'winlogbeat'],
      references: ['the mission briefing on known audit gaps'],
      steps: [
        step('Confirm the estate-wide audit gaps before anyone writes a query against them. Absent: 4625 failed logon, 4720 account created, 4728/4732/4756 group membership, 4698 scheduled task created, 4740 lockout, 4719 audit policy changed, 1102 log cleared.',
          'Kibana', 'The gap list confirmed by observation, not assumed from the brief.'),
        step('For each gap, write down the alternate source the team will use instead, and publish it. This is the deliverable that stops four separate analysts each rediscovering that 4720 is missing.',
          'Psephos · Comms', 'A published gap-to-alternate mapping.'),
        step('Confirm the winlogbeat duplication: every document appears under two agent ids. Halve raw counts unless a query explicitly de-duplicates, or every volumetric finding this week is wrong by a factor of two.',
          'Kibana', 'A de-duplication method agreed and written down.'),
        step('Spot-check accuracy, not just presence. Generate a known benign event on a known host and confirm it arrives, with the right timestamp and the right host attribution.',
          'Kibana', 'A round-trip you watched, on at least one host per segment.'),
      ],
      evidenceExpected: 'Confirmed gap list, published alternates, de-duplication method, one verified round-trip per segment.',
      doNext: 'Publish the gap-to-alternate mapping to the team channel before hunting starts.',
    },
    {
      key: 'M0-tt4-mip', title: 'TT4 — MIP configuration',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'Mission instrumentation platform stood up, reachable, and time-synchronised with the estate it observes.',
      mitre: [], tools: ['hunt platform'],
      steps: [
        step('Confirm time sync between the MIP and the mission partner estate. Timeline correlation is the entire product of a hunt, and a platform an hour out silently reorders the attack chain.',
          'NTP', 'Clock skew measured and under a second.'),
        step('Confirm retention covers the exercise window plus the pre-intrusion baseline period. Retention that starts when you deploy cannot answer "was this normal last week".',
          'hunt platform', 'Retention window stated and sufficient.'),
      ],
      evidenceExpected: 'MIP reachable, time-synced, retention window confirmed.',
    },
    {
      key: 'M0-tt5-dip', title: 'TT5 — DIP configuration',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'Deployable platform configured and its collection verified end to end.',
      mitre: [], tools: ['hunt platform'],
      steps: [
        step('Verify each configured collector actually delivers to the index, by observing a document arrive — not by reading the config back.',
          'Kibana', 'One observed document per collector.'),
      ],
      evidenceExpected: 'Each collector verified by an observed document.',
    },
    {
      key: 'M0-tt6-orm', title: 'TT6 — Complete operational risk management (ORM)',
      source: 'expanded', priority: 'high', team: 'Command',
      intent:
        'The gate on everything active this mission does. The specific decision it must record: whether ' +
        'active vulnerability scanning touches the OT segments. The M1V objective assumes it does, and ' +
        'on a control network that assumption can stop a process.',
      mitre: [], tools: [],
      terrain: ['OT segments', 'IT/OT boundary'],
      references: ['NIST SP 800-82r3 §3 (risk management for OT)'],
      steps: [
        step('Record the scanning decision explicitly, per segment. Active credentialed and uncredentialed scanning is routine on IT and hazardous on OT — legacy controllers have been knocked over by a discovery scan.',
          'ORM worksheet', 'A signed per-segment scanning decision.'),
        step('Read M1V-tt4 before signing. As written, that task routes systems that failed a credentialed scan into an uncredentialed scan — and the systems that fail credentialed scans are disproportionately the OT devices. The rule sends your most fragile assets to your most aggressive method.',
          'ORM worksheet', 'M1V-tt4 either carved out for OT or explicitly accepted with the mission partner.'),
        step('Agree the deconfliction path with the mission partner and white cell before anything active runs, and agree who can stop it.',
          'Comms', 'A named stop authority.'),
      ],
      evidenceExpected: 'Signed ORM with a per-segment active-scanning decision and a named stop authority.',
      doNext: 'M1V does not start until this is signed.',
    },
  ],
};

// ---------------------------------------------------------------------------
// M1 — Characterization
// ---------------------------------------------------------------------------

const M1_NETWORK = {
  key: 'M1N',
  name: 'M1 · Characterize — network',
  source: 'expanded',
  intent:
    'You cannot call something anomalous until you can say what normal was. Tasking of this shape marks ' +
    'these as examples; they are written here as real tasks because on this terrain they are the ones ' +
    'that matter. Weighted toward what APT29 and APT33 actually abuse: remote access, identity paths ' +
    'and egress.',
  tasks: [
    {
      key: 'M1N-tt1-ports-protocols-services', title: 'TT1 — Determine ports, protocols and services',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent: 'The PPS baseline is the reference every later "unexpected service" claim depends on.',
      mitre: ['T1046'], tools: ['Zeek', 'Arkime'],
      steps: [
        step('Build the observed PPS list from passive capture, per segment, before comparing it to any documented list. What the network does and what the documentation says it does are different artifacts, and the difference is itself a finding.',
          'Zeek conn.log', 'An observed PPS table per segment.'),
        step('Diff observed against the mission partner\'s documented PPS. Undocumented-but-present is the interesting column.',
          'Zeek', 'A reconciled diff with owners for each surprise.'),
        step('On OT segments expect a very short list — 502, 1883, 554, 47808 and management. A long tail there means something IT-shaped is living on a control network.',
          'Zeek', 'OT PPS list is short and explicable.'),
      ],
      evidenceExpected: 'Per-segment observed PPS table, diffed against documentation.',
    },
    {
      key: 'M1N-tt2-high-traffic', title: 'TT2 — Identify high traffic systems',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'Volume outliers are where both collection and exfiltration hide.',
      mitre: ['T1030'], tools: ['Zeek', 'Arkime'],
      steps: [
        step('Rank by bytes and by connection count separately. They surface different things: bytes finds bulk transfer, connection count finds beaconing and scanning.',
          'Zeek conn.log', 'Two ranked lists.'),
        step('Halve any count derived from winlogbeat — the duplicate-agent-id issue makes raw host-side counts double.',
          'Kibana', 'De-duplicated counts.'),
        step('Check the top talkers against role. A file server moving bulk data is its job; a workstation doing it is not.',
          'Psephos map', 'Each outlier explained by role or filed.'),
      ],
      evidenceExpected: 'Ranked talker lists with outliers attributed to role or filed.',
    },
    {
      key: 'M1N-tt3-intersystem-connections', title: 'TT3 — Identify common intersystem connections',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent:
        'The normal connection graph. This is the direct input to lateral movement hunting — an edge that ' +
        'was never there before is worth more than any single host indicator.',
      mitre: ['T1021'], tools: ['Zeek', 'Arkime'],
      steps: [
        step('Build the host-to-host edge set per segment and across the boundary. Record it; the Psephos map derives its connections from evidence, and this is the baseline that evidence is judged against.',
          'Zeek conn.log · Psephos map', 'A baseline edge set you can diff later.'),
        step('Pay attention to workstation-to-workstation edges. In a healthy estate they are rare, and APT29 lateral movement lives exactly there.',
          'Zeek', 'Peer-to-peer client edges enumerated and explained.'),
        step('Enumerate every edge crossing the IT/OT boundary and name the business reason for each. This overlaps P6-it-ot-boundary; record it once, there.',
          'Zeek', 'Boundary edges enumerated with owners.'),
      ],
      evidenceExpected: 'Baseline host-to-host edge set, with boundary crossings justified.',
    },
    {
      key: 'M1N-tt4-network-configs', title: 'TT4 — Collect network configurations, review and compare',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'Firewall and router configuration is where intent is written down. Compare it to what the traffic actually does.',
      mitre: ['T1016'], tools: ['Config review'],
      steps: [
        step('Collect running configs from firewalls and routers, including the boundary devices. Diff running against startup — a difference is an unsaved change somebody made and did not document.',
          'Config review', 'Running/startup diff per device.'),
        step('Find rules that permit more than the traffic requires, especially any-any and broad egress. Both simulated actors need egress; a permissive rule is their route out.',
          'Config review', 'Over-permissive rules listed for M4.'),
        step('Check for management interfaces reachable from user segments.',
          'Config review · Zeek', 'Management plane reachability documented.'),
      ],
      evidenceExpected: 'Configs collected, running/startup diffed, over-permissive rules listed for hardening.',
      doNext: 'Feed the over-permissive rule list to M4-tt3.',
    },
    {
      key: 'M1N-tt5-scan-connected-systems', title: 'TT5 — Scan for systems connected to the network',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'Discovery, subject to the M0-tt6 ORM decision. Passive on OT, active only where signed off.',
      mitre: ['T1046'], tools: ['Zeek', 'nmap (IT only, per ORM)'],
      steps: [
        step('Derive the OT device list passively from capture. Never scan a control segment to enumerate it.',
          'Zeek', 'OT inventory built without a single injected packet.'),
        step('On IT segments, scan only within the ORM decision, and time it so the mission partner is not surprised.',
          'nmap', 'Active discovery inside the signed scope.'),
      ],
      evidenceExpected: 'Connected-system inventory, method recorded per segment.',
    },
    {
      key: 'M1N-tt6-master-asset-list', title: 'TT6 — Generate master asset list',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent:
        'One authoritative list. The Psephos map already holds 181 reconciled hosts from the survey — ' +
        'this task is to confirm it is still the authority and to close the remaining unknowns.',
      mitre: ['T1018'], tools: ['Psephos map'],
      steps: [
        step('Work the "alive but unidentified" hosts down to zero or to a filed finding. An address that answers and that neither DNS nor AD can name is one of the strongest signals this map carries.',
          'Psephos map', 'Every alive-unidentified host named or filed.'),
        step('Reconcile any host the evidence found that the survey did not. Those are drawn as diamonds on the map for exactly this reason.',
          'Psephos map', 'No unexplained discovered hosts.'),
      ],
      evidenceExpected: 'Master asset list with zero unexplained alive-unidentified hosts.',
    },
    {
      key: 'M1N-tt7-nonstandard-processes', title: 'TT7 — Identify non-standard processes on the network',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'Protocol-level oddity: services speaking on ports that are not theirs, and tunnels inside permitted protocols.',
      mitre: ['T1571', 'T1572'], tools: ['Zeek', 'Suricata'],
      steps: [
        step('Look for protocol/port mismatches — Zeek names the service it actually observed, not the port number. TLS on 8443 is fine; SSH on 443 is a tunnel.',
          'Zeek conn.log service field', 'Mismatches enumerated.'),
        step('Check for long-lived connections with low, regular byte counts. That shape is a beacon regardless of which port carries it.',
          'Zeek · Arkime', 'Long-lived low-volume flows reviewed.'),
      ],
      evidenceExpected: 'Protocol/port mismatches and beacon-shaped flows reviewed.',
    },
    xref('M1N-tt8-verify-accounts', 'TT8', 'Verify user accounts (network view)',
      'P1-validate-administrative-account-baseline',
      'Note the 4720 and 4728/4732/4756 gaps: account and group changes cannot be reconstructed from Security logs on this range.'),
    {
      key: 'M1N-tt9-remote-access', title: 'TT9 — Analyze remote access and file transfer protocols',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent:
        'Weighted high because this is where both simulated actors enter and leave. APT29 favours valid ' +
        'accounts over legitimate remote services; APT33 has used web shells and staged transfer tooling.',
      mitre: ['T1133', 'T1021.001', 'T1021.004', 'T1105'], tools: ['Zeek', 'Arkime'],
      steps: [
        step('Enumerate every external-facing remote access path — VPN, RDP, SSH, and anything published through the boundary. Each one needs a named owner and a stated business reason.',
          'Zeek · config review', 'A complete external access inventory.'),
        step('Check which of those paths enforce MFA. The APT29 Microsoft intrusion succeeded against a legacy account that did not, and that is the single most repeatable lesson from this actor.',
          'Config review', 'MFA status per path, gaps listed for M4.'),
        step('Baseline file transfer: which hosts move files where, using what. Then look for transfer to destinations with no history — that is the exfil shape and it overlaps P5.',
          'Zeek files.log', 'Transfer baseline established.'),
      ],
      evidenceExpected: 'External access inventory with MFA status, and a file transfer baseline.',
      doNext: 'Feed MFA gaps to M4-tt3.',
    },
  ],
};

const M1_HOST = {
  key: 'M1H',
  name: 'M1 · Characterize — hosts',
  source: 'expanded',
  intent:
    'Host-side characterization. Most of this is already tracked in P1, P3, P4 and P8, so the entries ' +
    'below mostly point there — deliberately, so nobody works the same task in two places. What is not ' +
    'covered elsewhere is written out in full.',
  tasks: [
    xref('M1H-tt1-verify-accounts', 'TT1', 'Verify user accounts',
      'P1-validate-administrative-account-baseline'),
    xref('M1H-tt2-suspicious-processes', 'TT2', 'Identify non-standard / suspicious processes',
      'P8-process-network', 'For the Windows estate, pair it with P3.'),
    {
      key: 'M1H-tt3-scheduled-tasks', title: 'TT3 — Identify scheduled tasks',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'Written out rather than cross-referenced, because the obvious method does not work here. ' +
        '4698 (scheduled task created) is absent estate-wide, so the event-log approach that P3 assumes ' +
        'returns nothing and looks like a clean result.',
      mitre: ['T1053.005', 'T1053.003'], tools: ['Velociraptor', 'Kibana'],
      commands: [
        'Get-ChildItem C:\\Windows\\System32\\Tasks -Recurse -File',
        'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree" /s',
        'for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null; done',
        'systemctl list-timers --all',
      ],
      steps: [
        step('KNOWN GAP: do not hunt 4698. It is absent estate-wide. Any query built on it returns zero and that zero means nothing.',
          'Kibana', 'The gap acknowledged before the hunt, not after.'),
        step('Go to disk instead. Task definitions live as XML under C:\\Windows\\System32\\Tasks and are mirrored in the TaskCache registry tree. Compare file creation times against the host\'s sensor start time.',
          'Velociraptor', 'A task inventory per host, with creation times.'),
        step('Use Sysmon 11 (file create) under the Tasks directory as the closest available substitute for 4698 — it survives where the Security log does not.',
          'Kibana · Sysmon 11', 'Task creation events recovered from a different source.'),
        step('On Linux — most of this estate — cover cron, at, and systemd timers. Systemd timers are the ones teams forget, and a .timer unit is as good as a cron entry for persistence.',
          'Velociraptor · journald', 'cron, at and systemd timers all enumerated.'),
      ],
      evidenceExpected: 'Per-host scheduled task inventory built from disk and Sysmon 11, not from 4698.',
    },
    xref('M1H-tt4-persistence', 'TT4', 'Identify persistence on endpoints',
      'P8-persistence-sweep', 'Windows persistence is under P4-privilege-escalation-registry-run-keys and P4-privilege-escalation-wmi-event-subscription.'),
    {
      key: 'M1H-tt5-host-enumeration', title: 'TT5 — Host enumeration',
      source: 'expanded', priority: 'normal', team: 'Bravo',
      intent: 'Per-host ground truth: what is installed, what listens, who logs in, what runs at boot.',
      mitre: ['T1082'], tools: ['Velociraptor'],
      steps: [
        step('Collect installed software, listening sockets, local accounts and autoruns per host. Store it as the baseline — the value is in the diff a week from now, not in today\'s snapshot.',
          'Velociraptor', 'A stored per-host baseline.'),
        step('Prioritise the hosts that matter: domain controllers, the Exchange host, the file server, and anything with an edge on the IT/OT boundary.',
          'Psephos map', 'Mission-critical hosts enumerated first.'),
      ],
      evidenceExpected: 'Stored per-host baseline, mission-critical hosts first.',
    },
  ],
};

const M1_VULN = {
  key: 'M1V',
  name: 'M1 · Known vulnerabilities and exposures',
  source: 'expanded',
  intent:
    'Tactical Objective: identify known vulnerabilities and exposures. GATED ON M0-tt6 — nothing active ' +
    'runs against any segment until the ORM decision is signed. On OT the default is passive; see the ' +
    'warning on TT4 in particular.',
  tasks: [
    {
      key: 'M1V-tt1-systems-online', title: 'TT1 — Work with MP to ensure systems are online during scan',
      source: 'expanded', priority: 'normal', team: 'Command',
      intent: 'A scan window nobody told the mission partner about produces both bad data and bad relationships.',
      steps: [
        step('Agree the window with the mission partner and confirm which systems must stay untouched. Get it in writing in the team channel so the whole crew can see the boundaries.',
          'Comms', 'An agreed window with exclusions stated.'),
      ],
      evidenceExpected: 'Agreed scan window with named exclusions.',
    },
    {
      key: 'M1V-tt2-discovery-scan', title: 'TT2 — Run discovery scan',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'IT segments only unless the ORM says otherwise.',
      tools: ['Vulnerability scanner'],
      steps: [
        step('Confirm the target list matches the ORM scope exactly before launching. Scope creep in a scanner is measured in outages.',
          'Scanner config', 'Target list reconciled against the signed scope.'),
      ],
      evidenceExpected: 'Discovery results for the in-scope estate.',
    },
    {
      key: 'M1V-tt3-credentialed-scan', title: 'TT3 — Run credentialed scan',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'Credentialed results are far more accurate; the credential handling is the risk.',
      tools: ['Vulnerability scanner'],
      steps: [
        step('Use a dedicated scanning account, scoped to what the scan needs, and rotate it afterwards. A scanner credential is a domain-wide credential sitting in a config file.',
          'Scanner config', 'Dedicated account used and rotated.'),
      ],
      evidenceExpected: 'Credentialed results with coverage percentage stated.',
    },
    {
      key: 'M1V-tt4-uncredentialed-scan', title: 'TT4 — Uncredentialed scan of failed systems',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent:
        'READ BEFORE RUNNING. As written this task is backwards for this terrain. The systems that fail a ' +
        'credentialed scan are overwhelmingly the ones with no credential store and no agent — which on ' +
        'this estate means the OT devices. The rule therefore routes the most fragile assets to the most ' +
        'aggressive method available.',
      tools: ['Vulnerability scanner'],
      references: ['NIST SP 800-82r3 — active scanning cautions for OT'],
      steps: [
        step('Before scanning anything on the failed list, classify each entry as IT or OT. Do not treat the failed list as a homogeneous queue.',
          'Psephos map', 'The failed list split by estate.'),
        step('OT entries do not get an uncredentialed scan. Substitute passive identification from capture plus vendor advisories matched to the observed firmware. You lose precision and you keep the process running.',
          'Zeek · vendor advisories', 'OT exposures identified without active probing.'),
        step('IT entries proceed inside the ORM scope, throttled, with the stop authority reachable.',
          'Scanner', 'IT failures rescanned safely.'),
      ],
      evidenceExpected: 'Failed list split by estate; OT handled passively; IT rescanned in scope.',
      doNext: 'If the ORM did not carve OT out of this task, stop and raise it with the Mission Commander.',
    },
    {
      key: 'M1V-tt5-recurring-scans', title: 'TT5 — Set up recurring system scans',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'Recurrence multiplies whatever the scanning decision was, including a wrong one.',
      steps: [
        step('Schedule recurrence only for segments the ORM cleared for active scanning, and set it to a window the mission partner has agreed to. A recurring scan against OT is the ORM risk repeated on a timer.',
          'Scanner config', 'Recurrence limited to cleared segments.'),
      ],
      evidenceExpected: 'Recurring schedule limited to ORM-cleared segments.',
    },
    {
      key: 'M1V-tt6-monitor-scans', title: 'TT6 — Monitor scans daily',
      source: 'expanded', priority: 'normal', team: 'Alpha',
      intent: 'Watch for what the scan breaks as much as for what it finds.',
      steps: [
        step('Check daily for hosts that went unreachable during or after a scan window, especially anything on or adjacent to the boundary. That correlation is the early warning you were too aggressive.',
          'Psephos map · scanner', 'No scan-correlated availability loss.'),
      ],
      evidenceExpected: 'Daily scan health with availability correlation checked.',
    },
    {
      key: 'M1V-tt7-analyze-results', title: 'TT7 — Analyze results',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'Prioritise by what the simulated adversary would actually use, not by CVSS alone. Both actors ' +
        'reach in through remote access and identity; a medium on an internet-facing auth path outranks ' +
        'a critical on an isolated internal host.',
      steps: [
        step('Cross the vulnerability results against the M1N-tt9 external access inventory. Anything exploitable on a path that also lacks MFA is the top of the list.',
          'Scanner · M1N-tt9 output', 'A ranked list driven by reachability, not CVSS.'),
        step('Cross the results against hosts already carrying evidence on the Psephos map. A vulnerable host with a finding on it is a different conversation from a vulnerable host without one.',
          'Psephos map', 'Overlap of vulnerable and evidenced hosts identified.'),
      ],
      evidenceExpected: 'Ranked exposure list weighted by reachability and by existing evidence.',
    },
    {
      key: 'M1V-tt8-hardening-recommendations', title: 'TT8 — Make hardening recommendations to MP',
      source: 'expanded', priority: 'normal', team: 'Command',
      intent: 'The handoff into M4. Recommendations the mission partner cannot action are not recommendations.',
      steps: [
        step('Write each recommendation with the change, the risk of making it, and the risk of not. For OT include the maintenance window constraint — a patch that needs a process stop is a scheduling problem, not a technical one.',
          'Report', 'Actionable recommendations with both risks stated.'),
      ],
      evidenceExpected: 'Written recommendations delivered to the mission partner.',
    },
  ],
};

// ---------------------------------------------------------------------------
// M2 — Hunt
// ---------------------------------------------------------------------------

const M2 = {
  key: 'M2',
  name: 'M2 · Hunt',
  source: 'expanded',
  intent:
    'Tactical Objective 1: effectively hunt the assessed adversary. Objective 2: execute effective hunt ' +
    'operations against the mission partner network — MOE1 all adversary activity identified, MOE2 all ' +
    'cyber security issues highlighted, MOE3 adversary intent and capabilities fully characterized. ' +
    'Objective 3: hunt for anomalous activity. ' +
    'The bulk of the hunt is P1-P8; this phase adds the method, the quality controls, and the tasks the ' +
    'actor profile demands that the kill-chain plan does not cover. The worked example below is APT29 ' +
    '(stealth, identity abuse, long dwell) and APT33 (energy sector, destructive endgame).',
  tasks: [
    {
      key: 'M2-tt1-hunt-loop', title: 'TT1-TT8 — The hunt loop, run once per hypothesis',
      source: 'expanded', priority: 'high', team: '',
      intent:
        'Tactical Objective 1 lists eight tactical tasks that are not eight one-time tasks — they are one ' +
        'loop you run for every hypothesis. The plan UI already labels any task without authored steps ' +
        '"standard loop"; this is the definition of that loop. Do not tick it complete; use it.',
      mitre: [], tools: ['Psephos', 'Kibana', 'Zeek'],
      steps: [
        step('TT1 — Craft the hypothesis. State it so it can be wrong: "password spraying against the domain would appear as Kerberos pre-auth failures across many accounts from few sources." A hypothesis you cannot disprove is not one.',
          'Psephos · Evidence', 'A falsifiable statement written down.'),
        step('TT2 — Determine the TTPs the hypothesis implies. Pull them from the actor profile, not from imagination: APT29 for identity and stealth, APT33 for access and destruction.',
          'MITRE ATT&CK', 'A named technique list.'),
        step('TT3 — Identify data sources, and check them against the M0-tt3 gap list FIRST. If the canonical source is absent on this range, find the alternate before writing a query, not after it returns zero.',
          'M0-tt3 gap mapping', 'Sources confirmed present, or alternates chosen.'),
        step('TT4 — Craft the queries. Scope them to a time window and a host set; an unscoped query on a duplicated index is slow and wrong.',
          'Kibana', 'Queries written and scoped.'),
        step('TT5 — Run and analyse. Distinguish "no evidence found" from "no telemetry exists" every single time. On this range that distinction decides whether a negative result means anything.',
          'Kibana', 'A result with its confidence and its blind spots stated.'),
        step('TT6 — Brief the crew and element. TT7 — Brief the mission partner. TT8 — Document the finding in the Psephos so it enters the case file and the map.',
          'Psephos · Comms', 'A filed record and a briefed crew.'),
      ],
      evidenceExpected: 'Per hypothesis: the statement, the sources checked against the gap list, the result with its blind spots.',
    },
    {
      key: 'M2-tt2-validate-queries', title: 'TT3 (Obj 2) — Validate queries prior to execution',
      source: 'expanded', priority: 'normal', team: 'Bravo',
      intent: 'A query that silently matches nothing is indistinguishable from a clean estate. That is the failure mode this task exists to prevent.',
      steps: [
        step('Test every query against a known positive before trusting a negative. Generate the event, or find a historical instance, and confirm the query catches it.',
          'Kibana', 'Each query proven against a known positive.'),
        step('Confirm the query accounts for the winlogbeat duplicate-agent-id issue if it counts anything.',
          'Kibana', 'Counting queries de-duplicated.'),
      ],
      evidenceExpected: 'Each production query validated against a known positive.',
    },
    {
      key: 'M2-tt3-additional-hypotheses', title: 'TT2 (Obj 2) — Develop hypotheses as understanding changes',
      source: 'expanded', priority: 'normal', team: '',
      intent: 'The plan written on day one is wrong by day three. Feeding what you learn back into the hypothesis set is what makes MOE3 achievable.',
      steps: [
        step('When a finding changes the picture, write the new hypothesis into the plan rather than carrying it in someone\'s head. Use the team channel so it reaches both elements.',
          'Psephos · Comms', 'New hypotheses recorded, not remembered.'),
      ],
      evidenceExpected: 'Hypothesis set evolving with the evidence.',
    },
    {
      key: 'M2-tt4-report-to-mp', title: 'TT4 (Obj 2) — Report findings to mission partner as required',
      source: 'expanded', priority: 'high', team: 'Command',
      intent: 'Reporting cadence agreed and met. A finding the mission partner learns about at the outbrief was not actionable.',
      steps: [
        step('Report anything that changes the mission partner\'s risk immediately, not on the reporting cycle. Confirmed compromise of a mission-critical host is that category.',
          'Comms · Report', 'Immediate-report criteria agreed and honoured.'),
      ],
      evidenceExpected: 'Reports delivered on the agreed cadence, with immediate escalations recorded.',
    },
    {
      key: 'M2-spray-kerberos', title: 'Password spraying without 4625 — the shared APT29/APT33 entry',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'The highest-value hunt in this phase. Both simulated actors lead with password spraying, and the ' +
        'canonical detection does not exist here: 4625 and 4740 are both absent estate-wide. P2-password-' +
        'spraying tracks the technique; this task supplies the method that works on this range.',
      mitre: ['T1110.003', 'T1078'], tools: ['Kibana', 'Zeek'],
      dataSources: ['Security 4768', 'Security 4771', 'Security 4769', 'Security 4624', 'Linux auth.log / secure'],
      terrain: ['domain controllers'],
      references: ['MITRE T1110.003', 'CISA advisories on APT29 and Peach Sandstorm password spraying'],
      steps: [
        step('KNOWN GAP: 4625 and 4740 are absent. Do not build the spray hunt on failed logons or lockouts — both are gone, and their silence proves nothing.',
          'Kibana', 'The gap stated before the query is written.'),
        step('Use Kerberos instead. 4771 with failure code 0x18 is a bad password at the KDC, and 4768 failures cover the rest. Neither is in the gap list. Aggregate by source address over a window and look for few sources touching many distinct accounts — that shape is spraying regardless of volume.',
          'Kibana · 4768/4771', 'A per-source distinct-account count across the window.'),
        step('Cover the Linux estate separately and do not treat it as secondary — most of this terrain is Ubuntu. auth.log and secure carry failed SSH and PAM authentication, and they are intact.',
          'journald · auth.log', 'Linux authentication failures aggregated the same way.'),
        step('Then hunt the success, which is the part that matters. A 4624 type 3 for an account that has just been sprayed, from a source with no history with that account, is the compromise. Cross it against the M1N-tt3 baseline edge set.',
          'Kibana · 4624', 'Successful logons following spray activity, checked against baseline edges.'),
        step('Check the authentication paths that lack MFA first, from the M1N-tt9 inventory. The APT29 Microsoft intrusion succeeded specifically against a legacy non-MFA account, and that is the most repeatable lesson this actor offers.',
          'M1N-tt9 output', 'Non-MFA paths checked first.'),
      ],
      evidenceExpected: 'Spray attempts reconstructed from Kerberos and Linux auth, with any successful follow-on logon filed.',
      doNext: 'Any confirmed spray success goes to M4-tt3 as an MFA recommendation immediately.',
    },
    {
      key: 'M2-kerberoast', title: 'T1558.003 — Kerberoasting',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'The natural follow-on to the spray, and the rare case on this range where the canonical ' +
        'detection is intact. 4769 is not in the gap list and is already in the team\'s evidence ' +
        'vocabulary. Worth weighting because of what it costs the adversary: ANY authenticated domain ' +
        'account can request a service ticket, so the moment the spray lands a single low-privilege ' +
        'user, every SPN in the domain becomes an offline cracking target. Spray gets a foothold, ' +
        'Kerberoast turns it into a service account, and service accounts are how you reach M2-dcsync.',
      mitre: ['T1558.003', 'T1558.004', 'T1078.002'],
      tools: ['Kibana', 'PowerShell', 'Zeek'],
      dataSources: ['Security 4769', 'Security 4768', 'Security 4624', 'LDAP'],
      terrain: ['domain controllers', 'mail servers'],
      references: ['MITRE T1558.003', 'MITRE T1558.004'],
      commands: [
        'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordLastSet,MemberOf',
        'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth',
      ],
      steps: [
        step('Build the target list before hunting the tickets: every account carrying an SPN, with its password age and its group membership. That list is short, it is knowable, and it tells you which tickets would actually be worth cracking.',
          'PowerShell · LDAP', 'A per-domain SPN inventory with password ages.'),
        step('Flag any SPN account that is also privileged. A Domain Admin with an SPN is a one-step path from any domain user to domain compromise, and it is a finding on its own whether or not anyone has touched it yet.',
          'PowerShell', 'No privileged SPN accounts, or a filed finding.'),
        step('Hunt 4769 by ticket encryption type. Type 0x17 is RC4-HMAC, and on an estate that supports AES an RC4 request is usually deliberate — RC4 cracks far faster offline. Filter to failure code 0x0 so you are looking at tickets actually issued.',
          'Kibana · 4769', 'RC4 service ticket requests enumerated and attributed.'),
        step('Then look at shape rather than encryption. One account requesting tickets for many distinct service names in a short window is roasting even when the encryption type looks ordinary. Halve the counts — every winlogbeat document is duplicated under two agent ids, and this is a volumetric hunt.',
          'Kibana · 4769', 'Per-requester distinct-SPN counts, de-duplicated.'),
        step('Cover AS-REP roasting in the same pass. Accounts with Kerberos pre-authentication disabled can be roasted without any credential at all, which makes them worse than the SPN accounts. They show against 4768 rather than 4769.',
          'Kibana · 4768 · PowerShell', 'No pre-auth-disabled accounts, or a filed finding.'),
        step('Tie any hit back to the spray. If the requesting account is one M2-spray-kerberos flagged as a successful logon, that is no longer two findings — it is one intrusion with two stages, and it should be filed as a linked pair with propose_edge.',
          'Psephos · Evidence', 'Spray and roast correlated into one chain where they connect.'),
      ],
      evidenceExpected: 'The SPN inventory, any privileged or pre-auth-disabled account, and every 4769 requester that looks like roasting rather than use.',
      doNext: 'A privileged SPN account or a pre-auth-disabled account goes to M4-tt3 as a policy recommendation regardless of whether it was exploited.',
    },
    {
      key: 'M2-cmd-shell', title: 'T1059.003 — Windows Command Shell',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'Named explicitly in the tasking (Objective 3 TT2) and genuinely missing from P1-P8, which covers ' +
        'PowerShell and Visual Basic but not cmd.exe. It matters more here than usual: PowerShell 4104 is ' +
        'suppressed in memory by the Thread C script on hosts where it ran, so an adversary who drops to ' +
        'cmd.exe on those hosts is quieter than one who does not.',
      mitre: ['T1059.003'], tools: ['Kibana', 'Velociraptor'],
      dataSources: ['Sysmon 1 (Process Create)', 'Security 4688 (Process)'],
      steps: [
        step('Hunt cmd.exe process creation by parent. A cmd.exe whose parent is a browser, an Office application, a web server process or a service host is the interesting population; one whose parent is explorer.exe usually is not.',
          'Kibana · Sysmon 1', 'cmd.exe creations grouped by parent.'),
        step('Look for the discovery burst: whoami, net user, net group, nltest, systeminfo, ipconfig, tasklist running close together under one parent. That cluster is reconnaissance and it is loud in a way the individual commands are not.',
          'Kibana · Sysmon 1', 'Command clusters identified by parent and time.'),
        step('Check for cmd.exe on hosts where P3 found PowerShell activity suppressed. A gap in 4104 plus cmd.exe usage on the same host is a deliberate downgrade, not a coincidence.',
          'Kibana', 'Overlap of 4104 suppression and cmd.exe usage identified.'),
        step('Watch for one-liners using /c with obfuscation — caret escaping, environment variable substring tricks, or an unusual amount of quoting.',
          'Kibana', 'Obfuscated invocations filed.'),
      ],
      evidenceExpected: 'cmd.exe activity grouped by parent, with discovery clusters and any 4104-suppressed overlap filed.',
    },
    {
      key: 'M2-account-creation', title: 'T1136 — Account creation without 4720',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'Objective 3 TT1 names domain account creation. 4720 is absent estate-wide and so are the group ' +
        'membership events 4728/4732/4756, so the entire event-log approach to this technique returns ' +
        'nothing on this range. APT29 creates and elevates accounts for persistence; the hunt has to come ' +
        'from somewhere else.',
      mitre: ['T1136.001', 'T1136.002', 'T1098'], tools: ['Kibana', 'Velociraptor', 'PowerShell'],
      dataSources: ['Sysmon 1 (Process Create)', 'Security 4624', 'LDAP', 'Linux auth.log'],
      terrain: ['domain controllers'],
      commands: [
        'Get-ADUser -Filter * -Properties whenCreated | Sort whenCreated -Desc | Select -First 40',
        'Get-ADGroupMember "Domain Admins" | Get-ADUser -Properties whenCreated',
        'awk -F: \'$3>=1000 {print $1}\' /etc/passwd',
      ],
      steps: [
        step('KNOWN GAP: 4720, 4728, 4732 and 4756 are all absent. State it and move on — silence in the Security log is not evidence that no account was created.',
          'Kibana', 'Gap acknowledged.'),
        step('Query the directory itself for state rather than events. whenCreated on user objects gives you what the log cannot, and the answer is authoritative because it comes from the object, not from an audit trail.',
          'PowerShell · LDAP', 'Accounts created inside the exercise window, listed.'),
        step('Hunt the act instead of the record: Sysmon 1 for net.exe user /add, net localgroup /add, dsadd, and New-ADUser. Process creation logging is intact where account auditing is not.',
          'Kibana · Sysmon 1', 'Account-creation tooling executions found or ruled out.'),
        step('Compare current Domain Admins and local Administrators membership against the P1 baseline list. You cannot see the change event, but you can see that the membership differs — and the diff is the finding.',
          'PowerShell', 'Membership diffed against the P1 baseline.'),
        step('On Linux, check /etc/passwd and /etc/shadow modification times and useradd invocations in auth.log.',
          'Velociraptor · auth.log', 'Linux account additions covered.'),
      ],
      evidenceExpected: 'Accounts created in the window, recovered from directory state and process creation rather than 4720.',
    },
    {
      key: 'M2-dcsync-ntds', title: 'DCSync and NTDS extraction — APT29 credential access',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'APT29\'s signature move once it holds a privileged account. Not covered anywhere in P1-P8, which ' +
        'reaches password stores and browsers but not the directory itself. A successful DCSync ends the ' +
        'domain, so this is worth hunting even on thin evidence.',
      mitre: ['T1003.006', 'T1003.003', 'T1550.002'], tools: ['Kibana', 'Zeek'],
      dataSources: ['Security 4662', 'Security 4624', 'Zeek / PCAP'],
      terrain: ['domain controllers'],
      steps: [
        step('Hunt 4662 for the directory replication rights GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2. A replication request from anything that is not a domain controller is DCSync, full stop.',
          'Kibana · 4662', 'Every replication request attributed to a real DC.'),
        step('Confirm from the network side too. DRSUAPI traffic to a DC from a host that is not a DC is the same finding seen independently, which matters because 4662 needs the right SACL to be present.',
          'Zeek · Arkime', 'No unexpected DRSUAPI sources.'),
        step('Check for NTDS.dit access on disk — volume shadow copy creation, ntdsutil, or esentutl against the database. That is the offline route to the same prize.',
          'Kibana · Sysmon 1', 'No unexplained shadow copy or ntdsutil activity.'),
        step('If you find either, treat every domain credential as compromised and say so in the report. That is the recommendation, not a caveat.',
          'Psephos · Evidence', 'Filed at high confidence with the blast radius stated.'),
      ],
      evidenceExpected: 'Replication requests and NTDS access attributed, or filed at high confidence.',
    },
    {
      key: 'M2-c2-web-service-dns', title: 'C2 over web services and DNS',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent:
        'P3 and P5 cover web protocol C2 and non-standard ports. Neither covers the two channels these ' +
        'actors actually favour: APT29 uses legitimate cloud services as C2, which looks like permitted ' +
        'business traffic to a port-based control, and APT33 has used DNS-based channels.',
      mitre: ['T1102', 'T1071.004', 'T1568.002'], tools: ['Zeek', 'Arkime', 'Suricata'],
      dataSources: ['Zeek / PCAP', 'Zeek dns.log', 'Firewall log'],
      steps: [
        step('Baseline which hosts legitimately reach cloud storage and collaboration services, then hunt the exceptions. A server or an OT jump host talking to a file-sharing service is the finding; a workstation doing it may be Tuesday.',
          'Zeek · Arkime', 'Cloud service destinations attributed by host role.'),
        step('For DNS, look for high query volume to a small number of parent domains, long or high-entropy labels, and TXT or NULL record types carrying payload-sized answers.',
          'Zeek dns.log', 'DNS outliers by volume, label length and record type.'),
        step('Check timing regularity across both channels. Beaconing survives a change of transport — jitter and interval give it away when the destination looks legitimate.',
          'Arkime', 'Periodic flows identified regardless of destination reputation.'),
        step('Confirm which hosts can resolve externally at all. A host that should only use internal resolvers reaching an external one is a finding on its own.',
          'Zeek · firewall log', 'External resolver usage enumerated.'),
      ],
      evidenceExpected: 'Cloud-service and DNS channels baselined, with beacon-shaped exceptions filed.',
    },
    {
      key: 'M2-destructive-preparation', title: 'Preparation for destructive action — APT33 endgame',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent:
        'APT33 is associated with wiper tooling and with energy-sector targeting, which is exactly this ' +
        'terrain. Nothing in P1-P8 hunts destructive preparation, and the warning signs precede the act by ' +
        'long enough to matter. On a mission partner network with an OT estate, this is the finding that ' +
        'changes what the commander does today.',
      mitre: ['T1485', 'T1561.001', 'T1490', 'T1489', 'T0809', 'T0826', 'T0879'],
      tools: ['Kibana', 'Velociraptor', 'Zeek'],
      dataSources: ['Sysmon 1 (Process Create)', 'Sysmon 11 (File Create)', 'Linux auth.log'],
      terrain: ['OT segments', 'file servers'],
      references: ['MITRE T1485, T1490', 'ATT&CK for ICS T0809, T0826'],
      steps: [
        step('Hunt shadow copy deletion and backup interference: vssadmin delete shadows, wbadmin delete, bcdedit recoveryenabled No. These precede destruction and they have no legitimate administrative use in this window.',
          'Kibana · Sysmon 1', 'No unexplained recovery-inhibition commands.'),
        step('Look for staging of unfamiliar signed or unsigned drivers, and for raw disk handle access. Wipers reach the disk below the filesystem, and the driver load is the observable part.',
          'Kibana · Sysmon', 'Driver loads reviewed against a known-good set.'),
        step('Check for service stop and process kill patterns against backup, database and historian services. Availability attacks start by stopping the things that would survive them.',
          'Kibana', 'Service stops attributed.'),
        step('On the OT side the equivalent is loss of view or control: PLC program changes, HMI manipulation, and mass writes. Those are already tracked in P7 — pull the P7 findings in here rather than re-hunting them, and read them together as a destructive-intent picture rather than as separate anomalies.',
          'P7 findings · Psephos map', 'IT and OT indicators correlated into one assessment.'),
        step('If you find preparation rather than execution, escalate immediately regardless of confidence. The value of this finding decays to zero the moment it executes.',
          'Comms · Report', 'Immediate escalation on any positive.'),
      ],
      evidenceExpected: 'Recovery-inhibition, driver and service-stop indicators reviewed; IT and OT correlated into one assessment.',
      doNext: 'Any positive goes straight to the Mission Commander and the mission partner, not into the reporting cycle.',
    },
    {
      key: 'M2-antiforensics', title: 'Indicator removal and anti-forensics — APT29 stealth',
      source: 'expanded', priority: 'normal', team: 'Bravo',
      intent:
        'APT29 is defined by not being found. Nothing in P1-P8 hunts the cleanup itself, and there is a ' +
        'grim irony worth stating: 1102 (log cleared) is absent estate-wide, so the event that announces ' +
        'log clearing is itself unavailable.',
      mitre: ['T1685.005', 'T1070.004', 'T1070.006', 'T1685.001'],
      tools: ['Kibana', 'Velociraptor'],
      dataSources: ['Sysmon 1 (Process Create)', 'Host forensics'],
      steps: [
        step('KNOWN GAP: 1102 is absent, so you cannot hunt log clearing by its own event. Hunt the tooling instead — wevtutil cl, Clear-EventLog, and direct manipulation of the .evtx files.',
          'Kibana · Sysmon 1', 'Clearing tooling hunted rather than the clearing event.'),
        step('Hunt the shape instead of the event: gaps in log continuity. A host with no events at all for a period during which it was demonstrably up and on the network is the signature, and it survives the missing 1102.',
          'Kibana', 'Per-host continuity checked for unexplained silence.'),
        step('Check for timestomping — file creation times that precede the host\'s sensor start, or that cluster suspiciously on round numbers. Compare $STANDARD_INFORMATION against $FILE_NAME where you can.',
          'Velociraptor', 'Timestamp anomalies identified.'),
        step('Look for audit policy tampering. 4719 is also absent, so check the effective policy on host directly and compare it across peers — an outlier host is one somebody changed.',
          'Velociraptor · auditpol', 'Effective audit policy diffed across peers.'),
      ],
      evidenceExpected: 'Log continuity gaps, clearing tooling, timestamp anomalies and audit policy outliers reviewed.',
    },
  ],
};

// ---------------------------------------------------------------------------
// M3 — Clear
// ---------------------------------------------------------------------------

const M3 = {
  key: 'M3',
  name: 'M3 · Clear (when applicable)',
  source: 'expanded',
  intent:
    'The source tasking carries this phase as a placeholder — "create clearing action steps" — with no ' +
    'content. It is listed here so the mission phase model is complete and so its emptiness is visible ' +
    'rather than silently missing. Clearing actions are authored jointly with the mission partner, who ' +
    'owns the systems and the risk of touching them, and they are not written in advance of knowing what ' +
    'was found. Populate before any clearing is attempted.',
  tasks: [
    {
      key: 'M3-author-clearing-actions', title: 'Author clearing actions with the mission partner',
      source: 'expanded', priority: 'normal', team: 'Command',
      intent:
        'A phase with no tasks renders as nothing at all, which is how a placeholder becomes a silent ' +
        'omission. This entry exists so the gap is visible on the board. Authoring the clearing plan is ' +
        'genuine work and it belongs to Command jointly with the mission partner.',
      steps: [
        step('Do not author clearing actions before the hunt has characterized what is there. Clearing the wrong thing destroys evidence and can tip the adversary; both are worse than waiting.',
          'Psephos · Evidence', 'Clearing planned against confirmed findings, not suspected ones.'),
        step('For every proposed action, write who executes it, what it touches, how it is verified, and how it is rolled back. The mission partner owns the systems and therefore owns the decision.',
          'Report · Comms', 'A per-action plan with a named owner and a rollback.'),
        step('OT is a separate conversation with a separate authority. Clearing on a control system can stop a process, so nothing there proceeds without the process owner and a maintenance window.',
          'Comms', 'OT clearing actions gated on the process owner.'),
        step('Replace this task with the authored actions once they exist, and mark it complete.',
          'Psephos · Plan', 'M3 populated with real tasks.'),
      ],
      evidenceExpected: 'An authored clearing plan, or a recorded decision that clearing is not applicable.',
      doNext: 'Revisit once M2 has produced confirmed findings.',
    },
  ],
};

// ---------------------------------------------------------------------------
// M4 — Enable and harden
// ---------------------------------------------------------------------------

const M4 = {
  key: 'M4',
  name: 'M4 · Enable and harden',
  source: 'expanded',
  intent:
    'Tactical Objective 1: work with the mission partner to implement hardening against all critical CVEs ' +
    'and discovered malicious cyber activity. MOE1 — malicious actors blocked from the network. MOE2 — ' +
    'automated detections and protections employed against identified TTPs. MOE3 — critical CVEs patched ' +
    'or mitigated. Inputs are the M1V exposure list and every confirmed finding from M2 and P1-P8.',
  tasks: [
    {
      key: 'M4-tt1-automate-detections', title: 'TT1 — Automate optimized detections and protections',
      source: 'expanded', priority: 'high', team: 'Bravo',
      intent: 'Every confirmed finding should leave behind a detection the site keeps after the hunt team leaves. That residue is the durable part of the mission.',
      mitre: [], tools: ['Suricata', 'Sigma', 'Kibana'],
      steps: [
        step('Write a detection for each confirmed TTP, not for each indicator. An address blocks for a week; a behaviour holds.',
          'Sigma · Suricata', 'A behavioural rule per confirmed technique.'),
        step('Prioritise detections that work around the known audit gaps, since those are the ones the mission partner is otherwise blind to — spray via Kerberos rather than 4625, task creation via Sysmon 11 rather than 4698, account creation via process creation rather than 4720.',
          'Sigma', 'Gap-aware detections delivered.'),
        step('Test each rule against the evidence that motivated it before handing it over, and state its expected false positive rate. A rule the partner disables in a week is worse than no rule.',
          'Kibana', 'Each rule validated and its noise level stated.'),
      ],
      evidenceExpected: 'Validated behavioural detections, weighted toward the estate\'s telemetry gaps.',
    },
    {
      key: 'M4-tt2-cve-mitigation', title: 'TT2 — Recommend patches, removal or mitigation for identified CVEs',
      source: 'expanded', priority: 'high', team: 'Alpha',
      intent: 'Ranked by reachability and evidence overlap from M1V-tt7, not by CVSS.',
      steps: [
        step('For IT, recommend patching with a window. For OT, recommend compensating controls first — segmentation, protocol filtering at the boundary, access restriction — because patching a controller usually means stopping a process.',
          'Report', 'Separate IT and OT recommendation tracks.'),
        step('For anything exploitable on an externally reachable path, recommend mitigation now and patching later. Reachability is the multiplier.',
          'Report', 'External exposures mitigated ahead of the patch cycle.'),
      ],
      evidenceExpected: 'Ranked remediation plan with OT handled by compensating control.',
    },
    {
      key: 'M4-tt3-policy-recommendations', title: 'TT3 — Recommend user, network and endpoint policy',
      source: 'expanded', priority: 'high', team: 'Command',
      intent:
        'The actor profile makes the priority order unambiguous. Both simulated actors lead with password ' +
        'spraying against authentication paths, so identity policy outranks everything else here.',
      steps: [
        step('MFA on every external and remote access path, legacy ones first. This is the top recommendation and it comes directly from how APT29 succeeded against Microsoft — a legacy account without MFA. Feed the gap list from M1N-tt9.',
          'Report', 'MFA gaps enumerated with a remediation order.'),
        step('Recommend restoring the missing audit policy. 4625, 4720, 4728/4732/4756, 4698, 4740, 4719 and 1102 being absent estate-wide is itself a finding worth reporting, independent of anything the adversary did — the partner cannot detect what they do not log.',
          'Report', 'Audit policy recommendation delivered with the specific event IDs.'),
        step('Network: egress restriction and DNS control, driven by what M2-c2-web-service-dns found. Endpoint: application control on the paths that carried execution.',
          'Report', 'Egress and endpoint policy recommendations tied to findings.'),
      ],
      evidenceExpected: 'Policy recommendations led by MFA and audit policy restoration.',
    },
  ],
};

/**
 * Layer the mission phases onto an already-expanded plan.
 * P1-P8 are left exactly as they are; this only appends.
 */
/**
 * Lay the doctrinal frame over a plan: M0 preparation, M1 network, host and
 * vulnerability characterisation, M2 threat hunting, M3 response, M4 handover.
 *
 * Generic on purpose. Every task's `terrain` names a category — domain
 * controllers, the IT/OT boundary — rather than one exercise's hostnames, so
 * the frame is a starting point for any engagement and the team fills in which
 * of their boxes it means.
 */
export function addMissionPhases(plan) {
  // Idempotent. A plan that already carries M0 must not have it layered a
  // second time — task_key is UNIQUE and the import would refuse the whole
  // plan. This is also what makes it safe to re-run over a plan the frame was
  // already applied to by hand.
  if (plan.phases.some(p => p.key === 'M0')) return plan;

  plan.phases.push(M0, M1_NETWORK, M1_HOST, M1_VULN, M2, M3, M4);

  for (const phase of [M0, M1_NETWORK, M1_HOST, M1_VULN, M2, M3, M4]) {
    for (const t of phase.tasks) {
      t.assignees = t.assignees ?? [];
      t.tools = t.tools ?? [];
      t.dataSources = t.dataSources ?? [];
      t.commands = t.commands ?? [];
      t.mitre = t.mitre ?? [];
      t.references = t.references ?? [];
      t.terrain = t.terrain ?? [];
      t.steps = t.steps ?? [];
      t.team = t.team ?? '';
      t.priority = t.priority ?? 'normal';
      t.intent = t.intent ?? '';
      t.stepsSource = t.steps.length ? 'authored' : 'standard-loop';
      t.ttpText = t.mitre.join(', ');
      t.evidenceExpected = t.evidenceExpected ?? '';
      t.analysis = t.analysis ?? '';
      t.doNext = t.doNext ?? '';
      t.original = null;
    }
  }
  return plan;
}
