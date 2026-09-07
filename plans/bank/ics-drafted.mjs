/**
 * ICS overlays that a review declined to pass.
 *
 * Drafted from general control-system practice and read by a reviewer that did
 * not write them. These are the ones it would not sign off: the central claim
 * was wrong, the procedure could not run as written, or the entry was a
 * paraphrase of a technique's own name. In each case the reviewer judged that
 * fixing it meant writing a new entry rather than editing this one, and the
 * rule was that a rewrite is not a review.
 *
 * They are kept rather than deleted because a drafted entry still beats a stub,
 * and because the badge and the bank panel say plainly that nobody has checked
 * them. What they are is a list of the ICS techniques this bank has not yet
 * said anything useful about — which is a more honest artefact than a confident
 * entry would be.
 *
 * Anything the reviewer could correct in passing has been corrected, so these
 * are the drafts at their best rather than as first written.
 */
const step = (text, tooling, expect) => ({ text, tooling, expect, source: 'bank' });

const asDrafted = (m) => Object.fromEntries(
  Object.entries(m).map(([id, d]) => [id, { ...d, provenance: 'drafted' }]));

export const drafted = asDrafted({
  'T1691.001': {
    intent:
      'Blocking a command message has an effect similar to Manipulate I/O Image — the '
        + 'controller no longer responds to legitimate control — but the signature is different: '
        + 'the command was correctly formed and correctly sent, and simply never arrived. That is '
        + 'only visible by holding the sender\'s own record against what the controller received, '
        + 'since from the sender\'s side alone a blocked command and a successful one look '
        + 'identical.',
    tools: [
      'Zeek',
      'Historian',
    ],
    dataSources: [
      'HMI/SCADA command log',
      'Zeek modbus.log',
      'Zeek dnp3.log',
      'Process',
      'Operational Databases',
    ],
    terrain: [
      'HMIs',
      'controllers',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h func < modbus.log | grep -E \'WRITE|_COIL|_REGISTER\'',
    ],
    steps: [
      step('Pull the command log from the sending HMI or SCADA master for the window and compare '
        + 'each entry against the corresponding write or command function code observed on the wire '
        + 'arriving at the target controller.',
        'Historian · Zeek', 'A sent-versus-received command reconciliation.'),
      step('For any command present at the sender and absent at the controller, check the path '
        + 'between them for anything positioned to interfere, rather than assuming a benign '
        + 'transmission failure — the two are indistinguishable from the sender\'s side alone.',
        'Zeek · Psephos · Network Map', 'Path checked for interference capability.'),
      step('Ask the operator whether a command they issued visibly failed to take effect. A blocked '
        + 'command produces exactly that operator experience, and it is a useful independent '
        + 'confirmation.',
        'Site operator · Psephos · Comms', 'A recorded answer, possibly empty.'),
    ],
    evidenceExpected:
      'A sent-versus-received command reconciliation, with any gap investigated and an operator '
        + 'check recorded.',
    doNext:
      'An operator-reported failed command, confirmed missing at the controller, escalates '
        + 'immediately as a control-path integrity failure.',
  },

  T1693: {
    intent:
      'Firmware modification serves three tactics at once — persistence, impaired control, a '
        + 'suppressed response — and the parent technique is deliberately general: any device with '
        + 'an update path, not one class of device. What is common to all of them is that this is '
        + 'one of the least verifiable techniques in the matrix from a hunter\'s chair, because on '
        + 'most controllers the only way to inspect the artefact is to take the device out of '
        + 'service. The honest posture is to hunt the moment of change on the wire rather than '
        + 'claim to have inspected the result; the device-level argument lives under T1693.001 for '
        + 'the main unit and T1693.002 for modules, and this entry routes there rather than '
        + 'repeating them.',
    tools: [
      'Zeek',
      'host logs',
    ],
    dataSources: [
      'Zeek conn.log',
      'Zeek files.log',
      'asset inventory firmware versions',
      'maintenance records',
    ],
    terrain: [
      'controllers',
      'protection relays',
      'appliances',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h total_bytes mime_type < files.log | sort -k4 -rn | head -30',
    ],
    steps: [
      step('Get the maintenance record of authorised firmware activity before looking at anything '
        + 'else. A firmware update is planned and documented on a working site, so the baseline '
        + 'here is paperwork, not a capture.',
        'Site engineer · Psephos · Comms', 'A dated list of authorised firmware activity.'),
      step('Look for the traffic shape of a firmware push — a sustained transfer to the device '
        + 'followed by a restart or a gap in polling — and match every instance against the '
        + 'maintenance record.',
        'Zeek · Arkime', 'Every such event matched to a maintenance record, or one filed as unexplained.'),
      step('Where the device or its management system already publishes a version or checksum into '
        + 'an existing inventory, check reported versions against known-good rather than querying '
        + 'the device directly.',
        'Psephos · Characterization', 'Per device: reported version matches known-good, differs (a finding), or is not reported (a gap).'),
      step('Where a device exposes no verification at all, state that as the finding rather than as '
        + 'a completed check — it tells the site something true about their own exposure.',
        'Psephos · Evidence', 'An explicit statement of what cannot be verified passively.'),
    ],
    evidenceExpected:
      'Firmware transfer events matched against the maintenance record, and an explicit '
        + 'statement of what cannot be verified.',
    doNext:
      'An unmatched firmware push to any controller or appliance is an incident and a vendor '
        + 'conversation. Nothing gets reflashed or rolled back on a hunter\'s judgement.',
  },

  T0869: {
    intent:
      'T0885 asks whether a session on a familiar control port behaves like the protocol it '
        + 'claims. This asks a narrower and harder question about traffic that already passes that '
        + 'test: whether the values a legitimate-looking protocol is carrying make sense for the '
        + 'process it is supposedly running. A well-formed Modbus write to a real holding register '
        + 'can carry sixteen bits of anything, and the wire cannot tell you whether those bits are '
        + 'a setpoint or an encoded instruction — only someone who knows what that register does '
        + 'can.',
    tools: [
      'Zeek',
      'Historian',
    ],
    dataSources: [
      'Zeek modbus.log / dnp3.log',
      'engineering register or tag map',
      'historian trends',
    ],
    terrain: [
      'controllers',
      'the IT/OT boundary',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h register new_val < modbus_register_change.log | sort -u | head -40  # needs track-memmap.zeek',
    ],
    steps: [
      step('Get the register or tag map for every controller before anything else. Without knowing '
        + 'what an address means, well-formed traffic and a covert channel riding a legitimate '
        + 'protocol are indistinguishable.',
        'Site engineer · Psephos · Comms', 'A register-map record per controller.'),
      step('Check reads and writes against addresses with no assigned engineering meaning, or '
        + 'against reserved and unused ranges. Legitimate control traffic has no reason to touch an '
        + 'address nobody has documented.',
        'Zeek', 'Every access mapped to a documented address or filed.'),
      step('Compare values against the historian for the same registers over the same window; a '
        + 'value on the wire with no corresponding process effect is the signature this technique '
        + 'looks for, distinct from the shape-based check already covered under T0885.',
        'Historian', 'Each undocumented access matched to a process effect or its absence noted.'),
    ],
    evidenceExpected:
      'Register-map coverage per controller, and every access to an undocumented or reserved '
        + 'address explained or filed.',
    doNext:
      'A pattern of access to unmapped registers is escalated as a suspected covert channel; '
        + 'the inability to measure a process effect is not evidence there was none, so this goes '
        + 'to the process owner rather than being closed.',
  },

  T0815: {
    intent:
      'Denial of View is an outcome, not a signature: a temporary break in the reporting '
        + 'channel that leaves the operator\'s screen stale until the path recovers, distinguished '
        + 'from Loss of View (T0829) only by whether it came back on its own. What makes it worth '
        + 'hunting from the wire rather than waiting for a report is that a frozen display looks '
        + 'like a quiet process — values that stop moving raise nothing unless the HMI\'s own '
        + 'comms-fail alarm fires — so the operator being denied the view is often the last to know '
        + 'it was denied. The gap in polling is the observable; which side of it went quiet says '
        + 'where the denial sat.',
    tools: [
      'Zeek modbus.log',
      'Zeek conn.log',
      'Arkime',
    ],
    dataSources: [
      'Zeek conn.log',
      'Zeek modbus.log',
      'HMI alarm history',
      'HMI host logs',
      'shift and maintenance records',
      'operator report',
    ],
    terrain: [
      'controllers',
      'HMIs',
    ],
    commands: [
      'zeek-cut ts id.orig_h id.resp_h < modbus.log | sort -k2,3 -k1,1n | awk \'{k=$2" "$3} k==p && $1-t>30 {print k, t, $1-t} {p=k; t=$1}\'',
      'zeek-cut ts id.orig_h id.resp_h conn_state < conn.log | awk \'$4=="S0"||$4=="RSTO"||$4=="REJ"\' | sort -k3,3 -k1,1n | tail -40',
    ],
    steps: [
      step('Find the gap in the polling record per master-to-controller pair, with the threshold set '
        + 'to that pair\'s baselined poll interval, and read which side went quiet. A master that '
        + 'stops issuing requests has a problem at the HMI; a master still polling into S0 or RSTO '
        + 'sessions, or getting exception responses, has lost the device or the link. Same blank '
        + 'screen, different place, and only the wire tells them apart.',
        'Zeek modbus.log · Zeek conn.log', 'A bounded interruption window per pair, with the silent side named.'),
      step('Line the gap up with the HMI\'s own record — the comms-fail or bad-quality alarm in alarm '
        + 'history, the driver or OPC server log — to establish whether the operator was told the '
        + 'view was stale. A gap on the wire with no alarm at the HMI is the dangerous case: the '
        + 'screen kept showing a plausible process for the whole window.',
        'HMI alarm history · HMI host logs · operator report', 'Alarm timestamps aligned with the gap, or the gap stated as silent at the HMI.'),
      step('Check whether the channel came back on its own once whatever broke it stopped — a '
        + 'session re-established with no ticket, restart or site visit at the same minute. If it '
        + 'did, this technique fits; if somebody had to touch equipment, carry the gap to T0829. '
        + 'Either way the cause is hunted elsewhere, not here: a flood under T0814, a suppressed '
        + 'report under T0804, a restart under T0816.',
        'Zeek · Arkime · shift and maintenance records', 'A stated answer on whether recovery needed hands-on intervention, and the gap handed to the mechanism task that fits.'),
    ],
    evidenceExpected:
      'A bounded gap per master-to-controller pair with the silent side named, its alignment '
        + 'with the HMI alarm history stated, and a statement of whether it self-resolved.',
    doNext:
      'An operator working blind on a safety-relevant process during the gap is escalated '
        + 'regardless of how briefly the gap lasted, and a gap the HMI never alarmed on goes to the '
        + 'process owner as a finding about the HMI, not just about the channel.',
  },

  'T0873.001': {
    intent:
      'The general argument is T0873\'s: the infection lives in the source file, not the running '
        + 'program. Siemens formats happen to make that argument more tractable than most, because '
        + 'TIA Portal already exports per-block checksums for its own version-control purposes — '
        + 'reusing that mechanism as a baseline is cheaper and more precise than hashing an opaque '
        + 'project archive and hoping nothing else moved, since a single changed byte anywhere '
        + 'invalidates a whole-file hash without saying which block changed.',
    tools: [
      'host logs',
    ],
    dataSources: [
      'TIA Portal openness/versioning export',
      'per-block checksum history',
      'engineering workstation file hashes',
    ],
    terrain: [
      'engineering workstations',
    ],
    commands: [
      'sha256sum /home/*/Documents/Siemens/**/*.s7p /home/*/Documents/Automation/**/*.ap1[4-6] 2>/dev/null',
      'find / -iname \'*.zap1[3-9]\' -o -iname \'*.s7p\' -o -iname \'*.ap1[4-6]\' 2>/dev/null | head -30',
    ],
    steps: [
      step('Pull the project\'s per-block checksums or properties from the engineering team\'s own '
        + 'versioning output where one is already kept, rather than hashing the whole archive. A '
        + 'block-level diff attributes a change to a specific organisation unit instead of just '
        + '"the project changed."',
        'host logs', 'A block-level checksum diff against last known-good.'),
      step('Check for blocks marked non-visible or excluded from the standard project tree. Siemens '
        + 'tooling supports hiding a block from the engineer\'s own default view, which is a '
        + 'documented way to keep something out of a line of sight that would otherwise catch it.',
        'Psephos · Characterization', 'A stated check for hidden or excluded blocks, and their contents accounted for.'),
      step('Where the site keeps no versioning discipline for its Step 7 or TIA Portal projects, say '
        + 'so as the finding in its own right — the tooling to fix this already ships with the '
        + 'vendor product, which makes the gap a choice rather than a limitation.',
        'Psephos · Evidence', 'A filed statement of the site\'s project version-control posture.'),
    ],
    evidenceExpected:
      'A block-level checksum diff against known-good, and a stated check for hidden or '
        + 'excluded blocks.',
    doNext:
      'A mismatched block is escalated the same way as T0873: no redeployment from the suspect '
        + 'project while the process owner decides.',
  },
});
