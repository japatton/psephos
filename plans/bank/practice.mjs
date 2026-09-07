/**
 * Bank entries with no ATT&CK id.
 *
 * ATT&CK describes adversary behaviour. It does not describe the work around
 * hunting it, and these three categories are where hunts go wrong in ways the
 * matrix cannot show:
 *
 *   telemetry      — hunting for something you cannot see produces a confident
 *                    false negative, which is the worst output this tool has.
 *   hypothesis     — a hunt with no stated hypothesis has no negative result,
 *                    only silence, and silence is not a deliverable.
 *   deconfliction  — red team, site admin, scanner or adversary, asked rather
 *                    than assumed.
 *
 * Every entry here is authored. There is no generated tier, because a stub in
 * these categories would be a prompt with nothing behind it.
 */
const step = (text, tooling, expect) => ({ text, tooling, expect, source: 'bank' });

/*
  All authored: these three argue from things this estate measured — 4720 absent
  estate-wide, 1102 absent, 4104 suppressed where a script ran. See
  plans/bank/ics.mjs for what the provenance values mean.
*/
const authored = (list) => list.map(e => ({ ...e, depth: { ...e.depth, provenance: 'authored' } }));

export const entries = authored([
  {
    id: 'PRAC-telemetry-coverage', category: 'telemetry',
    name: 'Establish what the estate can actually see',
    desc: 'Before hunting a behaviour, find out whether the logs that would show it exist.',
    depth: {
      intent:
        'A hunt that finds nothing is either good news or a blind spot, and nothing in the result '
        + 'distinguishes them. This estate has already produced three of those: 4720 absent '
        + 'estate-wide, 1102 absent, and 4104 suppressed in memory on the hosts where a script ran. '
        + 'Each one turns an honest hunt into a confident false negative.',
      tools: ['Kibana', 'PowerShell'],
      dataSources: ['Windows Event Log configuration', 'Sysmon config', 'sensor inventory'],
      commands: [
        'auditpol /get /category:*',
        'Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 } | Select LogName,RecordCount',
      ],
      steps: [
        step('List the event ids the plan depends on, before hunting any of them. That list is the hunt\'s own dependency set.',
          'Psephos · Plan', 'A written list of required event ids per task.'),
        step('For each, establish presence per segment rather than per estate: a log enabled on servers and not workstations is a partial blind spot and reads as absence.',
          'Kibana', 'Presence or absence stated per segment.'),
        step('File each absence as a finding in its own right. A missing log is a result about the estate, not a footnote about the hunt.',
          'Psephos · Evidence', 'A filed record per blind spot, with its segment.'),
        step('Name the compensating source where one exists, and say plainly where none does.',
          'Psephos · Plan', 'Every blind spot either covered or acknowledged.'),
      ],
      evidenceExpected: 'A per-segment statement of which required logs exist, and a filed finding for each that does not.',
      doNext: 'Any hunt task depending on an absent log is re-scoped or marked as unrunnable before it is worked, not after.',
    },
  },
  {
    id: 'PRAC-hypothesis', category: 'hypothesis',
    name: 'State the hypothesis before hunting it',
    desc: 'Write down what would be true if the adversary were here, so that finding nothing means something.',
    depth: {
      intent:
        'A hunt without a stated hypothesis cannot produce a negative result, only silence. The '
        + 'difference matters at handover: "we looked for scheduled-task persistence across all '
        + 'forty Linux hosts and found none" is a finding the site can act on, and an empty '
        + 'section is not.',
      tools: ['Psephos · Plan'],
      dataSources: [],
      commands: [],
      steps: [
        step('Write the hypothesis as a falsifiable sentence naming the behaviour, the population and the window. "An operator established cron persistence on the Bravo Linux segment in the last 14 days" can be shown false; "check for persistence" cannot.',
          'Psephos · Plan', 'A falsifiable statement recorded on the task.'),
        step('State what would count as evidence for it and what would count as against, before looking. Deciding afterwards is how a weak signal becomes a finding.',
          'Psephos · Plan', 'Acceptance and rejection criteria written down.'),
        step('Record the outcome either way. A refuted hypothesis is filed with the population and window it was tested against.',
          'Psephos · Evidence', 'A filed result, positive or negative.'),
      ],
      evidenceExpected: 'The hypothesis, the population it was tested against, and the outcome — including when the outcome is nothing.',
      doNext: 'A refuted hypothesis goes into the report\'s coverage section as ground covered, not as an absence.',
    },
  },
  {
    id: 'PRAC-deconfliction', category: 'deconfliction',
    name: 'Deconflict before escalating',
    desc: 'Establish whether the activity is red team, site administration, a scanner, or an adversary.',
    depth: {
      intent:
        'Most of what looks like an intrusion on a live estate is somebody doing their job. '
        + 'Escalating a site administrator is expensive in a way that is hard to undo, and the '
        + 'question is cheap to ask first — which is why this profile already carries a thread for it.',
      tools: ['Psephos · Comms'],
      dataSources: ['change records', 'red team schedule', 'scanner inventory'],
      commands: [],
      steps: [
        step('Check the activity against the change record and the red team window before writing it up. Both are cheap lookups and both are common explanations.',
          'Site contact · Psephos · Comms', 'Activity matched to a change, or not.'),
        step('Ask the site directly, naming the host, the account and the time, and record the answer in the thread rather than in a head.',
          'Psephos · Comms', 'A recorded answer from a named person.'),
        step('If it deconflicts, file it as denied with the reason. A ruled-out finding is worth as much as a confirmed one and stops it being re-found next week.',
          'Psephos · Evidence', 'A denied record carrying the explanation.'),
      ],
      evidenceExpected: 'For each candidate: who was asked, when, and what they said.',
      doNext: 'Anything the site cannot explain moves back to the hunt thread with the deconfliction attempt recorded on it.',
    },
  },
]);
