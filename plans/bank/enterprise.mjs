/**
 * Authored depth, keyed by ATT&CK technique id.
 *
 * A generated stub says what MITRE says. This says what somebody who has hunted
 * it knows: why it is worth looking at here, what to run, and what a result
 * looks like. Entries are added by hand and there is deliberately no UI for
 * writing them — tradecraft that nobody signed is the thing this file exists to
 * keep out.
 *
 * The join is by id, so a new ATT&CK release cannot silently overwrite anything
 * here. store/bank.js reports an overlay whose technique has gone.
 */
const step = (text, tooling, expect) => ({ text, tooling, expect, source: 'bank' });

/*
  Written by a person on this engagement and reviewed against this estate. See
  plans/bank/ics.mjs for what the two provenance values mean and why the
  flattering one is never a default.
*/
const authored = (m) => Object.fromEntries(
  Object.entries(m).map(([id, d]) => [id, { ...d, provenance: 'authored' }]));

export const overlays = authored({
  'T1053.005': {
    intent:
      'Persistence is the one thing an operator has to leave behind. A scheduled task is the '
      + 'quietest way to do it on Windows, and the reason it is worth hunting across a baseline '
      + 'rather than per host is that identical builds make an outlier obvious: one host out of '
      + 'six carrying an entry the others do not is a change to that host, not a property of the '
      + 'platform.',
    tools: ['PowerShell', 'Velociraptor', 'Kibana'],
    dataSources: ['Security 4698 (Task Created)', 'Sysmon 1 (Process Create)', 'Task Scheduler operational log'],
    terrain: ['workstations', 'servers'],
    commands: [
      'Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author',
      'Get-ScheduledTask | ForEach-Object { $_ | Get-ScheduledTaskInfo }',
    ],
    steps: [
      step('Collect from every host in the segment, not a sample. A baseline is only an outlier detector if it covers the whole population.',
        'PowerShell · Velociraptor', 'Rows for every host in the segment.'),
      step('Import against the existing baseline and read the New band. Anything that appears on one host and not its siblings is the population worth looking at.',
        'Psephos · Characterization', 'A New band short enough to read.'),
      step('Read the author and the action, not the task name. A name is chosen to look ordinary; the binary it runs and the account that created it are not.',
        'PowerShell', 'Each new task explained by a change, or filed.'),
      step('Acknowledge fields the command did not return, so gaps stop reading as changes.',
        'Psephos · Characterization', 'Field gaps acknowledged for the run.'),
    ],
    evidenceExpected:
      'One scheduled-task baseline per estate, and a short list of entries that exist on one host and not its siblings.',
    doNext:
      'A task running from a user-writable path goes to the host owner as a finding regardless of whether it has fired.',
  },
});
