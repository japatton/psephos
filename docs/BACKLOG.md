# Backlog

Things known to be worth doing, with what is already understood about each, so
the next person does not have to rediscover it. Anything urgent is not here —
it is fixed.

Written down rather than left in a conversation because most of these were
found by measuring, and the measurement is the expensive part.

---

## ~~Identity: `shares` and `software`~~ — done

Both keyed on a bare name with the discriminator sitting unused beside it, the
same shape as the cron identity in `scheduled-tasks`. Neither was biting; both
would have failed silently, because two rows folding into one is far below the
twenty-row floor `reconcile()` needs before the fold guard says anything.

`shares` now keys on `name|path` where a path exists — 28 idents backfilled, 0
collisions, comparison unchanged at 42 rows and no deltas. `software` keys on
`name|arch`, which cost nothing because the repository is empty. The version
stays out of it: a bump has to read as a change to one row, not as one package
leaving and another arriving, and the test pinning that still passes.

---

## The task bank — shipped, with two things left on the floor

Built 2026-09-06 against the task-bank design. Every live
ATT&CK technique is a bank entry — 697 Enterprise, 97 ICS, generated from the
STIX bundles by `tools/import-attack.mjs` and committed — joined by id to
authored depth in `plans/bank/`. Drawing one copies a whole task into the plan
file; the bank never changes. Coverage mode in the Hunt Plan colours the matrix
by what the plan intends, which is a different question from the Navigator
export's what-was-found.

Two things measured and deliberately left:

- **`test/coverage.test.js`'s per-technique sort assertion cannot fail.**
  `listBank` returns techniques already in id order, because the importer sorts
  them, so deleting the sort in `store/coverage.js` changes nothing observable.
  The code is right; the test merely cannot tell. Making it discriminate means
  shuffling the input, which is more machinery than the property is worth.
- **Editing a task with Coverage open fetches the coverage twice.** The PATCH
  handler broadcasts both `plan.task` and `plan.changed`, and `onDelta` refreshes
  on each. Bounded at 2x and both responses are correct. The fix belongs with
  whoever next touches that double broadcast, not with a debounce here.

Not built, and on purpose — the spec argues each one out: pushing tasks back
into the bank (edit the file and commit; no UI), automatic plan generation, and
model-drafted depth. The last needs its own design about provenance before it is
worth having: generated tradecraft sitting beside authored doctrine is the
"looks like data" problem this codebase spends most of its effort avoiding.

**ICS is complete, and it introduced a third provenance tier.** All 97
techniques carry depth: 13 authored, 84 drafted, 0 stubs.

The 84 are what the design spec ruled out of scope, and building them meant
first building the reason it was ruled out — the spec said model-drafted depth
"needs its own design about provenance before it is worth having". So there are
three tiers rather than a bigger second one:

- **stub** — what MITRE says, generated, nobody has written anything.
- **drafted** — written from what is generally true of control systems, checked
  against nothing. Beats a stub; is not tradecraft anybody signed.
- **authored** — somebody on the engagement wrote it and it was reviewed against
  a real estate.

The tier is stamped by a wrapper per file, never a field per entry, so an entry
cannot acquire the flattering value by being edited next to one that earned it.
Promoting a draft means moving it from `plans/bank/ics-drafted.mjs` into
`plans/bank/ics.mjs` by hand, after reading it — and a test pins the authored
count at 13 so that cannot happen by accident.

It travels onto the plan (`bank_provenance`), because otherwise the problem
moves to briefing time: a drafted entry drawn into a plan is a task carrying
steps, and a week later nothing else distinguishes it from one somebody stood
behind. The board badges it `bank draft`; the bank panel says it has not been
reviewed.

**The 84 have now been through a review, one reviewer per entry, and it added a
fourth tier.** 79 passed and moved to `plans/bank/ics-reviewed.mjs`; 5 did not
and stayed in `plans/bank/ics-drafted.mjs`. `reviewed` means correct, specific
and worth reading, checked by somebody who did not write it — and explicitly not
checked against any particular estate, which is what still separates it from
`authored`.

The review was not cosmetic. It found commands that returned nothing (`ts`
before `uniq -c`, awk testing the wrong column, `journalctl -k` silently limited
to the current boot), invented log paths, `expect` values no result could fail,
and several arguments whose central claim was untrue — a blocked Modbus write is
a timeout at the master, not a silent success; controllers are not too small to
have anything to evade, since Triton beat the Tricon firmware check.

**The five it would not pass**, and why they are worth keeping as a list of what
this bank still has nothing useful to say about:

| Id | Why |
|---|---|
| `T1691.001` | Central claim false — a blocked write is a timeout, not indistinguishable from success. |
| `T1693` | Stripped of a false relay-specific framing it is a paraphrase of its own child. |
| `T0869` | Procedure unrunnable, and it chased a speculative covert channel over the real shape. |
| `T0873.001` | Misses the sub-technique's actual mechanism and misattributes block-hiding to a vendor feature. |
| `T0815` | Split verdict — reviewed twice by accident, and the two disagreed. A split is not a pass. |

**Two things this exercise says about itself.** `T0815` is the only entry with a
second opinion, and the two reviewers disagreed — so the other 83 verdicts rest
on one reader each and are not perfectly reproducible. And one reviewer caught a
Zeek `modbus.log` field that does not exist while two others passed the same
defect elsewhere; that is now a test rather than a matter of who was reading.

**Five revoked ids, found and migrated.** Authoring the ICS overlays turned up
five technique ids in this repository's own plan content that ATT&CK had revoked
and renumbered. A task naming one colours no cell in the coverage view and counts
toward no state, so the plan claimed ground the matrix could not show it covering
and nothing said otherwise.

| Was in | Old | Now |
|---|---|---|
| `plans/expansion.mjs` | T0855 Unauthorized Command Message | T1692.001 Command Message |
| `plans/expansion.mjs` | T0812 Default Credentials | T1694.001 Default Credentials |
| `plans/expansion.mjs` | T0857 System Firmware | T1693.001 System Firmware |
| `plans/mission-phases.mjs` | T1070.001 Clear Windows Event Logs | T1685.005 Clear Windows Event Logs |
| `plans/mission-phases.mjs` | T1562.002 Disable Windows Event Logging | T1685.001 Disable or Modify Windows Event Log |

All five are migrated, along with two in `tools/demo-data.mjs` — the demo is what
the published screenshots are made from, so a stale id there is a stale id on the
README. `test/plan-technique-ids.test.js` walks the plan objects the modules
actually build and fails on a dead id, so the next ATT&CK release cannot do this
quietly again.

Two halves, deliberately: that test is about the plans shipped in this box, and
the coverage view's orphan banner is about a plan somebody uploads. Neither
covers the other.

---

## Data hygiene, not urgent

- **Four repositories are still empty**: `listening-ports`, `spns`, `software`,
  `unclassified`. The first two are collection gaps rather than code problems.
- **`domain-accounts` has an upload whose usernames were inferred by row
  order.** It wants re-collecting rather than repairing; inferring an identity
  from position is how the original 879-row loss happened.
- **One collection run mixes OS families** (a `NetworkServices` baseline,
  Windows and Linux). Harmless there, but field-gap acknowledgement is scoped
  to the run, so on a mixed run in `accounts` acknowledging "shell not
  collected" would cover Windows hosts where the field is meaningless as well
  as Linux hosts where it is a real gap. It errs toward silence rather than
  false alarms. Nothing enforces that a run is homogeneous.

## ~~Three backups on disk may not be consistent~~ — resolved, and the premise was wrong

They were not corrupt. All three opened, passed `integrity_check` and held
sensible data — they were consistent but not *self-contained*, needing their
`-wal` alongside. The hazard was real but narrower than first written: move the
`.db` without its sidecar and you get a silently stale snapshot, which is
exactly what a `cp` of the live store did during the review (3,590 rows where
the store held 3,589).

Checked before deleting, which turned out to matter. Two held nothing that is
not still in the live store and were removed. The third — taken 24 Aug 06:21 —
held ten records and twenty-one messages that exist nowhere else, from before
the case was reset: REC-01 cron persistence and implant, REC-02 a time-critical
cron trigger, REC-03 a cleartext credential. It is now
`pre-reset-case-2026-08-24T06-21-07.db`, a single self-contained file, and the
fragile original is gone.

No backup in the directory depends on a sidecar any more. Take new ones with
`node tools/backup-db.mjs <label>`.

## ~~The exercise name is in the repository~~ — removed from the tree and the history

The operator's call: the exercise name is engagement data and does not belong in the
pushed repository. Removed from ten tracked files on 26 Aug, and `repo-hygiene.test.js`
now fails if it comes back.

The guard derives what to look for from `missions/*/mission.json` at runtime, the same way
the roster guard does, so the test file names no exercise itself and keeps working for
whoever uses this repository next. It matches the alphanumeric runs with any punctuation
between them, because a code written three ways is one leak wearing three hats, and it
also takes adjacent word pairs from the mission name — prose shortens a name long before
it spells one out.

Two of the ten were found by the guard and not by a hand-written `grep` over the same
tree, which is the argument for having it. One of those two was the guard's own docstring,
where the first draft spelled the real name out while explaining what not to do.

Four were live code rather than comments, and all four were already stale:

| Was | Now |
|---|---|
| `extract.mjs` defaulted to one operator's Downloads folder | the input path is required |
| `extract.mjs` stamped a fixed `source` into every terrain file | stamps the file it actually read |
| `Invoke-TerrainSurvey.ps1` defaulted to `terrain/<exercise>.json` | `terrain/terrain.json` |
| `import-huntplan.mjs` wrote `plans/<exercise>-week2.json` by default | `plans/huntplan.json` |

Both of those default paths pointed at files that no longer exist — they predate the
mission-profile system — so nothing that works today changed behaviour.

### The history was rewritten too

It was in the root commit, so every one of the 44 commits carried it. All 44 were rewritten
with `git filter-branch --tree-filter` and force-pushed. A fresh clone now has no
occurrence in any blob, any tree or any commit message, and the commit dates and messages
are unchanged.

The current tree came through byte-identical — `HEAD^{tree}` hashes the same before and
after — which is the check worth repeating if this is ever done again. Nothing about the
working code changed; only ancestry did.

**The server side is done too, as of 29 Aug.** Forgejo had been holding the pre-rewrite
objects as unreferenced garbage — a clone never got them, but they stayed fetchable by
explicit SHA, so the old blobs were readable to anyone who knew a hash.

Measured before running anything, and the exposure had already closed: 504 objects in the
pack against 504 reachable, no garbage, one reflog entry, and `git fsck --unreachable
--dangling` silent. Forgejo collected them at some point between the force-push and then.
The garbage collection was run anyway to make it definite, and the counts did not move.

If this is ever needed again, `git gc` alone is not enough — it keeps unreachable objects
that a reflog entry still points at, which is exactly the state a force-push leaves. Expire
the reflog first:

```
git reflog expire --expire=now --expire-unreachable=now --all
git gc --prune=now --aggressive
```

Equal counts from `git count-objects -v` and `git rev-list --objects --all | wc -l`, plus a
silent `git fsck --unreachable --dangling`, are what say it worked. *Site Administration
→ Maintenance → `git_gc_repos`* does the same across every repository.

Anyone holding a clone from before 26 Aug should re-clone rather than pull; their history
is the old one and a pull will try to merge it back.

## Checked in the review of 26 Aug and found clean

Recorded so nobody spends the afternoon rediscovering it. Each of these was
measured, not reasoned about.

- **Identities across all nineteen repositories.** Every one keeps apart two
  things that are genuinely different on one host, and collapses the two that
  should collapse. No rows anywhere share an identity within an upload.
- **Referential integrity.** Zero orphans across every foreign key in the
  store, and SQLite's own `integrity_check` and `foreign_key_check` both pass.
- **Silent drops.** No record with two addresses fails to produce a connection.
  Every `continue` in the ingest and read paths is either counted or documented.
- **Swallowed errors.** No empty catch anywhere; every one has an explicit
  fallback value.
- **Runtime.** All seven views render with no JavaScript errors, no console
  errors and no failed requests.
- **Provider parity.** Tool gating is shared rather than duplicated between the
  CLI and HTTP paths, and both broadcast the same events. The context they hand
  to tools had diverged and is fixed.
- **Prompt budget.** The largest mode uses 10,113 of 28,000 characters on the
  narrower argv path, so there is room as the case file grows.
- **Fresh install.** A clone with no data directory boots into the wizard and
  creates every table and column added this week.
- **Suite stability.** Three consecutive runs, identical: 540 tests, no order
  dependence.

## Not reviewed in depth

`server/setup.js` beyond confirming a fresh clone reaches the wizard, and the
internals of the plan and comms views beyond their delta handling.

## Deferred by the operator

- The four Claude CLI transcripts, `data/backups/hunt-2026-08-24T06-21-07.db`
  and `server.log` remnants.

---

## Second full review — 2026-09-07

Six dimensions reviewed again (store correctness, security and privacy,
process lifecycle, the browser client, the HTTP surface, and the suite itself),
after the first round's fixes had landed. Twenty-six findings, all reproduced
before being fixed and each one mutation-checked afterwards; they are in the
six commits between `0d63b9e` and `5505f89`.

Three are worth remembering as classes rather than as fixes:

- **A migration in `initSchema` runs at every boot.** The backfill that stamps
  `committed_at` was written as a one-time migration and left unguarded, so
  every characterization import an analyst had staged for review was committed
  into the live baseline by the next restart. Anything else added to that
  function has the same trap waiting.
- **A fix applied one place short.** Three of the six dimensions found the
  previous round's own fixes half-applied: the failing-search banner reached
  the records table and not the three views that make the strongest claims; the
  caret fix wrapped a function the delta path never calls; the DM broadcast was
  narrowed for message bodies but not for the channel row, whose title is both
  participants' names; and `killAllTurns` tracked children but exited before
  the escalation it exists to enable could fire.
- **A test that greps its own source.** `every Claude invocation is hardened`
  matched `--strict-mcp-config` in a doc comment, so deleting the flag from the
  spawn kept the test green. Asserted against `turnArgs()` and `sessionCwd()`
  now. The general point: a grep over source text proves the string exists
  somewhere in the file, and that is all it proves.

### Left on the floor, measured

- **`supportsPromptFile()` caches after its `await`,** so N concurrent first
  turns each spawn their own capability probe, and those children are not in
  `liveTurns`. Real, and no concrete loss could be attached to it: the probe is
  bounded at 15s and the window is one server start.
- **`writeMcpConfig` runs before `cleanUp` is wired to the child,** so a throw
  from `buildSystemPrompt` between them leaks one temp directory per failed
  turn. No realistic throw was found on that path.
- **`json()` on the export routes writes headers before serialising.** A throw
  mid-`JSON.stringify` would send a 200 with an empty body. The payloads are
  strings and numbers and no input could be constructed that throws.

---

## The two profile-driven hygiene guards can never run here again

`repo-hygiene.test.js` asks two questions it cannot answer on its own: does any
tracked file name somebody on the roster, and does any name the engagement. To
know that, it has to know the names — and writing them into the test would put
them in the repository, which is the thing it exists to prevent. So it reads
them at runtime out of `missions/*/roster.json` and `missions/*/mission.json`,
skipping `example`, and skips honestly when there is no profile to read.

That shape is right and should stay: this file names nobody, so it keeps working
for whoever runs the tool with an engagement in front of them. But the profile
for this codebase's own engagement is gone from the machine, and it was never
committed — only `missions/example/*` has ever been tracked — so the name list is
not recoverable. **Those two checks will skip on every run of this repository
from now on.** They were already skipping on every commit made after the profile
was deleted, which is how a personal handle sat in three test fixtures unnoticed.

What covers it now is `every analyst name in the tree is one we put there`, which
asks the question the other way round: not "is a real name present" but "is every
name present one we put here on purpose", against the example roster plus a
listed set of non-person actors. It needs no profile, so it runs in CI and on a
stranger's clone.

**The gap that leaves.** The inverted guard only sees names in *actor positions* —
a quoted `analyst:`, `actor:`, `createdBy:` and so on. A surname in a comment, in
prose, in a filename, or as a value of some field nobody thought to list is
invisible to it, and those are exactly the places the profile-driven guard used
to reach. Two of the leaks it caught historically were of that shape: a name
inside a generated baseline label, and one in a docstring.

Worth doing if it ever matters enough:

- Widen the inverted guard from actor positions to *any capitalised token that
  looks like a surname and is not a word*, with an explicit allowlist. That is a
  much noisier check and the allowlist becomes real work, which is why it was not
  done now.
- Or feed a name list into CI through a secret so the original guard can run and
  fail rather than skip. That means storing the roster in GitHub, which is a
  trade rather than a fix.

For the record, what was actually checked before publishing: every name-shaped
token ever used in an actor position across the 125 commits of the private
history — `Jones`, `Patton`, `Rios`, `Zinkone` beyond the example roster — and
none of them appears anywhere in this tree. That is a scan against the names that
are known to have been here, not against the roster itself.
