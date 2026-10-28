# One-week daily security workbench pilot

Status: prepared study, **zero participant observations**. This is a small
directional study of daily AppSec work, not a detection benchmark or proof of
general usability. The first session is selected: the maintainer will test
oxAudit itself. External participant and repository selection remains pending.

## Next human session: ready-to-run first pass

The first session is human-run by the maintainer, using the oxAudit repository
(`/Users/admin/oxAudit` in the current workspace). No human acceptance or
time-saving result is recorded.
Use the inert `examples/pilot` fixtures for setup, then a repository the
participant is authorized to review. Do not treat work on the fixtures as a
real-world productivity result.

Allow 45 minutes for the initial session:

1. **5 minutes — record the baseline.** Copy the blank scorecard outside this
   checkout. Record participant pseudonym, role, repository revision, current
   tools, and where private notes may be stored. Leave unknowns blank.
2. **5 minutes — freeze the build.** Record `git rev-parse HEAD`,
   `git status --short`, OS, client mode and artifact hashes. The fixes on an
   uncommitted working tree are not identified by the commit hash alone; retain
   the patch with the private session evidence. Build using the getting-started
   guide, then run `npm run pilot:smoke -- --cli ./src-tauri/target/debug/oxaudit-cli`.
   Its result is technical preflight evidence, not a participant observation.
3. **20 minutes — observe actual work.** Ask the participant to review one
   finding, prepare a developer handoff, recheck an authorized change, and
   recover the saved evidence after a restart. Use the neutral prompts below.
   Record assistance, failures, skipped work, active time and machine wait
   separately. If the timebox expires, record the attempt as blocked.
4. **10 minutes — check the exported evidence.** Have the participant inspect
   the report in their normal downstream tool. Check finding/run identity,
   qualifications, non-ASCII names and paths, and any imported license or
   dependency information relevant to their task. Record the exact tool and
   format. A structurally valid file is not proof that the recipient found it
   useful.
5. **5 minutes — debrief.** Ask what was hard, what information was missing,
   and whether they would use oxAudit for the next similar task. Record the
   answer verbatim as self-report; do not infer adoption from task completion.

After the session, link its private scorecard and artifacts from the team's
approved record, triage observed blockers, and decide whether to proceed with
the five-day comparison below. A single maintainer session remains a
maintainer session, not external acceptance. Recruitment and sending any
invitations are separate human actions; this preparation does not send them.

For this first session, start the current working-tree desktop build with
`npm run tauri dev`, open `/Users/admin/oxAudit`, and use **Check project**.
Record effective exclusions: this repository contains deliberately vulnerable
benchmark fixtures, which must not be mistaken for production defects. Keep
test/documentation findings distinct from production findings. For the edit
and recheck exercise, use a disposable copy of `examples/pilot` rather than
changing the application merely to make a finding disappear. For exported
evidence, use the newly built application, not an older installed release.

The first-session acceptance record stays pending until the maintainer records:

- Whether setup and the first scan completed without assistance, with actual
  elapsed/active time or an explicit unknown.
- One triage decision and its evidence, or a recorded reason none was possible.
- One handoff report opened in the intended downstream viewer, with any
  missing/corrupted content recorded.
- A fixture recheck and post-restart recovery result, including exact run IDs.
- The most important blocker and whether another real task would justify
  reopening oxAudit. This answer is self-report, not adoption measurement.

An [agent-run technical rehearsal on oxAudit](qa/2026-10-26-internal-workbench-pilot.md)
is complete, with fresh scans, benchmarks and browser integration checks. It
provides concrete follow-up cases but does not count as a participant session.

## Decision this pilot supports

Does oxAudit help an engineer reach a defensible security decision and hand off
or recheck remediation with less effort than their current workflow?

The initial scope is an individual AppSec/product security engineer reviewing
source and dependencies. Binary/image work can be recorded as an additional
task when it is already part of that engineer's job. Use the evidence to choose
among alert-quality work, a combined daily queue, and better developer handoff.
Do not infer that any of those features is required before observing the work.

## Start here

1. Start with one maintainer and one real repository to check the protocol.
   Label that session `maintainer`; it does not count as external acceptance.
2. Recruit 3–5 engineers who already perform application-security review, using
   repositories they are authorized to assess. Include their normal languages,
   frameworks, backlog and tool configuration. Record selection bias.
3. Copy [the blank scorecard](daily-workbench-scorecard.template.md) to a private
   study folder outside this checkout for each participant. Agree where notes
   may be retained and shared before collecting them. Do not include live
   credentials or unredacted secret findings in the study record.
4. Select and freeze one oxAudit build for the week. Record its commit, dirty
   state, artifact SHA-256, client mode, OS and architecture. Record the actual
   executable/bundle and frontend identity used; a CLI hash does not identify
   a separately built desktop or browser frontend. Version text alone is not
   enough. Record rule packs, effective settings, advisory freshness and AI use.
5. Choose an existing workflow for comparison: the participant's actual tools
   and process, not a deliberately weak baseline. Record versions and settings.
6. Follow the [existing pilot protocol](pilot-validation.md) on copied inert
   fixtures to check installation, recheck semantics, malformed dependencies,
   restart and export. Keep fixture acceptance separate from real-work results.
7. Run the real-work tasks below. Leave unavailable work `not evaluated`; never
   manufacture a finding, fix, participant or elapsed time to fill a row.

The [source-build instructions](getting-started.md) and
[server guide](headless-server.md) describe setup. Older release observations
in those documents are dated evidence, not the selected pilot artifact. Resolve
the exact build before inviting participants to install it. Browser and native
desktop results are separate: server paths and unavailable server AI change the
workflow. If the build changes during the week, record a new session identity
and do not merge its measurements silently with the original build.

## Five working days

| Day | Activity | Evidence to retain |
| --- | --- | --- |
| 1 | Understand the current workflow; install; complete fixture onboarding; prepare matched real-work tasks | Build identity, setup effort, blockers, baseline tools and task pairs |
| 2 | Review a real change and triage the first findings in each workflow | Scope, ordering, finding decisions, elapsed and active time, assistance |
| 3 | Assess a dependency and prepare a developer handoff | Package/version evidence, proposed action and uncertainty, handoff contents |
| 4 | Recheck an authorized fix; reopen saved work after restart | Original/new evidence, coverage outcome, recovered review/export |
| 5 | Review return use and conduct a short debrief | Actual reasons for opening the tool, unresolved blockers, per-participant comparison |

Allow normal use between scheduled tasks. Do not send daily reminders to open
oxAudit if measuring voluntary return. Log scheduled sessions, reminders and
unprompted use separately. A participant's recollection is self-report, not an
instrumented observation. No telemetry or automatic outreach is needed.

## Facilitator script

Start with: “Walk me through the last security finding you handed to a developer.
What took the most work, and how did you decide it was fixed?” Record their
existing tools and responsibilities before explaining oxAudit's features.

Read each task's goal, not a sequence of buttons. Let the participant choose
their path. Record assistance and recovery time; do not classify a guided
completion as unassisted. Agree on a task timebox before starting. When it
expires, retain time spent and the blocker rather than recording a successful
completion or excluding the attempt from the results.

| Task | Neutral prompt | Completion evidence |
| --- | --- | --- |
| Review a change | “Decide whether this change introduces an issue that needs action.” | Revision and scope, finding/evidence or a qualified no-action decision, skipped/unknown coverage |
| Triage findings | “Review the first 20 findings in the order you would normally use.” | Captured sort/filter and first-20 membership, per-finding decisions and time; use all available if fewer than 20 |
| Assess a dependency | “Decide what, if anything, the developer should change about this dependency.” | Installed identity, advisory match, usage evidence, candidate upgrade or justified uncertainty |
| Prepare handoff | “Prepare enough information for another developer to act.” | Location/package, risk and evidence, suggested action, finding/run identity and remaining questions; recipient review if available |
| Recheck a fix | “Determine what this change establishes about the original finding.” | Original and new revisions/runs, completed compatible coverage, result and remaining verification work |
| Resume work | “After restarting, continue the investigation and retrieve the evidence you need.” | Correct saved run, review state and export; lost context or manual reconstruction |

For a handoff without an actual recipient review, record `prepared, recipient
review pending`; do not claim developer acceptance. Preparing a ticket does not
authorize sending it. Use an isolated branch/copy for edits and keep fixture
code inert. A scan recheck establishes detection/coverage evidence, not general
exploit prevention or credential revocation. Keep independent remediation
validation separate from the legacy feedback task named `verified-resolution`.

## Fair comparison

- Prepare two comparable tasks or changes per task family. Record language,
  size, complexity, known prior exposure and why the pair is comparable before
  timing. Alternate which workflow comes first across participants. Never
  assume the second pass on the same known finding is an unbiased time saving.
- Where only one real task is available, record both attempts and their order,
  mark the comparison `learning-confounded`, and omit it from a time-saving
  claim. Do not invent a matched counterpart.
- Keep repository revision, relevant scan scope and advisory snapshot comparable
  where possible. Document differences and incomplete coverage. Faster work
  that skipped the relevant evidence is not a productivity win.
- Record installation/setup separately. For task time, start when the participant
  sees the task and target; stop at the stated completion evidence. Capture
  wall-clock seconds and active working seconds separately, with pauses,
  machine/provider waits and assistance noted. Include ordinary troubleshooting.
- Use the configured ranking the engineer would use. Capture it before triage;
  do not cherry-pick the best 20. Keep each tool's queue distinct and record
  duplicate findings as review effort even when they share a root cause.

## Measures and interpretation

| Measure | Definition |
| --- | --- |
| First actionable finding | Task start to the first finding for which the engineer can explain relevance, evidence and a concrete next action; if none, record no actionable finding within the observed period |
| Actionable fraction of reviewed queue | Actionable / all reviewed findings; separately retain non-actionable, duplicate and unresolved counts. This is task usefulness, not detector precision or recall |
| Triage cost | Active seconds spent deciding each finding and total review seconds; record dismissal effort separately and report unresolved work |
| Handoff effort | Time to prepare the agreed evidence packet; separately record recipient acceptance and subsequent clarification effort when observed |
| Recheck effort | Time from starting reassessment of an available fix to its coverage-qualified result; separate coding time and independent security validation |
| Paired time difference | Baseline task seconds minus oxAudit task seconds, only for comparable completed pairs with adequate evidence; percent difference divides by a positive baseline time |
| Return use | Days with reported/observed unprompted use / days with a real opportunity to use it; prompted use, no opportunity and unknown stay separate |
| Reliability | Completed, blocked and not-evaluated counts, with evidence of incomplete scans, lost reviews, stale identity or misleading outcomes |

Report participant-level values, counts, medians and ranges with denominators.
Keep wall-clock and active time separate. Show blocked attempts alongside
completed-pair times to avoid survivorship bias. Unknown findings are not false
positives. Detector recall needs independent ground truth and is not measured
by this study. Do not pool maintainer/internal sessions with external sessions
or generalize from a convenience sample to all security engineers.

## End-of-week decision

Ask: “Which work would you choose oxAudit for tomorrow?”, “What would send you
back to your current workflow?”, and “Show me one decision it helped or hindered.”
Record specific examples and negative feedback as well as useful outcomes.

Use these predeclared decision rules as pilot choices, not industry thresholds:

- Any observed misleading clean/resolved outcome, lost decision or wrong-run
  evidence takes priority for investigation before expanding the pilot.
- Treat the workflow as promising only when at least two external participants
  independently complete a recurring task with adequate evidence and describe
  a concrete benefit. A one-person maintainer run can refine the protocol but
  cannot satisfy this criterion.
- Call an efficiency result a preliminary signal only when at least two
  external participants have comparable completed pairs with lower active time,
  without worse evidence quality; also publish regressions and blocked attempts.
- Prioritize alert quality when non-actionable/duplicate triage dominates effort;
  prioritize the daily queue when finding the next relevant task dominates;
  prioritize handoff when packet preparation or developer clarification dominates.
  Tie the choice to measured minutes and observed examples, not feature votes.
- If evidence is insufficient or mixed, report that outcome and specify the next
  missing observation. Do not force a launch or feature decision.

## Existing feedback-tool compatibility

The Markdown scorecard is the working record for comparisons, queue sampling and
daily use. It is **not** input to `tools/pilot-feedback.mjs`. That tool accepts
only the existing JSON schema and six task IDs; do not add study fields to it.

For its five desktop acceptance tasks, initialize a separate blank JSON form:

```sh
node tools/pilot-feedback.mjs init --output /absolute/private/path/participant-feedback.json
node tools/pilot-feedback.mjs validate --input /absolute/private/path/participant-feedback.json
```

Replace the paths with an existing private directory. `init` refuses overwrite.
After actual consented observations, follow the existing protocol's capture
instructions. Link the JSON and scorecard by participant/session identifiers.
Neither a validated form nor a passing automated smoke is participant evidence
by itself. Keep the committed templates blank.
