# Daily workbench pilot — blank participant scorecard

Status: **prepared; zero observations**. Copy outside the checkout before use.
This Markdown file is not accepted by `tools/pilot-feedback.mjs`.
Follow [the study guide](daily-workbench-pilot.md); preserve its repository link
or path when copying this file elsewhere.

## Session and comparison setup

| Field | Recorded value |
| --- | --- |
| Participant pseudonym / relationship (external, internal, maintainer) | |
| Consent, permitted storage/sharing and retention agreement | |
| Dates / facilitator / observer | |
| Role, usual security tasks and prior oxAudit experience | |
| Repository alias / languages / framework / size | |
| Repository commit and dirty state / scan scope / exclusions | |
| oxAudit commit and dirty state / version / client mode | |
| Actual artifact path and SHA-256 / frontend identity if separate | |
| OS / architecture / editor | |
| Effective scan settings / rule packs / advisory identity and freshness | |
| AI enabled, provider and usage during tasks | |
| Baseline tools / versions / settings / advisory freshness | |
| Private evidence folder / related acceptance JSON | |

## Installation and fixture onboarding

| Activity | Outcome | Wall seconds | Active seconds | Assistance/blocker | Evidence |
| --- | --- | --- | --- | --- | --- |
| Installation and first launch | | | | | |
| Fixture finding and review | | | | | |
| Fixture correction and coverage-qualified recheck | | | | | |
| Malformed dependency handling | | | | | |
| Restart and export | | | | | |

Use `completed`, `blocked`, or `not evaluated`. Blank means unrecorded, not zero.
Fixture success does not establish real-work usefulness or external acceptance.

## Real-work task attempt (duplicate for each workflow and task)

| Field | Recorded value |
| --- | --- |
| Task ID / family / date | |
| Workflow: baseline or oxAudit | |
| Task prompt / completion evidence required / agreed timebox | |
| Pair ID / counterpart / reason tasks are comparable | |
| Attempt order / prior exposure / learning confound | |
| Target revision / scope / relevant input and advisory identities | |
| Start / finish / pauses | |
| Wall seconds / active seconds / machine wait seconds | |
| Outcome: completed, blocked, not evaluated | |
| Assistance / retries / blocker / time spent before stopping | |
| Finding fingerprint or package/advisory / canonical run IDs | |
| Decision and supporting evidence / remaining uncertainty | |
| Evidence references and adequacy checked by | |

For handoff, also record packet contents, recipient review status, and measured
clarification effort. For recheck, record original/new revisions and run IDs,
compatible coverage, exact outcome and any independent remediation validation.
Do not describe detection absence alone as proof of a secure fix.

## First-20 finding sample (duplicate for each workflow)

Record workflow, run/revision, scan family, initial sort/filter, available finding
count and evidence of queue membership before reviewing. Add one row per actual
finding, up to 20; use all available when fewer exist. Leave this table empty
until observation. If stopped early, retain the unreviewed count and reason.

| Queue position | Finding ID | Decision | Active seconds | Dismissal seconds | Evidence / rationale / root-cause duplicate of |
| --- | --- | --- | --- | --- | --- |

Decisions: `actionable`, `non-actionable`, `duplicate`, `unresolved`. A useful
next action needs stated relevance and evidence. Non-actionable does not
necessarily mean a detector false positive. Only fill dismissal time when a
dismissal was performed; unknown time stays unknown.

## Daily diary

Record after actual activity; no activity or no opportunity is valid. Separate
observed activity from self-report. Do not prefill five days as successful use.

| Date | Opportunity to use? | Prompted/scheduled/unprompted | Observed or self-reported | Actual job and result | Active minutes | Friction / evidence |
| --- | --- | --- | --- | --- | --- | --- |

## End-of-week comparison

| Task pair | Comparability / coverage adequate? | Baseline active seconds | oxAudit active seconds | Difference | Outcome / exclusion reason |
| --- | --- | --- | --- | --- | --- |

Difference = baseline minus oxAudit; positive means less active time in oxAudit.
Show blocked attempts separately, with time spent. Do not compute savings from
missing, learning-confounded, incomplete or inadequate-evidence attempts.

| Measure | Observed value and denominator / evidence |
| --- | --- |
| Real-work first actionable finding time, or none within observed period | |
| Actionable / reviewed; non-actionable / duplicate / unresolved counts | |
| Total triage and dismissal effort | |
| Handoff preparation and recipient clarification effort | |
| Recheck effort and coverage outcome | |
| Unprompted-use days / opportunity days; unknown days | |
| Completed / blocked / not-evaluated task counts | |
| Reliability incidents and investigation references | |

## Debrief and decision

- What work would the participant choose oxAudit for tomorrow, and why?
- What would send them back to their current workflow?
- Which specific decision did oxAudit help or hinder?
- What should change first, supported by observed effort or an incident?

Record actual answers below; quotes must be verbatim and attributed to the
pseudonym. Separate the participant's words from the facilitator's interpretation.

Study conclusion remains **pending** until observations exist. Participant-level
acceptance is separate from the cross-participant decision in the study guide.
