# Everyday engineering workflow

Approved direction: the September 7 project review and the user's instruction to implement all six priorities in order, committing and pushing each phase to GitHub main.

## Outcome

An engineer can reopen a project, inspect new issues, navigate to their editor, make a fix, and verify the result. Dependency findings explain the upgrade decision. Desktop and CI agree about incomplete coverage. First use has an installable pilot and an executable CI example.

## Delivery phases

1. Trustworthy results: reject incomplete dependency parsing before advisory lookup in both desktop and CLI; expose syntax/text evidence without claiming exploitability; add realistic paired regression scenarios and record corpus limitations.
2. Project home: use durable history, reopen recent projects/runs, restore project selection, show priority counts and freshness, and offer a project check that includes source and dependency work.
3. Review changes: expose new-since-baseline and Git change scope with base selection, staged/working-tree distinction, revision and coverage evidence. Subset scans must not resolve unscanned findings.
4. Fix and verify: preferred editor with exact position; actionable remediation; finding-specific recheck tied to compatible completed run evidence.
5. Dependency decisions: shared application workflow for desktop/CLI, durable CLI runs and baseline gating, dependency paths and grouped upgrade decisions. Unsupported relationship/version semantics are explicitly unknown rather than guessed.
6. Pilot adoption: installation and onboarding, executable CI setup, local distributable validation and a reproducible pilot task script. Signing credentials and actual feedback from other engineers cannot be fabricated.

## Constraints

- Keep scanning local and secrets redacted. Never execute repository scripts as part of scanning.
- Preserve project containment, resource budgets, cancellation, immutable evidence, review history, and policy authority.
- Unknown evidence is not safety. Incomplete work cannot be reported as a completed clean scan.
- Reuse existing domain/application and durable-run interfaces; do not create a competing scanner.
- Maintain compatibility with stored projections through defaults or explicit migrations.
- Test behavior, including failures and stale results. Run relevant checks and review before each push.
- Work on main and push origin main after each verified phase, explicitly authorized by the user. Never force push.

## Progress

- Phase 1: complete; dependency coverage failures, complete offline receipts, analysis evidence, and authored corpus additions verified.
- Phase 2: complete; durable project home, selection restoration, combined checks, cross-page cancellation, and result handoffs verified.
- Phase 3: complete; saved baseline selection, Git path review, revision/coverage evidence, policy-aware counts, and CLI baseline safety verified.
- Phase 4: complete; typed editor navigation, remediation examples, coverage-aware rechecks, and unsaved-result recovery verified.
- Phase 5: complete; shared durable dependency workflow, CLI baseline gates, bounded npm relationships, advisory-based upgrade decisions and native rechecks verified.
- Phase 6: implementation complete; first-project onboarding, reproducible CLI/desktop pilot, local artifact and CI corrections verified locally and reviewed. Platform/security execution is confirmed by the phase commit’s GitHub Actions checks.
