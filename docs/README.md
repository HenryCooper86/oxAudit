# oxAudit documentation

Start with [Install and run oxAudit](getting-started.md). The
[project README](../README.md) is the feature overview, and the
[changelog](../CHANGELOG.md) lists what changed in each release.

## User guides

How to install, run and rely on oxAudit today.

- [Install and run oxAudit](getting-started.md): published releases, platform
  matrix, verification, source builds, and the consumer CI workflow.
- [oxaudit-cli reference](cli.md): every subcommand and option.
- [The headless server](headless-server.md): the workbench in a browser,
  from the container image or a source build.
- [The local advisory database](advisory-database.md): offline dependency
  matching, coverage and comparison rules.
- [Scan reliability and recovery](project-reliability.md): scan ownership,
  saved evidence and recovery.
- [Compliance readiness and professional reporting](compliance-and-reporting.md).
- [Local pilot protocol](pilot-validation.md), the
  [one-week daily workbench pilot](daily-workbench-pilot.md) and its
  [blank scorecard](daily-workbench-scorecard.template.md).

## How the scanners work

Method, evidence and stated limits for specific engines.

- [Binary component signatures](binary-signatures.md) and
  [native binary extraction](binary-extraction-reliability.md).
- [Dependency scanning reliability](dependency-scanning-reliability.md).
- [Durable Git-history evidence](history-validation.md).
- [Local image content identity](local-image-identity.md).
- [Function-level reachability scoping](reachability-scoping.md).
- [Regression corpus](corpus.md) and
  [quality and performance validation](quality-performance-validation.md).

## Maintainer documents

- [Release checklist](release-checklist.md) and [release notes](releases/).
- [Dependency maintenance](dependency-maintenance.md).
- [Design system](design-system.md).
- [Architecture decision records](architecture/adr/).

## Internal studies, plans and records

Dated working material: research, design plans, QA logs and validation
records. Useful for history and rationale; not instructions for using the
current release, and parts may describe superseded states.

- Studies: [binary-scanning runtime evaluation](binary-scanning-runtime.md),
  [VulHunt](vulhunt-study.md), [VulnHunter](vulnhunter-study.md),
  [y-agent adoption](y-agent-adoption.md),
  [y-agent adoption report](y-agent-adoption-report.md),
  [y-agent port candidates](y-agent-port-candidates.md).
- Architecture studies and status: [architecture/](architecture/).
- Plans, specs and their acceptance records: [superpowers/](superpowers/).
- QA logs and pilot evidence: [qa/](qa/).
- Dated validation records:
  [alert evidence, 2026-10-09](alert-evidence-validation-2026-10-09.md),
  [reliability, 2026-10-09](project-reliability-validation.md), and the
  JSON measurement files in this directory.
