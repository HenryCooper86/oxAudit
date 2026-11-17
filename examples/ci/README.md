# CI templates

Each template runs the same four steps and differs only in how the CI system
shows the result.

1. `scan` the source tree, gated at `--fail-on high`.
2. `sca` the third-party components once, online, into a database. This
   fails on a `deny` violation of `.oxaudit/component-policy.json`. See
   [Software composition analysis](../../docs/composition-analysis.md).
3. Re-render that stored run in other formats with `--offline`, so
   advisories are looked up once.
4. Export a CycloneDX SBOM of the same run.

A failed gate does not stop the later steps; the job exits with the worst
exit code after every report is written.

| CI system | Template | Where findings appear |
| --- | --- | --- |
| GitHub Actions | [`oxaudit.yml`](oxaudit.yml), or the [composite action](../../action/action.yml) | Annotations, job summary, code scanning (SARIF) |
| GitLab CI | [`gitlab-ci.yml`](gitlab-ci.yml) | Code Quality widget, Dependency Scanning report, Tests tab |
| Jenkins | [`Jenkinsfile`](Jenkinsfile) | JUnit test results |
| Azure Pipelines | [`azure-pipelines.yml`](azure-pipelines.yml) | Pipeline issues linked to files, Tests tab, SARIF artifact |
| Bitbucket Pipelines | [`bitbucket-pipelines.yml`](bitbucket-pipelines.yml) | Tests tab |
| CircleCI | [`circleci-config.yml`](circleci-config.yml) | Tests tab |

## Runner requirements

The published Linux CLI is built on Ubuntu 24.04 and needs glibc 2.39 or
newer: Ubuntu 24.04, Debian 13, Fedora 40 and later. On Debian 12, Ubuntu
22.04 or RHEL 9 it fails to start with a `GLIBC_2.39 not found` error. The
templates name images that satisfy this; for an older runner, build the CLI
from source on that system.

## Installing the CLI

All but the GitHub workflow install the CLI with
[`install-oxaudit.sh`](install-oxaudit.sh). Copy it into your repository as
`ci/install-oxaudit.sh` and set two values in the pipeline:

- `OXAUDIT_VERSION`: a release tag. The `sca` command and the `junit` and
  `gitlab-*` formats need v0.3.1 or later.
- `OXAUDIT_SHA256`: the digest of the asset for your runner, from that
  release's `SHA256SUMS.txt`.

The script downloads that one asset and refuses it unless the digest
matches. The Bitbucket and CircleCI templates read both values from
repository variables. The GitLab, Jenkins and Azure templates ship pinned to
v0.3.1 with the digest of
`oxaudit-cli-linux-x86_64` (`7ee0e7a31fad9acd6e2771585c65be7b38980f550badad1a3824a28f7d4278fc`),
which suits the Linux x86_64 runners they name. On another architecture, use
that asset's line from `SHA256SUMS.txt`. Move both values together when you
take a later release.

## In JUnit reports

A finding that fails the gate is a failed test. A finding that is reported
without failing (below `--fail-on`, a policy warning, a waived violation, a
dismissed advisory) is a skipped test with the reason in its message. A run
with nothing to report has one passing test, because test publishers treat
an empty report as an error.
