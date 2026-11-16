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

## Installing the CLI

All but the GitHub workflow install the CLI with
[`install-oxaudit.sh`](install-oxaudit.sh). Copy it into your repository as
`ci/install-oxaudit.sh` and set two values in the pipeline:

- `OXAUDIT_VERSION`: a release tag. The `sca` command and the `junit` and
  `gitlab-*` formats need a release newer than v0.2.7; until one is
  published, build the CLI from source
  (`cargo build --release --locked --manifest-path src-tauri/Cargo.toml --bin oxaudit-cli`)
  and put it at `.oxaudit-tool/oxaudit-cli` instead of running the script.
- `OXAUDIT_SHA256`: the digest of the asset for your runner, from that
  release's `SHA256SUMS.txt`.

The script downloads that one asset and refuses it unless the digest
matches. The templates ship with placeholders for both values and fail until
you replace them.

## In JUnit reports

A finding that fails the gate is a failed test. A finding that is reported
without failing (below `--fail-on`, a policy warning, a waived violation, a
dismissed advisory) is a skipped test with the reason in its message. A run
with nothing to report has one passing test, because test publishers treat
an empty report as an error.
