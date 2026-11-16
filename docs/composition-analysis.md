# Software composition analysis

`oxaudit-cli sca` answers four questions about a project's third-party
components in one run:

- What is each component licensed under, and does the project accept that?
- Is the release deprecated, old, or far behind the current one?
- Does it have open advisories severe enough to block?
- Has someone approved or rejected this component by name?

`oxaudit-cli portfolio` then reads those answers across every project stored
in one database.

Both commands sit on the dependency scan `deps` already runs. The inventory,
the advisory match, the stored run and its SBOM exports are the same; `sca`
adds classification and a policy verdict on top.

```sh
# Report only: classify licenses, collect release facts, list violations.
oxaudit-cli sca .

# Keep the run so the portfolio and SBOM exports can read it, and write an
# attribution inventory.
oxaudit-cli sca . --db ~/.oxaudit/findings.db --notices THIRD-PARTY-NOTICES.md

# Which projects are failing policy, and where is this package used?
oxaudit-cli portfolio summary --db ~/.oxaudit/findings.db
oxaudit-cli portfolio where-used --db ~/.oxaudit/findings.db lodash
```

## What `sca` does not claim

- A license category is engineering triage from the license a package
  declares. It is not legal advice. oxAudit does not read package contents
  during a dependency scan, so a package whose files carry a different
  license than its metadata is classified by its metadata.
- A component with no violation has not been cleared. It means no rule in
  the policy matched what was known about it.
- Without a policy file nothing is judged. The report still classifies every
  component, and says that no policy was applied.
- oxAudit has no snippet or code-fingerprint database. It identifies
  components from lockfiles, manifests, package databases and binaries, not
  from copied source fragments.

## The component policy

The policy lives in `.oxaudit/component-policy.json`, committed with the
project like the other gate files. Each rule answers `deny` (a violation that
makes `sca` exit 1), `warn` (reported, never failing) or `allow`.

```json
{
  "version": 1,
  "licenses": {
    "deny": ["category:strong-copyleft", "category:network-copyleft", "SSPL-1.0"],
    "warn": ["category:weak-copyleft"],
    "allow": ["LGPL-2.1-only"],
    "unknown": "warn"
  },
  "operational": {
    "deprecated": "deny",
    "maxAgeDays": { "warn": 730, "deny": 1825 },
    "maxMajorVersionsBehind": { "warn": 2 },
    "staleAfterDays": { "warn": 1095 },
    "unknown": "allow"
  },
  "vulnerabilities": { "deny": "critical", "warn": "high" },
  "components": [
    {
      "ecosystem": "npm",
      "package": "left-pad",
      "decision": "rejected",
      "reason": "Unmaintained; use String.prototype.padStart"
    },
    {
      "ecosystem": "Maven",
      "package": "org.example:reporting",
      "version": "4.2.0",
      "decision": "approved",
      "reason": "Legal review LGL-118: used as a separate service",
      "expiresAt": "2027-06-30T00:00:00Z"
    }
  ]
}
```

Every section is optional. The file is strict: an unknown key, a license id
this build does not classify, or one license listed under two actions is an
error (exit 2), because a typo must not silently loosen a gate. The file is
read without following symlinks and is limited to 1 MiB. `--policy FILE`
judges against another file instead. `--ignore-invalid-policy` reports
without an invalid policy and says so. `--report-only` lists violations and
exits 0.

### License rules

An entry in `deny`, `warn` or `allow` is one of:

| Entry | Matches |
| --- | --- |
| `MIT`, `GPL-3.0-only` | That SPDX license. Deprecated ids are read as their current form (`GPL-2.0` is `GPL-2.0-only`, `GPL-2.0+` is `GPL-2.0-or-later`) |
| `GPL-2.0-only WITH Classpath-exception-2.0` | That license with that exception, exactly |
| `category:strong-copyleft` | Every license in the category |
| `text:Acme Internal License` | A declared license text that matched nothing, compared without case |

The most specific entry wins: the exact license, then the declared text, then
the category.

| Category | Examples |
| --- | --- |
| `public-domain` | CC0-1.0, Unlicense |
| `permissive` | MIT, BSD-3-Clause, Apache-2.0, ISC |
| `weak-copyleft` | LGPL, MPL-2.0, EPL-2.0, CDDL |
| `strong-copyleft` | GPL, EUPL, CC-BY-SA |
| `network-copyleft` | AGPL, OSL-3.0 |
| `source-available` | SSPL-1.0, BUSL-1.1, Elastic-2.0 |
| `non-commercial` | CC-BY-NC, PolyForm-Noncommercial |
| `proprietary` | `UNLICENSED`, `Proprietary`, `Commercial` |
| `unknown` | No declared license, or text that could not be resolved |

How a declaration is read:

- `A OR B` lets the licensee choose, so the operand the policy likes best
  decides. `MIT OR GPL-3.0-only` is allowed when MIT is.
- `A AND B` binds to both, so the operand the policy likes least decides.
- A recognised linking exception (`Classpath-exception-2.0`,
  `GCC-exception-3.1`, `LLVM-exception` and similar) turns strong copyleft
  into weak copyleft. A rule that names the bare license does not reach the
  exception form; list the `WITH` form to name it. An exception this build
  does not recognise changes nothing.
- Free text from registries is resolved where it is unambiguous
  (`Apache License, Version 2.0` is `Apache-2.0`). Text that names a family
  without a version (`BSD`, `GPL`) gets the family's category and no id.
  Anything else is `unknown`, never assumed permissive.

`unknown` sets the action for undeclared and unclassified licenses and
defaults to `allow`. `allowOnly: true` denies every classified license that
no `allow` entry matches; it requires `unknown` to be set, because an
unclassified license is on no list.

Licenses come from the same sources as SBOM exports: npm lockfiles carry
them, and online scans read PyPI, crates.io, RubyGems, Packagist and Maven
Central, up to 500 packages per run. Go and NuGet have no single-request
license source and stay `unknown`. An offline scan has only what the
lockfile states.

### Operational rules

These read release facts collected from the [deps.dev](https://deps.dev)
package index: one request per distinct package, up to 500 per run, for npm,
PyPI, Maven, crates.io, Go, NuGet and RubyGems.

| Rule | Fires when |
| --- | --- |
| `deprecated` | The registry marks the installed version deprecated |
| `maxAgeDays` | The installed version was published at least this many days ago |
| `maxMajorVersionsBehind` | The installed major version trails the registry's default release by at least this many |
| `staleAfterDays` | The package's newest release of any version is at least this old |
| `unknown` | No release facts are available for the component |

A rule fires only on a fact the index stated. A package the index does not
cover, a failed lookup, or a version it does not list leaves the fact
unknown, and only the `unknown` rule (default `allow`) reacts to that.

Collecting release facts sends package names and nothing else to
`api.deps.dev`. `--no-release-facts` skips it; `--release-index URL` points
at a mirror. With `--db`, the answer is stored as a receipt: `--offline`
reuses the newest receipt that covers the inventory, checked against its
content hash, and the portfolio reads the same receipts. When the policy has
operational rules and no facts were collected, the report states that those
rules were not evaluated.

### Vulnerability rules

`vulnerabilities.deny` and `vulnerabilities.warn` name a severity; a
component with an open advisory at or above it is a violation. Advisories
dismissed in `.oxaudit/advisory-policy.json` are not open. This is separate
from `--fail-on`, which `sca` also accepts and which works as in `deps`.

### Component decisions

A `components` entry names an ecosystem and package, optionally one version.

- `rejected` is a `deny` violation wherever the component appears.
- `approved` waives that component's license and operational violations.
  They stay in the report, marked waived with the reason. An approval does
  not waive advisories: accept those in the advisory policy, which names the
  advisory being accepted.

`reason` is required. `expiresAt` ends a decision; an expired approval stops
waiving and the report notes it. The last matching unexpired entry wins.
Package names compare the way their registry compares them.

## Direct and transitive components

The report marks each component direct, transitive or unknown. That comes
from the lockfile's own relationship evidence, which also drives the
dependency-path view in the desktop:

| Lockfile | Relationship evidence |
| --- | --- |
| `package-lock.json` v2/v3, `npm-shrinkwrap.json` | Yes |
| `Cargo.lock` | Yes. Dependency type is unknown: the lockfile merges normal, build and dev dependencies |
| `pnpm-lock.yaml` | Yes, per importer |
| `uv.lock` | Yes |
| `Gemfile.lock`, `gems.locked` | Yes. Groups are not recorded, so type is unknown |
| `packages.lock.json` | Yes, per target framework |
| `yarn.lock` (classic), `poetry.lock`, `pdm.lock`, `composer.lock`, `mix.lock` | No. The lockfile does not say which packages the project declares directly, and sibling manifests are not read |
| `bun.lock`, `deno.lock`, `yarn.lock` (berry) | Not yet. These record both edges and roots, but are not read for relationships |
| `go.mod`, `pubspec.lock`, `Pipfile.lock`, `requirements.txt`, `pom.xml`, `gradle.lockfile`, .NET project files | No. No dependency edges are recorded |

Where there is no evidence the component is reported as unknown, not as
transitive. Traversal is bounded as for npm (20,000 visits, depth 64, 32
chains per package); a cycle, an unresolved edge or a truncated traversal
marks the affected evidence partial with a warning.

## Output

| `--format` | Content |
| --- | --- |
| `text` | Counts, then violations: denied first, then warnings, then waived |
| `json` | The full report: `summary`, `components`, `violations`, `disclaimer` (`schemaVersion: 1`, `kind: "sca"`) |
| `junit` | One test case per violation and per advisory. A `deny`, or an advisory at or above `--fail-on`, is a failure; everything else is skipped |
| `gitlab-code-quality` | Unwaived violations and open advisories, located on the lockfile |
| `gitlab-dependency-scanning` | Open advisories in GitLab's schema 15 |

`--notices FILE` writes a Markdown inventory of every registry component
grouped by declared license. It is an attribution inventory: it does not
reproduce license texts or copyright lines, and says so in its header.

SBOM and VEX formats come from the stored run, as before:
`oxaudit-cli export --db DB --run RUN --format cyclonedx`.

Exit codes follow the rest of the CLI: `0` nothing denied, `1` a `deny`
violation or an advisory at or above `--fail-on`, `2` usage (including an
invalid policy), `3` the scan failed.

## Portfolio

Every `sca --db` or `deps --db` run stores its inventory. `portfolio` takes
the latest completed dependency run of each scanned directory in a database
and rebuilds its report. Stored runs are never modified.

| Command | Shows |
| --- | --- |
| `portfolio summary --db DB` | One row per project: components, denied and warned violations, components with open advisories, last scan. Failing projects first. `--fail-on-deny` exits 1 when any project fails |
| `portfolio components --db DB` | Every package, most widely used first, with the versions each project pins and the worst verdict |
| `portfolio where-used --db DB NAME` | Each project using the package, its version, license and whether it is direct. `--ecosystem` and `--version` narrow it |
| `portfolio history --db DB --target DIR` | One row per stored run of one project, newest first, up to the newest 100 dependency runs in the database |

All take `--json` and `-o FILE`.

By default each project is judged against its own committed policy, read
from its directory when that still exists on this machine. A project whose
directory is gone, or that has no policy, is shown as judged with no policy,
and the summary counts those so a `PASS` there is not read as approval.
`--policy FILE` judges every project against one organisation policy.

Two limits to keep in mind:

- The portfolio reflects each project's last stored run. A component added
  since then is not in it. Scheduled `sca --db` runs keep it current, and
  `monitor` covers new advisories against stored inventories.
- `history` judges past runs with the policy in force now, so it shows how
  the inventory moved, not what the verdict was at the time.

## In CI

`sca` is built to be the one dependency step in a pipeline: run it once
online with `--db`, then re-render other formats with `--offline` from the
same stored run.

- GitHub Actions: the [composite action](../action/action.yml) takes
  `command: sca`. Under Actions, `sca` also writes a job summary.
- GitLab CI, Jenkins, Azure Pipelines, Bitbucket Pipelines and CircleCI:
  templates are in [`examples/ci/`](../examples/ci/README.md).

`scan` and `deps` accept `--format junit` and `--format gitlab-code-quality`
as well, and `deps` accepts `--format gitlab-dependency-scanning`.
