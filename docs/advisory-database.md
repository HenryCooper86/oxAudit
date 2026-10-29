# The local advisory database

`oxaudit-cli deps` answers advisories online by asking OSV's API, which owns
ecosystem-correct version matching. The advisory database is the offline
counterpart: OSV's published per-ecosystem dumps, ingested into a local SQLite
file, matched by the same engine with the comparison rules carried locally.

A scan answered from the database and a scan answered by the network produce
the same finding shape and the same evidence, because both go through the same
record parser.

## Build and refresh

```bash
# Download the default ecosystems (npm, PyPI, Maven, crates.io, Go,
# RubyGems, Packagist, NuGet, Hex, Pub) and build the database.
oxaudit-cli advisory-db update --db ~/.oxaudit/advisories.sqlite3

# Add distro ecosystems on top of the defaults; repeatable.
oxaudit-cli advisory-db update --db ~/.oxaudit/advisories.sqlite3 \
  --ecosystem Debian:12 --ecosystem 'Alpine:v3.20'

# What does it cover, and how fresh is it?
oxaudit-cli advisory-db status --db ~/.oxaudit/advisories.sqlite3
```

The dump source is OSV's published bucket
(`osv-vulnerabilities.storage.googleapis.com`); `--source` points at a mirror
when the bucket is unreachable. The database file sits in a directory created
owner-only. Re-running `update` re-downloads and replaces rows idempotently;
the coverage list only advances after **every** requested ecosystem ingested
completely, so a failed update can leave inert extra rows but never widens
what queries are allowed to answer.

Downloads and ingestion are bounded: 2 GiB per ecosystem dump, 16 MiB per
advisory record, 300,000 records per ecosystem. A malformed record fails the
update **by name** — a half-populated database must not be presented as
coverage.

## Scanning against it

```bash
# Advisories answered by the database; works with --offline (no network at
# all, including enrichment) or without it (exploitation enrichment online).
oxaudit-cli deps . --advisory-db ~/.oxaudit/advisories.sqlite3 --offline
```

The summary reports `advisorySource: "local-db"` with
`advisoryFetchedAtMs` set to the database's build time — the answer is exactly
as fresh as the dump it was built from, and the Dependencies page shows the
same staleness warning as cached receipts. Every answer is persisted as an
immutable provider snapshot (`local-advisory-db`), so advisory evidence keeps
the same auditability online and offline.

The desktop app does the same without the CLI: the Dependencies page's
**Local advisory database** switch answers that scan from a database file
(prefilled with the app's default `advisories.sqlite3`), and the Advisory
Database page builds and refreshes that file. The same coverage discipline
applies — an ecosystem the file does not carry fails the scan as incomplete
coverage, never as a clean result.

## Image scans

`oxaudit-cli image <saved-image.tar>` reads the image's own package
databases (dpkg, apk) against its `os-release` and answers those packages
from a local database with `--advisory-db` — a fully offline image scan.
Ecosystems the database does not carry (a bare `Debian` from an ELF package
note, an undownloaded release) are named in the run notes rather than
silently answering nothing; CPE-keyed signature detections have no offline
source, and an offline run says so instead of implying a clean result. JAR
coordinates read from embedded `pom.properties` answer from the database the
same way — Maven ships in the default ecosystem set.

## Registry references

`oxaudit-cli image` accepts a registry reference
(`registry.example.com/ns/repo:tag`) and pulls the manifest and layers
itself: the registry's bearer-token challenge answered anonymously or with
`docker login`'s config.json (Basic credentials and identity tokens;
credential helpers are stated as unhandled rather than silently skipped),
manifest lists resolved to this machine's `linux/<arch>` manifest, every
blob verified against its `sha256` digest before scanning. Manifests are
capped at 16 MiB, layers at 1 GiB each and 8 GiB per image. `--offline`
still governs advisory providers only — the image you explicitly asked to
fetch still downloads.

## Coverage discipline

Coverage is per ecosystem: a query for an ecosystem whose dump was not
downloaded fails the scan as an **incomplete advisory coverage** error naming
the ecosystems, never a clean result. A record from the npm dump that also
lists a PyPI package is indexed under both names, but until the PyPI dump has
been downloaded, PyPI queries still fail as uncovered.

## Matching rules and stated limits

- **Ranges follow the OSV schema**: `introduced`/`fixed` intervals are
  half-open, `last_affected` is inclusive, `limit` is exclusive, intervals
  union in event order, and explicit `versions` lists add exact matches.
- **Version comparison is per ecosystem spec**: semver (npm, crates.io, Go,
  Hex, and `SEMVER`-typed ranges anywhere), Dart's `pub_semver` ordering
  (Pub: build metadata is significant and sorts after the release it
  annotates, so `1.0.0-pre < 1.0.0-pre+build < 1.0.0 < 1.0.0+build`), PEP 440
  (PyPI), the Debian-style epoch/upstream/revision comparator of policy
  §5.6.12 (Debian and Ubuntu), apk-tools' `apk_version_compare` (Alpine,
  Wolfi, Chainguard, MinimOS, CleanStart, Alpaquita and BellSoft Hardened
  Containers), rpm's `rpmvercmp` over `[epoch:]version[-release]` (Rocky
  Linux, AlmaLinux, Red Hat, SUSE, openSUSE, Mageia, Photon OS, Azure Linux
  and openEuler), Maven `ComparableVersion` (Maven), RubyGems (RubyGems),
  and dotted-numeric-with-prerelease (NuGet, Packagist). A distribution
  ecosystem takes its comparator bare or release-qualified (`Debian`,
  `Alpine:v3.20`, `Rocky Linux:9`, `Red Hat:enterprise_linux:9::appstream`,
  `SUSE:Linux Enterprise Server 15 SP5`); the release never changes the
  version scheme.
- **apk pre-releases sort below their release.** `1.2.3_rc1` (likewise
  `_alpha`, `_beta`, `_pre`) is older than `1.2.3`, while `_cvs`, `_svn`,
  `_git`, `_hg` and `_p` snapshots are newer, and `-rN` revisions order
  after the version, so a release candidate of a fixed version is still
  reported as affected. Versions apk itself rejects (`1.9.5p2`, `v1.2.3`,
  uppercase suffixes) are refused.
- **RPM epochs default to 0 and a missing release sorts first.** A fix
  recorded as `0:4.15-11.el9_8` (Rocky Linux and Red Hat spell the epoch)
  equals an installed `4.15-11.el9_8`, `~` sorts before the end of a
  version and `^` after it, and a version without a release sorts below the
  same version with one, as rpm's `rpmverCmp` orders them. Non-ASCII or
  whitespace, a `:` outside the epoch, or more than one `-` is refused —
  rpm never builds such a version, and rpm and OSV split it differently.
- **Ecosystems without a comparator stay unmatched.** `Linux`, `Android`,
  Echo and any other scheme not listed above have their ranges reported as
  undetermined rather than guessed, and the advisory is kept as described
  below. (OSV itself lists Photon OS without a comparator; oxAudit compares
  it with rpm's ordering, which Photon's packages use.)
- **`GIT` ranges are skipped.** They name commits, not releases; those
  advisories match only through their explicit affected-versions lists. The
  skip is counted and surfaced.
- **A comparison the comparator refuses to make keeps the advisory** — the
  same trade the dataflow analysis makes: undetermined is reported, not
  dropped, and the refusal is counted in `advisoryNotes` with examples.
  Maven no longer refuses unknown qualifiers: Guava's `-jre`/`-android`,
  Jetty's `.v20210629` and `LATEST` follow `ComparableVersion` ordering,
  compared case-insensitively and sorted after every known qualifier. Only an
  empty Maven version, or one containing whitespace or non-ASCII characters,
  is refused; other refused shapes are non-version strings in the remaining
  ecosystems.
- **Package names normalize per ecosystem rules** exactly as the registry
  does: PEP 503 folding for PyPI, case-folding for npm, exact elsewhere.
