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
# RubyGems, Packagist, NuGet) and build the database.
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
  and `SEMVER`-typed ranges anywhere), PEP 440 (PyPI), Debian policy §5.6.12
  (Debian, Ubuntu, Alpine), Maven `ComparableVersion` (Maven), RubyGems
  (RubyGems), dotted-numeric-with-prerelease (NuGet, Packagist).
- **`GIT` ranges are skipped.** They name commits, not releases; those
  advisories match only through their explicit affected-versions lists. The
  skip is counted and surfaced.
- **A comparison the comparator refuses to make keeps the advisory** — the
  same trade the dataflow analysis makes: undetermined is reported, not
  dropped, and the refusal is counted in `advisoryNotes` with examples.
  Refused shapes include unknown Maven qualifiers (`LATEST`, vendor-specific
  tokens) and non-version strings.
- **Package names normalize per ecosystem rules** exactly as the registry
  does: PEP 503 folding for PyPI, case-folding for npm, exact elsewhere.
