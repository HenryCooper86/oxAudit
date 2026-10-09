# Dependency scanning reliability

The desktop, CLI, server, and research-tool dependency workflow uses `deps/service.rs` for
inventory, provider coverage, cancellation, durable run state, and offline
receipts. This refinement covers Bun inventory parsing and the shared OSV
client, plus provider cancellation and source-index efficiency in that workflow.
Research scans also persist canonical runs and immutable full-detail receipts.
Their compact response includes the run id, advisory coverage and inventory notes.

## Inventory and package identity

`bun.lock` accepts JSONC comments and trailing commas while preserving strings.
Registry coordinates come from the first package tuple element, rather than the
installation key. Aliases therefore query their resolved package name, and
nested installations retain their resolved versions. Empty inventories and
local-only workspaces are valid. Malformed package tuples fail the parse;
they cannot silently disappear from an otherwise successful inventory.

Local, git, and tarball resolutions have no registry version and are excluded
from Bun's npm advisory queries. Their code needs source or binary analysis.
Bun tuple shapes follow the [published format](https://bun.com/reference/bun/BunLockFile/packages),
and JSONC handling follows the [text lockfile description](https://bun.com/blog/bun-lock-text-lockfile).

Canonical npm relationships resolve every chain step by lockfile, ecosystem,
package identity and installation path. Multiple versions and identical paths
in different workspaces therefore link to their own evidenced components.
Missing or conflicting installation evidence produces no guessed edge.

Bundler inventories contain only four-space specification rows inside source
`specs:` sections. Nested dependency constraints are excluded. Ruby platform
suffixes are retained in occurrence evidence and separated from the registry
version. Git and local gems keep their declared version and source kind, but
receive no registry advisory or license lookup and no registry purl. They remain
distinct from registry components with the same name and version. These source
and platform limits are visible in the scan's inventory notes, including empty
advisory results. See the official [Bundler lockfile explanation](https://guides.rubygems.org/using_bundler_in_applications/#gemfilelock).

Go inventory comes from `go.mod` requirements, with version-specific and global
replacements applied. Remote replacements use the replacement module coordinates;
local replacements retain an unversioned source component and a warning. A
required version excluded by the manifest fails parsing because static scanning
cannot establish its replacement selection. Valid dependency-free manifests
produce an empty inventory. Malformed requirements, replacements, checksum rows
and unterminated blocks fail instead of silently dropping packages.

`go.sum` validates checksum row shape but contributes no installed components.
It requires a discovered sibling `go.mod`; standalone checksum history fails
with a coverage error. Go permits unused historical versions in
[checksum files](https://go.dev/ref/mod#go-sum-files), and a replacement may use
different module contents ([replace directives](https://go.dev/ref/mod#go-mod-file-replace)).
Static requirements are not a resolved transitive or workspace build list.
Every Go scan reports this limitation in `inventoryNotes`; complete advisory
coverage describes the queried declarations only. No package manager or project
dependency code is executed to infer a build list.
CLI text reports print these inventory notes as well. Dependency baselines
accept explicitly local, unversioned Go replacements while still rejecting
registry dependencies whose versions are missing.

## Complete, bounded advisory queries

Both version-specific queries and package searches follow OSV pagination,
including pages that contain only a token. Batch pagination sends only the
unfinished queries, preserving each package's own token and original identity.
Advisory ids are deduplicated across pages for each package. The four-package
regression fixture sends 4, 3, and 1 queries over three HTTP requests.

Every page validates response shape, advisory ids, token types, and batch result
count. Repeated tokens, failed later requests, truncated bodies, and exceeded
limits return errors instead of partial results. The shared workflow writes a
complete offline receipt only after page traversal and full-detail resolution
have succeeded. Existing receipt integrity and package-membership checks apply.

Offline selection searches receipts that cover every requested package and
version, newest first. Unrelated receipts are filtered in SQLite, with an index
on provider and freshness; one candidate payload is loaded at a time. Every
selected receipt passes content-hash, schema, count, membership and package
identity checks. Invalid covering candidates are discarded with a visible note
when an older valid receipt succeeds. The selected receipt's original timestamp
and identity are retained. Missing complete coverage fails, and validation stops
after 64 invalid covering candidates with an explicit resource-limit error.

Limits are 32 MiB of decompressed JSON per response, 64 pages per package query,
4 KiB per pagination token, 10,000 unique advisories per package, and 100,000
package/advisory matches per batch operation. Full-detail resolution retains its
existing 600 unique-advisory limit and concurrency of 20. These are input and
request limits, not a process-wide memory ceiling. Pagination behavior follows
the OSV [query](https://google.github.io/osv.dev/post-v1-query/) and
[batch query](https://google.github.io/osv.dev/post-v1-querybatch/) contracts.

## Cancellation and avoidable work

License, advisory, and exploitation-enrichment waits poll cancellation every
100 ms and drop pending provider futures when cancelled. The durable run becomes
cancelled and emits no completed result. Tests exercise providers that never
finish, rather than relying on a network timeout. Synchronous inventory parsing
and local source indexing still finish their current operation before observing
cancellation.

Source usage is indexed only when vulnerabilities were found. Empty inventories
skip license lookup. Existing dependency occurrence evidence and direct-usage
meaning are preserved; absence of a direct import does not prove unreachability.

## Repeatable checks

```sh
cargo test --locked --manifest-path src-tauri/Cargo.toml --workspace --all-features
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
npm test
npm run check
npm run build
```

HTTP regressions use a local server and do not depend on live OSV availability.
`tests/fixtures/osv_lodash.json` contains the
[GHSA-35jh-r3h4-6jhm provider record](https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm),
captured on 2026-10-09. The real-record parser test always runs using this
committed fixture, replacing its previous optional `/tmp` input.
