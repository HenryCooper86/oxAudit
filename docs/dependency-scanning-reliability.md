# Dependency scanning reliability

The desktop, CLI, and server dependency workflow uses `deps/service.rs` for
inventory, provider coverage, cancellation, durable run state, and offline
receipts. This refinement covers Bun inventory parsing and the shared OSV
client, plus provider cancellation and source-index efficiency in that workflow.

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
