# Native binary extraction and reliability

The same native pipeline handles executables and libraries, firmware archives,
saved container images, and downloaded registry layers. This document describes
its resource limits and the regression checks added during the extraction review.

## Reading and extraction

Files are classified from a 4 KiB prefix. Text, localization catalogs, and empty
files stop there. Scannable files reuse that prefix and read the remaining bytes
once, up to the 128 MiB file cap. Components beyond the classification prefix
remain detectable. A file-read failure produces a coverage note; an inaccessible
inventory target produces an error.

Extraction stays in memory. Streamed members transfer their buffers into the
result instead of making an additional full-size copy. Reads stop at the smaller
of the per-member cap and the remaining total allowance, plus one probe byte.
Previously accepted members survive an extraction stop.

| Input | Regression coverage |
| --- | --- |
| Executables and libraries | Banners after the classification prefix; readable and unreadable files; `ar` member size and count limits |
| Firmware and nested archives | Compressed wrappers, tar/zip members, squashfs nesting, embedded magic-search stops, CramFS page bounds and sparse-file offsets |
| Container images and packages | Saved layer tars, verified OCI aliases, Debian/Alpine package identity, Maven inventory, cancellation during the final registry layer |

CramFS decoding follows the page and hole behavior in the
[Linux reader](https://raw.githubusercontent.com/torvalds/linux/master/fs/cramfs/inode.c).
Each decoded block is bounded to 4 KiB, raw blocks require the uncompressed flag,
and holes preserve the positions of later bytes. Corrupt compressed data is
skipped with an unreadable-content note.

## Limits and coverage

The defaults are 100,000 files and 20 GiB of inventory input, four file workers,
128 MiB per file/member, 20,000 retained members per extraction, three container
levels, and 8 GiB of accounted member bytes per extraction. CramFS directory
recursion also uses the depth limit. Compressed-wrapper staging buffers are
separately bounded by the per-member cap.

Per-member limit skips and decoder read errors are reported even when no member survives.
Archives yielding no members explicitly report that only raw bytes were scanned.
Embedded squashfs search limits reach the scan notes even when no filesystem
was extracted. Prefix truncation is reported even when no component was found.
These notes describe incomplete coverage; zero components does not establish
that skipped content was examined.

These are per-input budgets, not a process-wide memory ceiling. Extraction
still retains a container's member buffers before scanning them, and multiple
workers can hold separate containers. Cancellation is checked between files
and image layers and before an image result is returned; an individual codec
operation is not interruptible through the current extraction API. Streaming
members under a shared memory allowance and measuring peak RSS on large real
firmware/container corpora remain necessary to establish that performance bound.

## Repeatable checks

```sh
cargo test --locked --manifest-path src-tauri/Cargo.toml --workspace --all-features
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
npm test
npm run test:ci-shell
npm run check
npm run build
```

The byte-volume regression reads only 4 KiB from a 64 KiB text fixture, while a
binary fixture still detects a banner after that prefix. This verifies reduced
I/O without claiming a wall-clock throughput result. Archive tests exercise real
tar, zip, compression, squashfs, and committed CramFS inputs, including a corrupt
zip CRC and blocks that attempt to expand beyond a CramFS page.
