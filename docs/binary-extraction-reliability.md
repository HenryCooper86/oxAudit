# Native binary extraction and reliability

The same native pipeline handles executables and libraries, firmware archives,
saved container images, and downloaded registry layers. This document describes
its resource limits and the regression checks added during the extraction review.

## Reading and extraction

Files are classified from a 4 KiB prefix. Text, localization catalogs, and empty
files stop there. Scannable files reuse that prefix. Ordinary binaries and
random-access archives read at most 128 MiB; native tar files stream instead.
Registry spool files stream tar, gzip, xz, zstd and bzip2 layer tars without a
whole-layer buffer. A later layer member remains detectable even after the
128 MiB ordinary-file cap. A file-read failure produces a coverage note; an
inaccessible inventory target or missing registry spool file produces an error.

The native scanner uses extraction visitors: it scans and drops each member
before reading the next. Nested extraction retains container ancestors and the
current member, rather than every extracted member. Compression wrappers in the
random-access path still require a bounded staging buffer. Capped reads grow
without doubling capacity beyond their byte cap. String extraction writes ASCII
and UTF-16 runs directly into the final string blob, avoiding a second buffer
for a long printable run.

Reads stop at the smaller of the per-member cap and remaining member allowance,
plus one probe byte. Streamed layer tars additionally bound actual decoded bytes,
including tar framing and skipped oversized content. Known tar and ZIP member
lengths reject a partial member when a stream ends or a budget cuts it short.
Previously accepted detections survive a budget stop, with incomplete coverage
reported. Package detections are annotated after later `os-release` members or
registry layers arrive; Maven coordinates supersede weaker manifest identities
regardless of member order.

The existing archive `extract()` APIs remain collecting variants for callers
such as the corpus and fuzz harnesses. They retain their returned buffers; the
visitor API's retention benefit requires consuming rather than saving members.
The compatible in-memory image API also caps raw fallback and its string buffer
at 128 MiB, with a prefix coverage note; accepted archive members still stream.

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

The defaults are 100,000 files and 20 GiB of inventory input, up to four file
workers, 128 MiB per ordinary file/member, 20,000 visited members per extraction,
three container levels, and 8 GiB of accounted member bytes per extraction.
Streamed tar inputs separately stop at 8 GiB of decoded bytes including framing
and skipped content. CramFS directory recursion also uses the depth limit;
embedded filesystems inside members consume the remaining container depth.
Compressed-wrapper staging buffers are bounded by the per-member cap.

A process-shared native payload allowance reserves 1,153 MiB plus nine probe
bytes for each archive/opaque workspace, with a total of 2,306 MiB plus eighteen
bytes. This covers a capped input, two staging/member buffers per container
level, the string blob and scratch space. Executable workspaces reserve 385 MiB
plus three bytes. Four executable workers can run together, while at most two
archive workspaces can run together across directory scans, registry spool
scans and the compatible in-memory image scan API. Waiters observe cancellation
at 50 ms intervals. RAII releases reservations on success, read errors and
unwinding; extraction checks cancellation between members and bounded reads.

Per-member limit skips and decoder read errors are reported even when no member survives.
Archives yielding no members explicitly report that only raw bytes were scanned.
Embedded squashfs search limits reach the scan notes even when no filesystem
was extracted. Prefix truncation is reported even when no component was found.
These notes describe incomplete coverage; zero components does not establish
that skipped content was examined.

The shared allowance bounds reserved scanner payload work, not process RSS.
Codec dictionaries and decoder state, archive indexes, allocator overhead,
package/detection metadata, advisory enrichment and result storage are outside
that allowance. Inputs already retained by callers of the compatible
`scan_image_layers()` API are also outside it; registry pulls use owned spool
files and `scan_image_layer_files()` instead. An individual codec step may
continue until it next reads input or returns output. These limits do not
establish a memory or latency ceiling for hostile codec metadata, and large
real firmware/container corpora still need peak-RSS measurements.

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
binary fixture still detects a banner after that prefix. Archive tests exercise
real tar, ZIP, compression, squashfs and committed CramFS inputs, including a
corrupt ZIP CRC and blocks that attempt to expand beyond a CramFS page.

The 2026-10-09 resource regressions observed the following owned fixtures:

| Fixture | Observation |
| --- | --- |
| Twelve 64 KiB tar members | The collecting baseline retained 1,572,864 bytes of member capacity; the visitor regression bounds retained capacity at 65,537 bytes (one current member, including probe allowance). |
| Nested tar | Peak tracked payload capacity includes the active ancestor and current leaf, and excludes completed siblings. |
| Streamed tar with an oversized member | A later BusyBox member is retained; a 4,096-byte decoded-stream limit reads at most 4,097 bytes and preserves earlier members. |
| Sparse tar with a member beyond 128 MiB | BusyBox remains detectable. One direct local debug-test run took 0.19 seconds with 27,377,664 bytes (26.1 MiB) maximum RSS, measured by `/usr/bin/time -l`. |

Capacity tracking counts simultaneous member/wrapper vectors during extraction;
it excludes the input, decoder/page/table allocations and buffers saved by a
visitor. The RSS observation includes the debug test process and its fixture
setup. It is one local synthetic measurement, not a production throughput or
worst-case memory claim. Focused validation passed 67 archive tests and 141
native pipeline tests. The coupled binary suite passed 216 tests, including
localhost registry checks for stalled manifest/body cancellation within 500 ms,
understated actual layer/aggregate byte limits, declared-byte overflow and
verified private spool cleanup. Strict Clippy passed for the archive crate.
