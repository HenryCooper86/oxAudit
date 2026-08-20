# Binary component signatures: method and provenance

> Written 2026-08-20, alongside `src-tauri/src/binscan/native/`.

oxAudit detects components inside compiled binaries with its own scanner. This
document records how the signatures were made, why they were made rather than
borrowed, and what the method can and cannot do.

## 1. Why not just use cve-bin-tool's checkers

cve-bin-tool established the method and its ~365 checkers are the best public
collection of these patterns. They are also **GPL-3.0-or-later**, with an SPDX
header on every file. Transcribing them into Rust would produce a derivative
work, and oxAudit would have to be GPL-3.0 to ship it.

The distinction that matters:

| | Licence consequence |
|---|---|
| Running an installed cve-bin-tool as a subprocess | None — arms length |
| Copying or translating its checker files | Derivative work; oxAudit becomes GPL-3.0 |
| Implementing the same **method** from our own patterns | None — a method is not copyrightable |

The third is what we did. It is also the only option that survives the fact
that oxAudit currently ships **no LICENCE file at all**, which means all rights
reserved and no defined relationship to GPL code. That gap should be closed
regardless of this decision.

## 2. The method

Unchanged in shape from what cve-bin-tool demonstrated, because it is correct:

1. Decide whether a file is worth reading (`filetype.rs`).
2. Extract its printable strings (`strings.rs`).
3. Match signatures over the strings; capture a version (`signature.rs`).

Three things are ours and are improvements:

- **A single `RegexSet` pass.** cve-bin-tool evaluates checkers one at a time,
  rescanning the same strings for each. Every pattern here goes into one set,
  so one pass names the candidates and only those run their capture regexes.
  Measured on the same 21,279-file tree: **0.5 s against 300 s**.
- **The ELF package note is read** (`package_note.rs`). See §4.
- **Linear-time matching.** Rust's `regex` crate cannot backtrack, so a
  pathological pattern cannot hang a scan on a hostile firmware image. Python's
  engine can.

## 3. How a signature is made

`tools/derive-signatures.py` takes a root filesystem that still has its package
metadata, reads the version the package manager recorded for each package, and
prints the strings inside that package's binaries containing that version.

```
$ python3 tools/derive-signatures.py rootfs curl
### curl 8.14.1-2+deb13u4  (upstream 8.14.1, 1 ELF files)
    [1] 'curl 8.14.1 (aarch64-unknown-linux-gnu) %s'
    [1] 'curl/8.14.1'
```

The ground truth is the package manager's own record, so this is not circular:
we are shown what a binary of a *known* version actually contains. Choosing an
anchor from that output is a judgement call, and the reasoning is written next
to each signature in `signatures.toml`.

### Three rules, each learned by getting it wrong

**Never capture an ELF symbol-version tag.** `libcrypto.so.3` carries nine
`OPENSSL_3.x` tags, `libz` fourteen `ZLIB_1.2.x`, `libxml2` forty-odd
`LIBXML2_2.x`. These are the ABI versions a library *can serve*, not the version
it *is*. A pattern like `OPENSSL[_ ]([0-9.]+)` reports nine phantom OpenSSLs for
every real one. Anchoring on mixed case — `OpenSSL ` and never `OPENSSL_` — is
usually enough.

**Anchor on prose, not digits.** A bare `1.5.7` in a binary is evidence of
nothing. `inflate 1.3.1 Copyright 1995-2024 Mark Adler` is evidence of zlib.

**A mention is not a declaration.** Python's `_hashlib` contains the sentence
"For OpenSSL 3.0.0 and newer it returns the state of the digest". A pattern
requiring only `OpenSSL <version>` reads that as a linked OpenSSL 3.0.0. The
fix is to require the release date that `OPENSSL_VERSION_TEXT` always carries:
`OpenSSL 3.5.6 7 Apr 2026`. This was a measured false positive on a real tree,
and there is a regression test carrying both strings.

**And one thing not to do:** if a library has no version string, do not invent a
weak pattern. zstd, sqlite3, pcre2 and liblzma have nothing but symbol tags. A
guess there is worse than silence, because §4 identifies them exactly.

## 4. The ELF package note

Debian, Fedora and others stamp binaries with a `.note.package` entry — the
[ELF package metadata](https://systemd.io/ELF_PACKAGE_METADATA/) convention:
owner `FDO`, type `0xcafe1a7e`, JSON payload.

```json
{"type":"deb","os":"Debian","name":"libzstd","version":"1.5.7+dfsg-1","architecture":"arm64"}
```

This is a statement by the builder rather than an inference, and it exists in
libraries that carry no version string at all. Reading it is why the native
scanner finds `libzstd 1.5.7`, which cve-bin-tool misses entirely and grype
misses too. Neither reads this note structurally.

The version is normalized to upstream — `1:8.14.1-2+deb13u4` → `8.14.1` —
because advisory feeds key on upstream numbers. Skipping that step is why
grype's `mariadb 1:11.8.6-0+deb13u1` and cve-bin-tool's `mariadb 11.8.6` fail to
merge into one row today.

## 5. What this cannot do

- **Coverage is 22 signatures, not 365.** They are the libraries that dominate
  firmware findings, and the package note covers much of the rest on any
  distribution-built target. A vendor-built stripped binary of something
  uncovered will be missed. Extending coverage is mechanical: run the harness
  against a corpus containing it.
- **Signatures are build-dependent.** cve-bin-tool misses zstd on Homebrew
  because its checker requires the version adjacent to an error string and that
  build lays it out differently. Ours will have equivalent blind spots.
- **A detection is not a vulnerability.** The scanner reports components; CVE
  enrichment through oxAudit's existing NVD and OSV clients is the next step and
  is not built yet.
