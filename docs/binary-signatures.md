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
guess there is worse than silence — §4 identifies them exactly on a
distribution build, and §6 reads them out of the code on any build.

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

- **Coverage is 71 signatures, not 365.** They are the components that dominate
  firmware findings (see §7), and the package note covers much of the rest on
  any distribution-built target. A vendor-built stripped binary of something
  uncovered will be missed. Extending coverage is mechanical: run the harness
  against a corpus containing it.
- **Signatures are build-dependent.** cve-bin-tool misses zstd on Homebrew
  because its checker requires the version adjacent to an error string and that
  build lays it out differently. Ours will have equivalent blind spots.
- **A detection is not a vulnerability.** The scanner reports components;
  CVE enrichment runs through oxAudit's existing NVD and OSV clients
  (`native/enrich.rs`: signature detections to NVD by CPE, package-note
  detections to OSV by distro ecosystem, then KEV/EPSS/Exploit-DB signals on
  whatever was found).


## 6. Versions compiled in as numbers

A library with no version *string* often still has a version *constant*, in a
function that returns it. zstd's `ZSTD_versionNumber` is one instruction:

```
x86-64   f3 0f 1e fa  b8 0b 29 00 00  c3     endbr64; mov eax, 0x290b; ret
AArch64  60 21 85 52  c0 03 5f d6            movz w0, #0x290b; ret
```

`0x290b` is 10507; `1 * 10000 + 5 * 100 + 7` is 1.5.7. A byte pattern that pins
the instruction and captures the operand reads that version out of a stripped
binary. The technique comes from VulHunt — see `vulhunt-study.md`.

```toml
  [[signature.byte_patterns]]
  pattern = "f3 0f 1e fa b8 .. .. 00 00 c3"
  capture_offset = 5
  encoding = "u32-le"
  formula = "decimal-10000"
  min = 10000
  max = 19999
```

`.` is a wildcard nibble, so `..` is any byte and `5.` is any byte in
`0x50..=0x5f`. Masking at nibble granularity is what lets a pattern pin an
opcode while leaving a register or operand free.

Eight libraries use this today, each verified against a real binary of a known
version:

| Library | Constant | Accessor |
|---|---|---|
| zstd | `ZSTD_VERSION_NUMBER` 10507 | `mov eax, imm32; ret` / `movz w0,#imm; ret` |
| sqlite | `SQLITE_VERSION_NUMBER` 3046001 | `mov eax, imm32; ret` / `movz`+`movk`+`ret` |
| xz (liblzma) | `LZMA_VERSION_NUMBER` 50080012 | `mov eax, imm32; ret` / `movz`+`movk`+`ret` |
| Mbed TLS | `MBEDTLS_VERSION_NUMBER` 0x03060500 | `mbedtls_version_get_number()` |
| nghttp2 | `NGHTTP2_VERSION_NUM` 0x14000 | `cmp edi, …` in `nghttp2_version(least)` |
| c-ares | `ARES_VERSION` 0x12205 | `mov [rdi], …` in `ares_version(int*)` |
| mosquitto | `LIBMOSQUITTO_VERSION_NUMBER` 2000021 | `mosquitto_lib_version()` |
| nettle | *(no combined constant)* | `nettle_version_major()` + `_minor()` |

zstd, sqlite and xz carry patterns for both x86-64 and AArch64; the rest are
x86-64 only so far, because that is what was verified.

A constant too large for one AArch64 instruction is loaded as
`movz w0, #lo16` then `movk w0, #hi16, lsl #16`, which is why
`arm64-movz-movk-imm32` validates both words — shift and destination register
included — before recombining the halves.

**pcre2 gets no byte pattern, and that is the finding.** It has no numeric
version constant: there is no `pcre2_version_number()`, only
`pcre2_config(PCRE2_CONFIG_VERSION)` copying a string. Measured, the
`endbr64; mov eax, imm32; ret` idiom occurs *zero* times in
`libpcre2-8.so.0.14.0` and the AArch64 equivalent zero times in
`libpcre2-8.0.dylib`. What it has is `10.47 2025-10-21` as its own string,
which only needed an anchor — see the identity rule below.

### Rules, again learned by getting it wrong

**Declare a plausible range, always.** The field is required. On a real
`libzstd.1.5.7.dylib` the AArch64 pattern matches 34 times — "return a small
constant" is an ordinary code shape — and yields three plausible-looking
versions: the true 1.5.7 plus 2.73.52 and 6.55.34. Bounding zstd to 1.x removes
both phantoms. Widening the bound brings them back, which is how the guard is
tested.

**Let the decoder do what the mask cannot.** A nibble mask cannot express "bits
23..31 are `010100101`", so the AArch64 pattern is loose and
`Encoding::Arm64MovzImm16` validates the instruction word exactly. Cheap
prefilter, exact confirmation.

**One pattern per architecture.** The same source line compiles to unrelated
bytes on x86-64 and AArch64. There is no portable pattern; write both.

**A byte pattern never establishes identity — only a version.** This was the
expensive one. Bounded to zstd's range and measured on a single libzstd, the
AArch64 `movz w0,#imm; ret` pattern looked precise. Run over a 21,000-file tree
it produced **282 components instead of 34**, about forty of them phantom zstd
versions, because "return a small constant" is an ordinary code shape in
ordinary binaries. Ranking the evidence lowest was not enough; the pattern must
not be able to claim a component at all. Identity comes from a `contains` string
or a filename, and the byte pattern supplies the number once it has. A signature
with byte patterns and nothing else is refused at compile time.

zstd is still found in stripped firmware because it is not anonymous: its error
messages (`Frame requires too much memory for decoding`) identify it perfectly
well. It simply never states its version.

**A version pattern that names nothing cannot claim the component either.**
Same rule, string side. pcre2's `10.47 2025-10-21` says nothing about pcre2 and
would attribute any date-suffixed number to it, so its signature sets
`version_implies_identity = false` and earns identity from its verb strings
(`BSR_ANYCRLF)`, `LIMIT_DEPTH=`). Almost every other signature is fine as-is,
because `OpenSSL 3.5.6 7 Apr 2026` and `libpng version 1.6.48` name themselves.

**Anchor on the library, not on its data or its callers.** Two ways to get this
wrong, both measured over the same tree:

- `SQLite format 3` is the *database file* header magic, so it matched 11 files
  — every `.db` in the tree — rather than the library.
- `sqlite3_libversion` and `lzma_str_to_filters` are symbol names, which appear
  in the dynamic symbol table of anything that *links* the library. That is a
  different claim from containing it.

The replacements — `attempt to write a readonly database`, `SQLITE_TMPDIR`,
`Unsupported flags to lzma_str_to_filters()` — match 2 files each.

**Verify the CPE identity against NVD before shipping it.** `sqlite3` is the
obvious product name and it is wrong: `cpe:2.3:a:sqlite:sqlite:3.46.1` returns
7 CVEs, `cpe:2.3:a:sqlite:sqlite3:3.46.1` returns none. A wrong vendor or
product is a *silent* failure — the scan reads as clean rather than broken.
Verified pairs are listed in `VERIFIED_CPE_IDENTITIES` as a tripwire, so
renaming one fails a test.

For the same reason liblzma and the xz CLI are **one** signature, not two: NVD
knows both as `tukaani:xz`, so a separate `lzma` product would be a component
that never matches a CVE.

### Distribution names are a different vocabulary

Debian ships zstd as `libzstd`; NVD knows it as `facebook:zstandard`. Signatures
carry `aliases` so the two reconcile — without it the same library detected by
package note and by byte pattern becomes two rows that never merge, and the
note-derived one can never be looked up in NVD, which needs a CPE vendor a
package note does not carry. OSV keeps being asked under the distribution's own
name, because that is what its distribution ecosystems are keyed on.


## 7. Firmware coverage

The set is chosen for what an embedded Linux image is actually made of, not for
what a developer laptop has. Derived from a Debian trixie image with 41
firmware-relevant packages installed, so dpkg's own record is the ground truth,
and each version below is asserted in `FIRMWARE_GROUND_TRUTH`.

| Component | Anchor | CPE |
|---|---|---|
| dropbear | `SSH-2.0-dropbear_2025.89` | `dropbear_ssh_project:dropbear_ssh` |
| dnsmasq | `dnsmasq-2.91` | `thekelleys:dnsmasq` |
| lighttpd | `lighttpd/1.4.79 (ssl) - a light and fast webserver` | `lighttpd:lighttpd` |
| wpa_supplicant | `wpa_supplicant v2.10` | `w1.fi:wpa_supplicant` |
| hostapd | `hostapd_cli v2.10` | `w1.fi:hostapd` |
| OpenSSH | `OpenSSH_10.0p2 Debian-…` | `openbsd:openssh` |
| u-boot | `U-Boot 2025.01-3 (Apr 08 2025 …)` | `denx:u-boot` |
| net-snmp | `net-snmp-5.9.4` | `net-snmp:net-snmp` |
| libssh | `libssh_0.11.5` | `libssh:libssh` |
| strongSwan | `strongSwan 6.0.1,` | `strongswan:strongswan` |
| libpcap | `libpcap version 1.10.5` | `tcpdump:libpcap` |
| Lua | `Lua 5.4.7  Copyright … PUC-Rio` | `lua:lua` |
| OpenVPN | `OpenVPN 2.6.14 x86_64-pc-linux-gnu […]` | `openvpn:openvpn` |
| avahi | `STATUS=%s 0.8 starting up.` | `avahi:avahi` |
| libjpeg-turbo | `libjpeg-turbo version 2.1.5` | `libjpeg-turbo:libjpeg-turbo` |

Every CPE was resolved against NVD's **CPE dictionary** (`/rest/json/cpes/2.0`)
rather than guessed, then confirmed to return CVEs for a real version. Several
were not what they look like: ncurses is `invisible-island:ncurses`, not
`gnu:ncurses`; hostapd is `w1.fi` and NVD also carries a typo'd `w1.f1`.

u-boot matters beyond its CVE count: its banner lives in a raw image with no
executable header, which is why the file-type gate scans headerless binary data
rather than only recognized formats.

### Three more false-positive traps, all measured

**sshd carries a bug-compatibility list.** `OpenSSH_3.*`, `OpenSSH_6.6.1*`,
`OpenSSH_7.0*,OpenSSH_7.1*` and more are patterns for negotiating around old
peers. A signature matching `OpenSSH_<version>` reports a router as running five
OpenSSH releases at once. Requiring the portable `pN` suffix picks the real
banner and leaves the list alone; every portable release carries it.

**"OpenVPN 2.6.0 or higher)"** is a requirement the binary states, not a version
it is — the same shape as OpenSSL's "3.0.0 and newer" prose. Requiring the
platform triple that follows a real build banner fixes it.

**`avahi-daemon` is a service name, not a binary marker.** It appears in systemd
units, in `/etc/passwd`, and in anything that names the service: 24 files across
the corpus. The daemon's own `STATUS=%s … starting up.` banner matches one.

### Deliberately not covered, and why

- **libupnp** — its embedded string is `Portable SDK for UPnP devices/17.2.0`,
  which is the *SDK/soname* version. Upstream is 1.14.20. Capturing it would
  report a version that matches no CVE, which is worse than reporting nothing.
- **libtiff, ncurses** — carry only ELF symbol-version tags (`LIBTIFF_4.0`,
  `NCURSES6_TIC_5.0.19991023`). See rule 1.
- **freetype, nghttp2, c-ares, readline, nettle, libwebsockets, libmicrohttpd,
  jansson, mbedtls, chrony, mosquitto** — no version string at all in the builds
  examined. These need byte patterns against their numeric version constants,
  which is the obvious next batch.


## 8. Versions that exist only as constants — and the five that do not

A second pass over the libraries firmware carries that print no version at all.
Each accessor below was located in a Debian trixie binary whose version dpkg
recorded, and its exact bytes are asserted in `CONSTANT_GROUND_TRUTH`.

Two mechanisms came out of it:

- **`packed8-hi`** for Mbed TLS, whose `MBEDTLS_VERSION_NUMBER` is `0xMMmmpp00`
  with a reserved low byte. Pinning that byte as `00` in the pattern is also
  what makes an otherwise generic "return a constant" shape specific.
- **`capture_offset_2`** for nettle, which has *no* combined constant:
  `nettle_version_major()` and `nettle_version_minor()` are two
  one-instruction functions the compiler emits adjacently, separated by its
  usual `nopw` padding. Both are read and packed as `(major << 8) | minor`.

**libmicrohttpd** needed neither. It stores a bare `1.0.1`, but the linker
places the `@LIBMICROHTTPD` symbol-version tag immediately after it — so the
adjacency is the anchor, the same trick pcre2's release date provides.

### The identity rule paid for itself, measurably

Mbed TLS's pattern is the generic `endbr64; mov eax, imm32; ret` shape with a
range. Across 26,077 real x86-64 files that shape produces a constant inside
Mbed TLS's range **four times** — and none of them became a detection, because
none of those files contain `mbedtls_ssl_`, `mbedtls_x509_` or `MBEDTLS_ERR_`.
That is four phantom findings suppressed by the rule that a byte pattern may
supply a version but never an identity.

On the same 26,077 files the six new signatures produced exactly two components,
nettle 3.10 and nghttp2 1.64.0 — both genuinely installed, both matching dpkg.
No false positives.

### An authoring mistake the guard caught

nettle's minor sits at offset **21**, not 20; offset 20 is the `mov` opcode
itself. Written as 20, the second capture reads `b8 0a 00 00` = 2744, which the
"each half must fit a byte" check rejects. The result was silence rather than a
version invented out of an instruction byte, which is the behaviour to want.
There is a test for it.

### Five with nothing to read — carried as present-but-unversioned

These genuinely do not embed a version a scanner can recover. They are still
identified, because "freetype is in this image" is a lead, and because absence
of a row is indistinguishable from absence of the library:

| Library | Why |
|---|---|
| **freetype** | Neither `2/13/3` as adjacent constants nor a triple-store in `FT_Library_Version`. The values are folded away entirely; searched as u8, u16 and u32 triples and as immediate stores. |
| **readline** | `rl_readline_version` (0x0802) is a bare global in `.data`, surrounded by other globals. Any pattern for it would encode one build's data layout. |
| **jansson** | Only `jansson_version_str` returning a bare `2.14`. Its neighbours are `%.*g` and `do_dump` — no stable anchor. |
| **libwebsockets** | Stores `4.3.5-unknown`, where the suffix is a build id that differs per build. Its neighbours are a format string and `cpdcheck`. |
| **chrony** | A bare `4.6.1` whose only neighbour is the `--version` option string — a linker layout artifact, not a property of the build. |

For these, a weak *version* pattern would be worse than none — a version that
matches no CVE is indistinguishable from a clean result. The same judgement as
libupnp in §7 and pcre2 in §6. Identifying them costs nothing by comparison.

Every anchor is a **data** string — an error message or a module name — never a
symbol name, since a symbol appears in the dynamic symbol table of anything that
*links* the library. FreeType and jansson export nothing but `FT_*` and `json_*`
symbols, so their anchors are FreeType's module-registry names (`autofitter`,
`pshinter`, `psnames`) and jansson's parser errors.

Two things measured on a 26,077-file Debian tree:

- **readline's anchors match `/usr/bin/bash`.** Not a false positive — Debian's
  bash links readline *statically*, so bash genuinely contains it. A package
  manager will never tell you that, and it is exactly the kind of thing binary
  scanning exists to surface. Five files match in total: bash, `libreadline.so`,
  `libhistory.so` and the two `.a` archives.
- **FreeType's anchors also appear in five `.h` headers**, and none became a
  detection, because the file-type gate skips text. The rule that documentation
  cannot masquerade as a component (§1) is what makes module names usable as
  anchors at all.

**libwebsockets has no CPE in NVD.** Checked against the CPE dictionary under
`libwebsockets`, `websockets` and `warmcat`; the only match is the unrelated
Python `websockets_project:websockets`. So an NVD lookup returns nothing however
precise a version would have been. A distribution build still routes to OSV
through the package note.

A note on that route: `aliases` folds a package note's version onto the same
row, so an identity-only component *can* end up versioned. Notes are added
per-package rather than universally, though — none of these five carried one in
the image examined — so it is a bonus rather than the plan.


## 9. A real firmware image

> Run 2026-08-20 against OpenWrt 21.02.7 for the **TP-Link Archer C7 v2**
> (`ath79/generic`, big-endian MIPS), downloaded from downloads.openwrt.org and
> verified against the published `sha256sums`. 5.7 MB image, 920-file root
> filesystem, built 2023-04-17.

The first end-to-end run on something that is actually firmware rather than a
distribution rootfs. Four things it established.

### The raw image yields nothing, and that is correct

Pointed at the 5.7 MB `.bin`, the scanner reports **zero components** — because
only **1.1%** of the image is printable. The payload is an xz-compressed
squashfs at `0x1f8718`; the readable remainder is the OpenWrt metadata JSON and
a build id. There is genuinely nothing to read.

**oxAudit extracts archives, and now squashfs too.** Since 2026-09-22 the
native scanner opens tar (and anything wrapped around one — `.tar.gz`,
`.tar.xz`, `.tar.zst`, `.tar.bz2`), zip, gzip, xz, zstd, bzip2, `ar` — which
covers `.deb` packages and `.a` static libraries — RPM packages (a
hand-parsed lead/header skip over a compressed cpio payload, xz included
through the same liblzma `.tar.xz` uses), and a saved `docker`/OCI image (a
tar of layer tars) — in memory, with depth, member-count, per-member, and
total-expansion budgets that a decompression bomb trips loudly rather than
fatally. Squashfs v4 unpacks through the maintained, fuzzed `backhand`
reader, and a raw firmware blob gets a bounded sliding magic search for
embedded squashfs within its first 256 MiB — every offset, no alignment
assumption, since this very image's filesystem sits at the unaligned
`0x1f8718` and would be missed by any aligned step. CramFS, RPM packages,
tar and every compression wrapper around one, zip, and `ar` (so `.deb`)
open through the same path. Two caps keep a hostile
blob from turning the search into a cost attack: the window, and a limit of
64 parse attempts after which the search gives up and says so. Members scan
under virtual paths
(`fw.bin!sqfs@0x1f8718!/bin/busybox`), directories/symlinks/whiteouts are
skipped rather than honored, and nothing is written to disk. An on-disk OCI
image layout (a directory with `oci-layout` and `index.json` beside
content-addressed blobs) is recognized as of 2026-09-24: the index and
manifests resolve — one nesting level of image indexes included, bounded —
to ordered layers whose members carry
`image@<digest12>!layer-0003!/bin/busybox` names instead of the blob's hash
filename, and every blob is verified to hash to its digest before it counts
as a layer; a renamed or truncated blob is skipped with its reason. Still not
unpacked: UBI/UBIFS and the long tail of vendor filesystems, plus
squashfs v3 (pre-2009) — each needs its own vetted reader, and those blobs
still scan raw, exactly as before. CramFS is now unpacked (2026-09-22): a
hand-rolled reader following the kernel's own `fs/cramfs/inode.c`, verified
end to end against a genuine `mkfs.cramfs` image committed as a fixture —
the block-pointer table, where each pointer names its block's *end* and the
first block starts immediately after the table, was the detail the kernel
comments settled. Refused variants, each falling back to a raw scan: the
shifted-root-offset flag, the wrong-signature flag, and legacy direct block
pointers. Squashfs v3 was investigated and
deliberately left out, with the measurement: the plain-zlib v3 kinds in the
`backhand` reader could not be verified against any obtainable standard
image, and the v3 images that actually dominate old firmware — OpenWrt
Kamikaze/8.09-era vendor builds — are LZMA-patched hybrids with
mixed-endian headers (`sqsh` magic, little-endian fields) that backhand
rejects under every kind (measured against 8.09.2's
`openwrt-atheros-root.squashfs`: all four kinds fail). The vendor-LZMA kinds
that might read them require a C++ 7zip-era dependency that does not build
cleanly. Unverifiable parse paths do not ship; that is the rule.

UBI/UBIFS is scoped out with a reason rather than a date: reading it means
parsing erase-block association and volume tables, then a second filesystem
(UBIFS) with its own journal and LPT model on top — a project comparable to
the squashfs reader on its own. `backhand` does not cover it and no
maintained Rust reader exists to adopt. UBI images carry no magic the
extractor recognizes, so they scan as opaque blobs, exactly as before.

### Extracted, it finds real vulnerabilities

| Component | Version | CVEs | Worst |
|---|---|---|---|
| wolfSSL | 5.5.3 | **63** | 3 critical |
| u-boot | 2021.01 | **19** | 2 critical |
| busybox | 1.33.2 | **6** | CVE-2022-48174 critical |
| lua | 5.1.5 | 2 | medium |
| wpa_supplicant | 2.10 | 1 | CVE-2023-52160 (PEAP bypass) |
| dnsmasq | *unversioned* | — | |
| dropbear | *unversioned* | — | |
| hostapd | *unversioned* | — | |
| iptables | *unversioned* | — | |

**91 CVEs, 6 critical, 32 high**, in 34 ms over 920 files.

> The first version of this run reported 28 CVEs, because wolfSSL had no
> signature. It is the TLS library the image actually uses, and it turned out to
> be the most vulnerable component in it by a wide margin — one missing
> signature was two thirds of the findings. Worth remembering when reading a
> clean result: coverage is the limit, not the target.

### Hardened firmware strips version strings on purpose

dnsmasq, dropbear and hostapd were identified but carry no version, and that is
not a signature failure. OpenWrt's dropbear emits `SSH-2.0-dropbear` with **no
version suffix** — deliberately, so the daemon does not advertise it. dnsmasq
and hostapd build their version banners from macros at runtime rather than
embedding a literal.

So on hardened firmware, string signatures give identity and often not a
version. That is exactly the case byte patterns answer — except:

### Byte patterns were x86-64 and AArch64 only — MIPS has since arrived, partially

Verified rather than assumed: the busybox binary contains **zero** occurrences
of either the x86-64 `endbr64` or the AArch64 `ret` encoding. All eight
detections came from strings and filenames; no byte pattern could fire. Reaching
MIPS, ARM32 and the other embedded targets means a pattern per architecture per
library, and `patfind`-style architecture tagging (see `vulhunt-study.md` §4).

Since that run, sqlite, liblzma, and zstd gained embedded-architecture
patterns derived from real OpenWrt packages (23.05.5, versions known
independently from the package filenames):

- **MIPS16e2** (`mips_24kc`, big-endian): the 32-bit accessors end in a
  PC-relative load, a return, and the constant sitting in the literal pool as
  four raw big-endian bytes — no instruction decoding needed at all. sqlite
  and liblzma both use this shape. zstd's 16-bit accessor is the
  EXTEND+LI pair, whose immediate is a bit permutation rather than an
  integer: the EXTEND word's low five bits land above the LI immediate and
  its upper six below it. That mapping resisted four rounds of manual
  derivation and was then settled empirically — a sweep of 2,048 EXTEND
  words disassembled through GNU objdump isolated each bit's contribution,
  and the resulting formula reproduces all four real accessors exactly
  (zstd 1.4.5, 1.4.9, 1.5.2, 1.5.7). Three li-then-return sites in the real
  libzstd 1.5.2, exactly one plausible version.
- **ARM (A32)** (`arm_cortex-a7`, little-endian): zstd's accessor is
  `movw r0, #imm16; bx lr` — the immediate split across the instruction word
  as imm4 over imm12, exactly one movw-then-return site in the real library.
  sqlite and liblzma use `ldr r0, [pc, #..]; bx lr` with the constant in the
  pool as four little-endian bytes (two pool sites in libsqlite3, one in
  range; one in liblzma).

### Two honest caveats on the findings

- **u-boot's 19 CVEs are for the bootloader; the file detected is
  `/usr/sbin/fw_printenv`.** That tool is genuinely built from u-boot 2021.01
  source and genuinely carries its version, so the *component* detection is
  right — but most bootloader CVEs will not apply to a userspace environment
  reader. This is precisely the case `triage/` exists for: a candidate that
  needs Gate 1 asked of it.
### The two gaps this run surfaced, since closed

- **wolfSSL** states itself plainly — `wolfSSL 5.5.3` on this MIPS build,
  `wolfSSL 5.7.2` on Debian trixie's x86-64 — so it gets identity *and* a
  version from one string. Both are asserted in `FIRMWARE_GROUND_TRUTH`.
- **iptables** does not. Its banner is built from `%s v%s (legacy): ` at
  runtime, and the bare version that is present has no stable neighbour: it sits
  between `-N %s` and `append` on the MIPS 1.8.7 build and between `help` and
  `unexpected '!' flag` on x86-64 1.8.11. Identity only, anchored on
  `Failed to initialize xtables` and `cannot have ! before` — both checked
  across both builds. `Perhaps iptables or your kernel needs to be upgraded.` is
  in the MIPS build but neither 1.8.11 binary, so it is not used.

Negative control: across 26,077 files of a Debian image with neither installed,
neither signature fires.

Against opkg's own package list — 105 packages, 73 excluding kernel modules —
the scanner now finds 14 components, matching every version opkg records for
them.

### OpenWrt's own userspace

ubus, uci, netifd and odhcp6c were the last visible gaps, and are now covered.
They are in essentially every OpenWrt-derived image, which is a large slice of
consumer routers and vendor firmware built on it.

None embeds a version, and that is not a build oversight: OpenWrt versions these
as dated git snapshots (`2021-06-30-4fc532c8`), so there is no release number to
read. Identity only, therefore — anchored on data strings, never symbols:

| Component | Anchor |
|---|---|
| ubus | `ubus.object.add` (event names ubusd emits) |
| uci | `commit    [<config>]` (aligned command list) |
| netifd | `external device handler` |
| odhcp6c | `Usage: odhcp6c [options] <interface>` |

Two things checked rather than assumed:

- **CPE reality.** I had claimed last section these had no CPE. Half wrong: the
  dictionary registers **`openwrt:libuci`** (one entry, no CVEs at this
  version), while `ubus`, `netifd` and `odhcp6c` genuinely have none. So uci's
  product is `libuci` to match. More usefully, **OpenWrt itself is in NVD** — as
  `cpe:2.3:o:openwrt:openwrt`, 10 CVEs at 21.02.7 — but under the `o` (operating
  system) namespace, which `enrich::cpe_match_string` does not build. Firmware
  distribution CVEs are a category the component-level scanner does not reach.

- **ubus provenance.** ubus resolves to 6 files, not 3: alongside `ubus`,
  `ubusd` and `libubus.so`, its event strings appear in `procd`, `netifd` and
  `odhcpd` — binaries that genuinely link libubus and use ubus IPC. This is
  accurate provenance (one `ubus` component, found in six files that use it),
  the same shape as readline inside bash, not a false positive.

Negative control: on 26,077 files of a Debian image with none of the four
installed, none fires.

## 10. A wider firmware batch, and two traps it exposed

> Added 2026-08-20. Fourteen more libraries, derived the usual way from Debian
> trixie with dpkg as ground truth.

Five read a version, verified against the exact bytes:

| Library | Anchor | CPE |
|---|---|---|
| libarchive | `libarchive 3.7.4` | `libarchive:libarchive` (16 CVEs) |
| libcap | `shared library version: libcap-2.75.` | `libcap_project:libcap` |
| libevent | `2.1.12-stable` | `libevent_project:libevent` |
| libpsl | `0.21.2 (+libidn2/2.3.7)` | none — inventory only |
| ppp | `pppd.so.2.5.2` / `/usr/lib/pppd/2.5.2` | `samba:ppp` (not `canonical:ppp`, which returns 0) |

Nine more are identity-only — libtasn1, dbus, gmp, openldap, libtirpc, libnftnl,
json-c, libidn2, e2fsprogs — each anchored on a data string, never a symbol.

### Two false-positive traps, both measured on 26,077 files

**Translation catalogs carry a library's error strings.** libidn2's anchors
matched 23 files — the `.so`, the `.a`, and 21 gettext `.mo` locale catalogs,
which embed every translatable error message. A `.mo` is not the library, and a
different library's stray catalog would be a true false positive. The fix is
general: `filetype.rs` now recognizes the gettext MO magic (`0x950412de`, either
endianness) and skips it, the same way it skips text. libidn2 dropped to 2 files.

**Sun RPC error strings are shared heritage.** libtirpc's first anchor,
`RPC: Can't encode arguments`, matched `libc.so.6` and MIT Kerberos's
`libgssrpc.so` — because glibc's built-in sunrpc and every RPC descendant carry
the same classic strings. Re-anchored on libtirpc's own diagnostics
(`rpc_broadcast_exp: uaddr %s`, `Netconfig database not found`), absent from
glibc.

**And one avoided by design:** dbus's `org.freedesktop.DBus` protocol name is in
glib, systemd and every dbus client — 53 files. The signature uses the daemon's
own diagnostics (`Failed to start message bus: %s`) instead, so it reports dbus
only where the bus daemon actually is.

The lesson repeating across all three: an anchor must belong to the library, not
to its protocol, its translations, or its ancestry. Each was caught by measuring
what a signature matches across a real tree, not by reading it.

## The legacy signature set is now fixture-verified

The 24 signatures that carried `unverified` provenance ("legacy
independently-derived, lacks one committed positive fixture") are resolved:
**22 of 24** moved to verified through `REAL_BUILD_GROUND_TRUTH`, a committed
table of positive detections whose every entry is a real banner string lifted
from a real binary whose version was known independently — Debian trixie
packages (dpkg) for bash 5.2.37, binutils 2.44, busybox 1.37.0, bzip2 1.0.8,
expat 2.8.3, git 2.47.3, glibc 2.41, GnuPG 2.4.7, krb5 1.21.3, libcurl 8.14.1,
OpenSSL 3.5.7, perl 5.40.1, sqlite 3.46.1, util-linux 2.41.5, zlib 1.3.1;
Homebrew kegs for curl 8.7.1, GnuTLS 3.8.13, libgcrypt 1.12.2,
libmicrohttpd 1.0.1, libpng 1.6.58, libssh2 1.11.1, xz 5.8.4.

The remaining two were unverified for a sharper reason than a missing
fixture, because measuring found something worse: **neither ICU nor
libxml2's identity anchors exist in real modern builds**. `ICU 7x` occurs
nowhere in Homebrew's icu4c 78.3 or Debian's libicu 76.1; `libxml2 version`
and `xmlsoft.org` occur nowhere in Debian's libxml2 2.9.14. Those two
signatures would never fire on a real modern binary and need re-derivation —
which is a more useful fact to record than a TODO.

Both were re-derived on 2026-09-24, and the set is now **24 of 24
fixture-verified** (71 products total):

- **ICU** identifies by its mangled C++ symbol namespace — `_ZN6icu_78…`,
  present in every library build regardless of stripping — and libicuuc
  alone embeds `U_ICU_VERSION` as the only bare `major.minor` string in its
  string table (measured unique in Debian libicu 76.1 and 78.3;
  libicui18n's bare dotted strings are ln(2)/log10(e) constants with
  one-digit majors, which the two-digit-major pattern excludes). The
  bare-digits version line is not allowed to imply identity, per authoring
  rule 2. Ground truth transcribed from both Debian builds.
- **libxml2** identifies by its link-mismatch fatal prose (`Fatal: program
  compiled against libxml %d using libxml %d`, stable since the 2.x era)
  and deliberately reports **no version**: the only version-shaped text in
  a stripped modern build is the `LIBXML2_2.x` symbol-tag history — 2.9.14
  still tags 2.4.30 — which authoring rule 1 forbids capturing because
  those are the ABIs the library can serve, not what it is. The ELF package
  note reports the exact version wherever the distro left one. Ground truth
  from Debian bookworm and trixie 2.9.14 builds, with the tag lines present
  in the fixture to prove none of them is captured.

## 11. Exploitation signal: KEV and EPSS

> Added 2026-08-20. `binscan/exploit.rs`.

Detecting a component and matching CVEs answers "is this vulnerable?". On the
OpenWrt router that produced **92 CVEs**, the question that matters is "which do
I fix first?" — and two free, key-less sources answer it. Neither finds new
CVEs; both rank the ones already found.

- **CISA KEV** — the Known Exploited Vulnerabilities catalog (1,671 entries, one
  JSON file). Presence means the CVE has been *observed exploited in the wild*,
  the strongest prioritization signal there is, plus a per-entry ransomware flag.
- **EPSS** (FIRST.org) — the probability a CVE will be exploited in the next 30
  days, `[0, 1]`, with a percentile.

Both are parsed purely and tested against captured real responses
(`tests/fixtures/cisa_kev.json`, `epss.json`), then fetched once per scan and
attached to every finding. They are best-effort: a failure of either is a note,
not a scan failure — the findings stand on their own.

Why these two and not the forty other sources catalogued at
[haxdoggy/vulnerability-databases](https://github.com/haxdoggy/vulnerability-databases):

- The regional CERTs (BSI, CERT-FR, JVN, CNNVD, …) and vendor pages (Apple,
  Cisco, Oracle) are **HTML with no API** — not machine-integrable.
- The aggregators (VulnDB, Snyk, Vulners) are **commercial or gated**.
- Debian, Ubuntu, Red Hat and GitHub's advisory database are **already covered**:
  OSV aggregates them and the enrichment path already queries it.

KEV and EPSS are the ones that are free, key-less, machine-readable, and *not*
redundant — because they answer a question NVD and OSV do not: not whether a CVE
exists, but whether anyone is using it.

On the router, none of the 92 CVEs is currently in KEV — an honest result, since
KEV tracks internet-facing enterprise exploitation, not embedded busybox and
u-boot CVEs. EPSS scored every one, so the findings sort by exploitation
probability even where nothing is a confirmed KEV hit.

### Also wired into the dependency scanner

The same signal now ranks dependency-scan findings. `exploit.rs` moved to the
crate root (it is no longer binscan-specific), and `scan_dependencies` attaches
KEV/EPSS to every advisory before sorting exploited-first, then by EPSS, then by
CVSS. A dependency advisory's CVE lives in its OSV aliases rather than its id —
OSV names an npm advisory `GHSA-…` — so `exploit::cve_among` teases it out; it is
tested against the real GHSA→CVE shape.

Verified against live data: lodash 4.17.4 and minimist 0.0.8 resolve through OSV
to twelve CVEs, none in KEV (honest — neither is actively exploited), all
EPSS-scored, with `CVE-2021-23337` (lodash command injection) highest at 0.21 —
so it sorts to the top of the list.

### And the CVE research view

The single-CVE dossier now shows the same signal: a `KEV · exploited` badge
(`KEV · ransomware` when the campaign flag is set) and the EPSS score beside
CVSS, and the exploitation status is fed into the "Discuss in Assistant" text so
an AI briefing has it too. Because research is interactive — a user opens several
CVEs in a session — the KEV catalog is cached on `CveState` for an hour rather
than re-downloaded per lookup; EPSS is one query per CVE.

Verified against live data: `CVE-2021-44228` (Log4Shell) comes back
`known_exploited`, `ransomware`, EPSS 100%.

### And the source-code scanner, at the weakness-class level

The source scanner was the honest exception: its findings are regex pattern
matches with a **CWE** but no CVE, and KEV/EPSS are CVE-keyed. But KEV entries
*carry* CWEs, so there is a real class-level signal: is this *kind* of bug being
actively exploited in the wild?

`KevSet::cwe_exploited_count` counts the exploited CVEs sharing each CWE, and
`scan_project` flags every finding whose CWE is represented, sorting them first.
The correlation is not academic — measured against the live catalog, 9 of the
12 CWEs our rules emit are in KEV:

| CWE | Weakness | Exploited CVEs in KEV |
|---|---|---|
| CWE-78 | OS command injection | 107 |
| CWE-502 | Unsafe deserialization | 70 |
| CWE-79 | Cross-site scripting | 33 |
| CWE-89 | SQL injection | 30 |
| CWE-120 | Buffer overflow | 12 |
| CWE-95 | Eval injection | 6 |
| CWE-295 | Improper cert validation | 4 |
| CWE-259 | Hardcoded password | 2 |
| CWE-98 | PHP file inclusion | 1 |

So a command-injection finding now carries "Exploited class · KEV" — command
injection is the single most exploited weakness class in the wild. EPSS is
CVE-keyed and genuinely cannot apply to a class, so it is deliberately left off
rather than faked; the badge is explicit that this is a weakness class, not a
specific CVE.

Two properties kept: the correlation reuses the KEV catalog already cached for
the CVE tools (no extra fetch mid-session), and it is best-effort — a failed
fetch leaves findings unflagged rather than failing the scan, so source scanning
still works offline.

All four scan paths — binary, dependency, CVE research, and source — now carry
exploitation signal, each in the form its data supports.
