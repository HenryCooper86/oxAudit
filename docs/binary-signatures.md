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

- **Coverage is 40 signatures, not 365.** They are the components that dominate
  firmware findings (see §7), and the package note covers much of the rest on
  any distribution-built target. A vendor-built stripped binary of something
  uncovered will be missed. Extending coverage is mechanical: run the harness
  against a corpus containing it.
- **Signatures are build-dependent.** cve-bin-tool misses zstd on Homebrew
  because its checker requires the version adjacent to an error string and that
  build lays it out differently. Ours will have equivalent blind spots.
- **A detection is not a vulnerability.** The scanner reports components; CVE
  enrichment through oxAudit's existing NVD and OSV clients is the next step and
  is not built yet.


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

Four libraries use this today, each verified against real binaries of a known
version on both x86-64 and AArch64:

| Library | Constant | Idiom |
|---|---|---|
| zstd | `ZSTD_VERSION_NUMBER` 10507 | `mov eax, imm32; ret` / `movz w0,#imm; ret` |
| sqlite | `SQLITE_VERSION_NUMBER` 3046001 | `mov eax, imm32; ret` / `movz`+`movk`+`ret` |
| xz (liblzma) | `LZMA_VERSION_NUMBER` 50080012 | `mov eax, imm32; ret` / `movz`+`movk`+`ret` |
| — | — | — |

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
