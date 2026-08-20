# What oxAudit took from VulHunt

> Studied 2026-08-20 against [`vulhunt-re/vulhunt`](https://github.com/vulhunt-re/vulhunt)
> at HEAD — Binarly's binary and UEFI firmware vulnerability framework, 878
> stars, actively maintained. Companion to the other adoption studies here.
> Not to be confused with `capitalone/VulnHunter`, a different project studied
> in `vulnhunter-study.md`.

## 1. The licence is not what the repository badge says

GitHub reports the repository as GPL-3.0, and the top-level `LICENSE` is. But
the crates are licensed individually, and the split is exactly along the line
that matters:

| Crate | Licence | What it is |
|---|---|---|
| `bias-core` | **MIT OR Apache-2.0** | the analysis framework |
| `bias-compat-flirt` | **MIT OR Apache-2.0** | FLIRT signature matching |
| `bias-compat-fwhunt` | **MIT OR Apache-2.0** | FwHunt rule engine |
| `bias-compat-patfind` | **MIT OR Apache-2.0** | function-prologue patterns |
| `bias-btp` | **MIT OR Apache-2.0** | Binarly platform client |
| `bias-vulhunt-engine` | GPL-3.0 | the Lua rule engine |
| `bias-vulhunt` | GPL-3.0 | the CLI |
| `bias-lutil`, `bias-tutil`, `bias-loader-bndb` | GPL-3.0 | utilities, Binary Ninja loader |

So the parts most relevant to oxAudit are permissively licensed, and the
constraint that dominated the cve-bin-tool decision does not apply to them.
Worth checking per-crate rather than trusting the repository badge — the
opposite mistake would have ruled out the useful half.

The crates are published to crates.io but only as **0.0.0 placeholders**, so
using them means a git dependency, and `bias-compat-*` all pull in `bias-core`
with its own analysis model. That is a large dependency for what we need.

## 2. The idea worth taking: match code, not text

Every signature oxAudit had before this matched *strings*. A library built
without its version string is invisible to that, and those are exactly the
libraries firmware is full of: zstd, sqlite3, pcre2 and liblzma carry nothing
but ELF symbol-version tags.

VulHunt's `bias-compat-fwhunt` matches byte patterns whose unknown bytes are
wildcards, masked at **nibble** granularity (`bmatch.rs`). That granularity is
the insight: it pins an opcode while leaving an operand free, so a pattern
survives a recompile instead of matching exactly one build.

The other half is ours, and it is what makes this more than a second string
matcher: **capture**. Many libraries compile their version in as a number.
zstd's `ZSTD_versionNumber` is one instruction returning it:

```
x86-64   f3 0f 1e fa  b8 0b 29 00 00  c3     endbr64; mov eax, 0x290b; ret
AArch64  60 21 85 52  c0 03 5f d6            movz w0, #0x290b; ret
```

`0x290b` is 10507, and `1 * 10000 + 5 * 100 + 7` is zstd **1.5.7**. A pattern
that pins the instruction and captures the operand reads a version out of a
binary that never spells one out.

Both encodings above were read off real binaries — Homebrew's
`libzstd.1.5.7.dylib` and Debian trixie's stripped `libzstd.so.1.5.7` — not
derived from a manual.

## 3. What that required getting right

**A byte pattern alone is weak evidence, and the measurement says so.** On the
real AArch64 dylib, `movz w0, #imm; ret` matches **34 times**: "return a small
constant" is an ordinary code shape, not a zstd marker. Three of those matches
produce a plausible-looking version — the true `1.5.7` plus `2.73.52` and
`6.55.34`.

So every byte pattern must declare the version range it considers plausible,
and the field is **required rather than optional**. With zstd bounded to 1.x,
the two phantoms disappear and the real version remains. Widening the bound
brings them straight back, which is how that guard is tested.

Byte-pattern evidence also ranks below a characteristic string, which ranks
below a filename, which ranks below a declared package note. The UI says which
one it was.

**The decoder does the exactness the mask cannot.** A nibble mask cannot express
"bits 23..31 are `010100101`", so the AArch64 pattern is deliberately loose and
`Encoding::Arm64MovzImm16` validates the full instruction word and extracts bits
5..21. Cheap prefilter, exact confirmation — the same division of labour FLIRT
uses with its CRC16.

**Naming had to be reconciled.** Adding byte patterns immediately produced zstd
twice on one file: `libzstd 1.5.7` from the ELF package note and
`facebook/zstandard 1.5.7` from the byte pattern. Distribution package names and
CPE product names are different vocabularies. Signatures now carry `aliases`, so
a note-detected component gains the CPE identity it otherwise lacks entirely —
which is also what lets it be looked up in NVD at all — while OSV keeps being
asked under the distribution's own name.

## 4. Evaluated and not built

### FLIRT — the highest ceiling, blocked on data not code

`bias-compat-flirt` turned out to be a thin wrapper over
[`lancelot-flirt`](https://crates.io/crates/lancelot-flirt), an independent
crate: **Apache-2.0, 0.10.0, ~60k downloads**. Its API is exactly what we would
need —

```rust
FlirtSignatureSet::match(&self, buf: &[u8]) -> Vec<&FlirtSignature>
```

— an anchored match against a buffer, with no address and no disassembler
required. Sweeping every offset of a code section is viable, and the format's
CRC16 plus tail-byte checks keep false positives down.

FLIRT identifies statically-linked library *functions* by their byte patterns,
which is the strongest available answer to "which OpenSSL is compiled into this
stripped object". The blocker is not the engine, it is the **signature data**:
`.sig`/`.pat` files are conventionally produced by IDA's FLAIR tools, and public
collections have murky provenance. Generating our own from library archives is
the clean path and is a project in itself.

Recorded here because the engine being free changes the shape of that project:
it is signature generation, not matching.

### The Lua rule engine — wrong shape for us

`bias-vulhunt-engine` is GPL-3.0 and, more decisively, is written against an IR
produced by `bias-core` or Binary Ninja. Rules reason about basic blocks, calls
and data flow. That is a disassembler-class dependency, and oxAudit's binary
scanning is deliberately a file-reading tool.

### UEFI specifics — out of scope

`bias-compat-fwhunt`'s protocol, NVRAM and GUID matching is aimed at UEFI
firmware. oxAudit does not parse UEFI images, and adding that is a different
product decision rather than a port.

### Function-prologue patterns — only useful with the above

`bias-compat-patfind` carries YAML byte patterns for finding function starts in
stripped ARM code, keyed by architecture (`architecture: ARM:LE:32:*:*`). It is
the missing half of a FLIRT pipeline. The one idea taken from it standalone is
that **patterns are architecture-specific**, which is why the zstd signature
carries one pattern per encoding rather than pretending one fits.

## 5. Result

zstd is now detected, with its exact version, on a stripped binary carrying no
version string and no package metadata — on both x86-64 and AArch64. That is a
component **cve-bin-tool, grype and our own string signatures all missed**.

Still open: coverage. One library uses byte patterns today. sqlite3, pcre2 and
liblzma expose their versions the same way and are the obvious next ones; the
method for adding them is in `binary-signatures.md`.
