# YARA scanning

oxAudit runs YARA rules you supply against files and folders on disk. The
rules run natively through [YARA-X](https://virustotal.github.io/yara-x/), the
Rust implementation of YARA, which is compiled into oxAudit. No `yara` binary
is installed or invoked, and nothing is sent over the network. The desktop app,
`oxaudit-cli yara` and the headless server run the same engine, so a match in
CI is the match on a workstation.

oxAudit ships no YARA rules. You import your own, or rules you are licensed to
use, as a **signature pack**. oxAudit is not affiliated with VirusTotal or the
YARA project; YARA and YARA-X are the names of their respective projects.

A scan reports which rules matched which files, at which offsets. It does not
report a file as clean, safe or secure: "no rule matched" says nothing about
content the rules do not describe, or about files the scan did not read.

- [Import rules](#import-rules-as-a-signature-pack)
- [Run a scan](#run-a-scan)
- [Read the results](#read-the-results)
- [Run states and exit codes](#run-states-and-exit-codes)
- [Modules and unsupported features](#modules-and-unsupported-features)
- [Compatibility with classic YARA](#compatibility-with-classic-yara)
- [Performance and limits](#performance-and-limits)
- [Building without YARA](#building-without-yara)

## Import rules as a signature pack

A signature pack is a set of rule files of one kind, imported from a single
`.yar`/`.yara` file, a folder, or a `.zip`. In the desktop app and the
headless server, open **Rule Library**, then **Import signature rules**: pick
the kind (YARA), choose the file or folder (on a server, type a path on the
server's filesystem), and select **Inspect**. The preview shows the file count,
the rules that will run, ignored files, the total size, the content SHA-256
and every file or rule that was skipped, with the reason. Enter a name and the
licence, then **Install pack**. From the command line:

```sh
oxaudit-cli signature-pack install --db packs.sqlite3 --kind yara \
  --name "Doc fixture rules" --license MIT --version 1.0 rules/
```

```text
installed doc-fixture-rules-590a99f8e7b4 (Doc fixture rules) — 2 file(s), 1 rule(s), licence MIT
1 file(s) or rule(s) not applied:
  sandbox.yar:1: module `cuckoo` is not available in oxAudit
```

- **A licence is required.** oxAudit refuses to install a pack without one. If
  the pack root holds a `LICENSE`, `LICENCE` or `COPYING` file (optionally
  `.md`, `.txt` or `.rst`) that matches a known licence, it is offered as the
  default; you confirm or change it. Detection looks for characteristic phrases
  and is a convenience, not a legal determination. The licence is stored with
  the pack and recorded on every run that used it.
- **Pack identity.** The pack id is the name, lower-cased, plus the first 12
  characters of the content hash, for example `doc-fixture-rules-590a99f8e7b4`.
  Importing identical content under the same name returns the existing pack.
- **What is read.** Files ending `.yar` or `.yara`, in any subfolder. A folder
  import does not descend into `.git`. A zip whose members all sit in one
  top-level folder (a repository download) has that folder stripped. Symbolic
  links are never followed, and a zip member that would escape the archive root
  makes the whole archive refused.
- **What is skipped, and why.** Each skipped file is listed with a reason and
  does not stop the import: a file that is not valid UTF-8; a file that does not
  compile (the reason carries the line of the first error); a file that imports
  a module oxAudit does not provide. A rule file compiles or is skipped as a
  whole: one bad rule removes every rule in that file. Other files in the pack
  still apply.
- **What is refused.** The whole import is refused, with a message, when a
  `.yar`/`.yara` file is over 1 MiB, when any file is a compiled rules file
  (`.yarc`, or starting with the bytes `YARA`) because oxAudit cannot inspect
  what compiled rules contain, when a pack has more than 20,000 rule files or
  more than 256 MiB of rule text, when a folder or archive has more than
  200,000 entries, or when no rule file is found.
- **Storage.** Files are copied into a `sigpacks` folder beside the rule-pack
  database, with a manifest of per-file SHA-256 hashes. A pack is never read
  from its original location again.
- **Verification before every scan.** Before each scan the stored files are
  re-read and checked against the manifest, and the manifest against the
  content hash recorded at import. A pack that fails (a file edited, deleted
  or added) is not applied. The scan reports the pack and the reason, and ends
  [incomplete](#run-states-and-exit-codes).
- **Enable, disable, remove.** An enabled pack applies to every scan that does
  not name packs. Disabling keeps the pack but leaves it out by default; the
  CLI `--pack` flag and an explicit selection still apply it. Removing a pack
  deletes its files and never alters past runs, which keep the pack id, licence
  and hash they recorded.
- **Copyleft rules.** You may import a pack published under a copyleft licence
  such as the GPL. It stays in your local data directory and oxAudit does not
  redistribute it. The licence is shown with the pack and in every result.

## Run a scan

**Desktop and server.** Open **YARA Scan**, enter or choose a file or folder,
optionally untick packs to leave out for this run, and select **Run YARA
scan**. **Max file size (MiB)** defaults to 64. **Cancel** stops the scan.
Without an enabled pack the page says so and links to Rule Library.

**Command line.**

```text
oxaudit-cli yara [OPTIONS] <PATH>
```

See [the `yara` reference](cli.md#yara). Rules come from `--rules FILE|DIR`
(this scan only, never installed, repeatable) and/or from a pack store named by
`--pack-db`. With `--pack-db` and no `--pack`, every enabled YARA pack applies.
With `--rules` and no `--pack-db`, installed packs are not consulted.

```sh
oxaudit-cli yara ./target --pack-db packs.sqlite3 --fail-on high
```

```text
YARA scan of /work/target: 3 file(s) scanned (89 bytes) with 1 rule(s) from 1 pack(s).
2 rule match(es) in 2 file(s).

notes.txt  (sha256 f8779e0c9306c88131483c7cfecad8093c82038d65b6725664d66c2990d6b230)
  [high] demo_marker  (doc-fixture-rules-590a99f8e7b4:example.yar)  tags: example
    $hex at offset 13 (4 byte(s)): 4f584155
    $marker at offset 13 (18 byte(s)): 4f5841554449542d444f432d4d41524b4552
...
1 rule file(s) did not compile and were not applied:
  doc-fixture-rules-590a99f8e7b4/sandbox.yar:1: module `cuckoo` is not available in oxAudit
```

The walk reads every file under the target. **Ignore files are not applied**
(malware hides in folders a source scan would skip) and **symbolic links are
not followed**: a link is listed as skipped. Files are read in a fixed order,
and results come back in that order whatever the thread schedule was.

## Read the results

Each match row has the file path (relative to the target, forward slashes), the
file's SHA-256, the rule name, tags, the rule's metadata, the pack and the rule
file's path inside the pack, and a rule id of the form
`<pack>/<rule file>:<rule>`.

- **String matches** list the string identifier (`$marker`), the byte
  **offset** into the file, the match length, and an **excerpt** of the matched
  bytes, shown as hex (the app also shows a printable rendering). Excerpts keep
  at most 64 bytes. A rule that reports secrets has its excerpts masked; see
  [masked excerpts](#masked-excerpts). At most 32 string matches are kept per
  rule per file, the
  earliest by offset; the rest are counted ("N more string matches"). A rule
  that matches on a condition with no string (a module check) has no offsets.
- **Private rules** are evaluated but never reported.
- **Severity** comes from the rule's metadata. A `severity` string
  (`critical`, `high`, `medium`, `low`, `info` or `informational`; key and
  value case-insensitive) wins. Otherwise an integer `score` maps to: 80 or
  more critical, 60 to 79 high, 40 to 59 medium, 20 to 39 low, below 20 info.
  With neither, the severity is `medium`. A `severity` value that does not
  parse falls through to `score`. `--fail-on` uses this severity.
- **Not scanned** lists every file that was not evaluated, with the reason:
  larger than the size limit, a symbolic link, not a regular file (a device,
  socket or pipe), unreadable, timed out, or an engine error. Nothing is known
  about these files from this run.
- **Rule files not applied** lists rule files that did not compile when the
  scan compiled them, with file and line.
- **Notes** explain why a run is incomplete and other limits that applied.
- A saved run can be reopened from the app, and exported from the Export Center
  or `oxaudit-cli export`.

Stored match rows are capped at 100,000 and stored skipped-file rows at
100,000; the remainder is counted and the run is marked incomplete in the
match case.

### Masked excerpts

A rule reports secrets when it has one of the tags `secret`, `secrets`,
`token`, `keys`, `credentials`, `creds`, `password`, `api-key`, `apikey` or
`private-key` (any letter case), or the metadata `sensitive = true` (a boolean,
or the string `"true"`). For such a rule the matched bytes are cut before they
leave the scan: the excerpt keeps only the first 4 bytes, and only when the
match is longer than 8 bytes (otherwise nothing of it); the offset and length
are kept. This applies everywhere the excerpt appears: the result rows
(`excerptMasked` is set), the stored projection, the canonical graph's
evidence (encoding `masked-hex`, value `<first 4 bytes in hex>… (<length>
bytes)`), the events, the app, and the CLI's text, JSON and SARIF output (text
prints `<hex>… (masked: the rule reports secrets)`; SARIF regions keep the
exact byte length). Other rules' excerpts are not masked, so a rule written to
find credentials should carry one of these tags or `sensitive = true`.

### Export

SARIF 2.1.0 and the oxAudit JSON (the canonical run graph) work for YARA runs.
In SARIF, each string match is a `byteOffset`/`byteLength` region, the
severity maps to the result level, and the rule id is the one above. A
`--format json` report is oxAudit's result object. The inventory, VEX, ticket
CSV, JUnit and GitLab formats are refused for YARA runs, because an empty
document would read as a result.

```sh
oxaudit-cli yara ./target --rules rules/ --format sarif -o yara.sarif
```

## Run states and exit codes

A scan ends in one of these states.

| State | Meaning |
| --- | --- |
| `completed` | Every file was either scanned or listed as skipped for a per-file reason, every selected pack verified, and no cap was hit |
| `incomplete` | Coverage is not total. The matches reported are real |
| `cancelled` | You cancelled. No result is returned; earlier saved results remain |
| `failed` | The scan could not run, for example no rules compiled or the target is unreadable. No result is returned |

A run is **incomplete** when any of these happen:

- a selected pack failed verification, or the signature-pack store could not be
  read, so the pack was not applied;
- a file timed out (30 seconds) and was not fully evaluated;
- the YARA engine reported an error on a file;
- the target holds more than 1,000,000 files; the rest are not scanned;
- more than 100,000 matches were found; the rest are counted, not stored;
- rules compiled but **no file was scanned** (an empty folder, or every file
  was skipped): nothing was evaluated, so the run is incomplete
  (`yara_nothing_scanned`) and the report says no file was scanned rather
  than "no rule matched".

Files skipped for being over the size limit, being links, or being unreadable
are listed but do not by themselves make a run incomplete, unless no file at
all was scanned. Rule files that fail
to compile are listed and recorded as a run warning, and do not make the run
incomplete either. A scan with no compiled rules at all does not run: it fails
rather than reporting "no rule matched", and the message says whether no pack
is installed, every pack failed verification, or every rule file failed to
compile.

Pass `--strict` to make uncompilable rule files a failure: after printing the
report the command exits `3` with the count and the first few files. Without
`--strict`, such files are reported in the output but do not change the exit
code.

CLI exit codes follow the [CLI contract](cli.md#exit-codes):

| Code | Meaning |
| --- | --- |
| `0` | Completed; nothing at or above `--fail-on` matched (including no match at all) |
| `1` | Completed; a match at or above `--fail-on` |
| `2` | Usage error: no rules given, `--pack` without `--pack-db`, an unsupported `--format` (only `text`, `json`, `sarif` and `oxaudit-json` are accepted) |
| `3` | The scan failed, or it ended `incomplete` (the report is still printed, and the reasons go to stderr). Incomplete wins over `1`. Also `--strict` with a rule file that did not compile |

## Modules and unsupported features

Available modules: `pe`, `elf`, `macho`, `dotnet`, `lnk`, `dex`, `math`,
`hash`, `string`, `time` and `console`. `console.log` output is discarded; it
never reaches the host's output.

Not available: `cuckoo`, `vt` and `magic`, and any module not in the list
above. A rule file that imports one is skipped with `module 'x' is not
available in oxAudit`; the rest of the pack still applies.

Not supported:

- **`include`.** The compiler is given text only and never reads other files.
  A file using `include` is skipped with "`include` directives are not
  supported; inline the included rules".
- **Compiled rules** (`.yarc`, from `yarac` or YARA-X). Import refuses them.
- **Process or memory scanning.** Only files on disk are scanned.
- **External variables.** There is no way to define them, so a rule that needs
  one does not compile and is skipped.

## Compatibility with classic YARA

YARA-X's own documentation states that it "is not a drop-in replacement for
YARA". For the rule language, see its page
[YARA-X vs YARA](https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/).
That page says YARA-X reports more detailed errors, has faster regular
expressions and complex hex patterns, has APIs incompatible with libyara, does
not yet implement process scanning, and still lacks some YARA features. It does
not list rule-syntax differences in detail, so oxAudit does not repeat claims it
cannot confirm: validate your rules by importing them and reading the skipped
list. Rule files that compile under the embedded YARA-X version are applied.

What oxAudit itself decides:

| Topic | In oxAudit |
| --- | --- |
| Rule sources | `.yar` and `.yara` text files, UTF-8 |
| Compilation | Each file separately, in its own namespace `<pack>/<path>`. A failing file is skipped whole. Two files in the same pack may reuse a rule name |
| `include` | Not supported |
| Compiled `.yarc` | Refused at import |
| Modules | The eleven above; `cuckoo`, `vt`, `magic` unavailable |
| Process scanning | Not available |
| External variables | Not available |
| Private rules | Evaluated, never reported |
| Metadata | Kept and shown; `severity` and `score` set the severity; `sensitive = true` masks excerpts |
| Match output | Offsets, lengths, 64-byte hex excerpts (masked for rules that report secrets), at most 32 per rule per file |
| Timeout | 30 seconds per file |

## Performance and limits

- **Files are scanned in parallel**, one scanner per worker thread. Each file
  is read whole into memory before it is scanned, so memory use grows with file
  size times the number of workers.
- **Per-file timeout: 30 seconds.** YARA-X checks its timeout against a clock
  that ticks once a second, so a file can run up to about a second past the
  limit. A file that times out is listed as skipped and makes the run
  incomplete. The timeout is not configurable.
- **Size cap: 64 MiB by default**, set with **Max file size (MiB)** or
  `--max-file-size-mb`, from 1 to 1,024. Larger files are listed as not
  scanned. Each file is read into memory whole; the parallel workers share a
  read budget of at most 2 GiB, so a worker waits for room before it reads
  the next file, and a file larger than the budget is scanned alone. A file
  that grows while it is being read is listed as skipped.
- **File cap:** 1,000,000 files per target.
- **Cancellation** is checked between files; a file already being scanned
  finishes or times out first.
- **Rule limits:** see [import](#import-rules-as-a-signature-pack): 1 MiB per
  rule file, 20,000 files and 256 MiB per pack.

## Building without YARA

YARA is a Cargo feature, `yara`, on by default. A build made with
`--no-default-features` (and the features you want back) has no engine. In such
a build `scan_yara` and `oxaudit-cli yara` fail with "This build of oxAudit has
no YARA engine, so no scan was run", and YARA packs cannot be validated or
imported. A missing engine is reported as unavailable, never as an empty
result.

```sh
cargo build --manifest-path src-tauri/Cargo.toml --no-default-features \
  --features grammars-all,templates
```

The embedded engine also turns on insertion-ordered JSON maps for the whole
build; oxAudit's outputs do not depend on map order, so results match a build
without the feature.
