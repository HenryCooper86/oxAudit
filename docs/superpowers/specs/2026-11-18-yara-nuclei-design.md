# YARA rules and Nuclei templates

Date: 2026-11-18. Status: implemented on branch `yara-nuclei`: both engines, signature packs, the YARA and Template scans on desktop, CLI and headless server, the live-target scope and limits, the UI pages and the user guides ([YARA](../../yara.md), [templates](../../template-scanning.md)). Where the code and this design differ, the code is the truth; see [As built](#as-built).

## Goal

oxAudit runs YARA rules and Nuclei templates that users already have, natively,
through the same engine on desktop, CLI and headless server.

- **YARA**: scan local files and folders with imported `.yar`/`.yara` rules.
- **Nuclei templates**: run file-protocol templates against local paths, and
  HTTP, DNS, TCP and SSL templates against live targets the user names.

oxAudit ships the engines and no third-party rules. Users import their own
content; the licence is recorded per pack.

## Decisions taken with the user

1. Live-target scanning is in scope now (not files only).
2. Import only: no bundled YARA rules or Nuclei templates.

## Assumptions (mine; correct any of these)

- YARA uses VirusTotal's YARA-X 1.23 (pure Rust, BSD-3-Clause), embedded. No
  external `yara` binary. Spike result: builds on Rust 1.97.1 and passes
  `deny.toml` licences, bans and sources. With `default-features = false`
  the crate needs `rsa` with `pkcs1v15` enabled by us (upstream feature gap).
- Nuclei has no Rust engine, so the template format is implemented natively.
  No `nuclei` binary is invoked.
- Two new run kinds: `yara` and `template`. One Template Scan covers both a
  local path (file protocol) and live targets.
- Matches are stored as observations plus a projection, like binary scans.
  They do not enter the source review workflow in this version.
- YARA is a Cargo feature `yara`, on by default. Without it the capability
  reports Unavailable; it never reports clean.
- Headless server refuses live-target scans unless started with
  `--allow-live-targets`. A token holder could otherwise use the server to
  probe the network it sits in.
- GPL rule packs may be imported by a user into their own data directory. The
  licence is recorded and shown. Nothing GPL enters the repository; test
  fixtures are authored here.

## Architecture

```
crates/oxaudit-yara      pure: compile rule sources, scan bytes       (yara-x)
crates/oxaudit-nuclei    pure: template model, DSL, matchers, request planning
src-tauri/src/sigpacks/  host: signature pack store (files + SQLite)
src-tauri/src/yara/      host: file walk, parallel scan, graph, projection
src-tauri/src/template/  host: scope policy, HTTP/DNS/TCP/SSL executors, graph
commands/yara.rs, commands/template.rs, commands/sigpacks.rs
```

Neither pure crate does I/O or networking. `oxaudit-domain` and
`oxaudit-application` do not depend on them (dependency wall unchanged).

### Domain additions

- `RunKind::Yara`, `RunKind::Template`; `WorkKind::Yara`, `WorkKind::Template`.
- `ArtifactKind::File` (any scanned file), `ArtifactKind::NetworkTarget`.
- `ObservationKind::SignatureMatch` (YARA), `ObservationKind::TemplateMatch`.
- `Evidence::NetworkExchange { protocol, target, request, response_excerpt,
  matcher_name, extracted }`. Request and response are bounded (4 KiB each)
  and `Authorization`, `Cookie`, `Set-Cookie` and proxy auth values are
  redacted. YARA string matches reuse `Evidence::BinaryMatch`; file-template
  matches reuse `Evidence::FileLocation`.

### Signature packs

A signature pack is a set of files of one kind (`yara` or `nuclei`) imported
from a file, a folder or a `.zip`.

- Files are copied to `<data>/sigpacks/<kind>/<id>/` with a manifest of
  per-file SHA-256. The pack's `content_sha256` covers the sorted manifest.
  Every scan re-verifies the manifest; a pack that fails is skipped with a
  reason, as TOML packs are today.
- Table `signature_packs` in the rule-pack database: id, kind, name, version,
  license, source, authors, content_sha256, file_count, rule_count,
  skipped_json, enabled, installed_at.
- Licence is required at import. It is prefilled from a `LICENSE`/`COPYING`
  file in the pack root when one is recognised, and the user confirms it.
- Limits: 20,000 files, 1 MiB per file, 256 MiB per pack. Zip members use
  `enclosed_name`; symlinks are not followed.
- Runs record `rule_pack_ids` as `<kind>:<id>@<content_sha256 prefix>`.
- Removing a pack never alters past runs.

### YARA

`oxaudit-yara`:

- `RuleSet::compile(sources, limits)` adds each file separately so one bad
  file does not sink the pack. Result carries compiled rules plus
  `skipped: [{ file, line, message }]`.
- Modules enabled: pe, elf, macho, dotnet, lnk, dex, math, hash, string,
  time, console. `cuckoo`, `vt` and `magic` need external data; a file that
  imports them is skipped with that reason.
- `include` resolves only inside the pack root.
- `scan(bytes, timeout)` returns `[{ rule, namespace, tags, meta,
  strings: [{ identifier, offset, length, excerpt }] }]`. Excerpts are capped
  at 64 bytes; at most 32 string matches per rule per file are kept and the
  rest are counted.
- Compiled `.yarc` files from libyara cannot be loaded; import refuses them
  with that explanation.

Host engine `scan_yara_engine`:

- Walks the target with no ignore rules (malware hides in ignored folders),
  no symlink following, files up to 64 MiB by default.
- Parallel with rayon, one scanner per thread, 30 s per-file timeout,
  cancellable between files.
- Every file not scanned is listed with a reason (too large, unreadable,
  timed out). The run is `Incomplete` when any file timed out or the walk was
  cut short, never `Completed`.
- Projection `yara` v1: `{ matches, filesScanned, skipped, packs,
  rulesCompiled, rulesSkipped }`. Paged sections: `matches`, `skipped`.
- Severity: from rule meta `severity` when it parses, else `score`
  (≥80 critical, ≥60 high, ≥40 medium, ≥20 low), else `medium`.

### Nuclei templates

`oxaudit-nuclei` loads a YAML template into a model and classifies it:

- **Supported** protocols: `http` (also the legacy `requests` key), `dns`,
  `tcp` (also `network`), `ssl`, `file`.
- **Not evaluated** (listed per template with the reason, never silently
  dropped): `headless`, `code`, `javascript`, `flow`, `workflows`,
  `websocket`, `whois`; out-of-band interaction (`{{interactsh-url}}`);
  `unsafe` raw requests, `pipeline`, `race`, `fuzzing`; `xpath` matchers and
  extractors; `json` (jq) extractors; `self-contained` templates; any DSL
  function not implemented. `code` templates are never executed under any
  setting.
- HTTP: `method`/`path`/`headers`/`body`, well-formed `raw` requests,
  `payloads` with `batteringram`, `pitchfork` and `clusterbomb`, redirects
  (`redirects`, `host-redirects`, `max-redirects`), cookie reuse,
  `stop-at-first-match`, request conditions (`status_code_2`, `body_1`, …),
  `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}`, `{{Host}}`, `{{Port}}`,
  `{{Path}}`, `{{File}}`, `{{Scheme}}`, template `variables`.
- Matchers: `status`, `size`, `word`, `regex`, `binary`, `dsl` with `part`,
  `condition`, `negative`, `case-insensitive`, `encoding: hex`, `match-all`,
  `internal`, `name`, and `matchers-condition`.
- Extractors: `regex` (with group), `kval`, `dsl`, including `internal`
  extractors that feed later requests.
- DSL: literals, variables, comparison, boolean and arithmetic operators,
  regex match operators, and the documented helper functions except payload
  gadget generators, `aes_gcm`, `print_debug` and `wait_for`. All expressions
  are parsed at load so an unsupported one marks the template before any
  request is sent.
- Go's RE2 syntax maps to the Rust `regex` crate; a pattern that does not
  compile marks the template not evaluated.

The crate plans requests and evaluates responses; it sends nothing.

### Live targets: scope and safety

The host executor is the only code that opens connections.

- **Scope**: the targets the user typed (URL, host, host:port, IP, CIDR up to
  256 addresses). Every request, redirect hop and DNS question is checked
  against scope; anything else is refused and counted. Redirects leave scope
  only never.
- **Pinned resolution**: a host is resolved once per run and connections use
  those addresses, so a DNS change mid-run cannot move a request.
- **Metadata endpoints** (`169.254.169.254`, `fd00:ec2::254`,
  `metadata.google.internal`) are refused unless typed as a target.
- **Authorization**: each run needs an explicit acknowledgement that the user
  is authorized to test the targets. It is stored in the run with its
  timestamp and is not remembered between runs.
- **Limits** (settings, with these defaults): 50 requests/s overall, 10
  concurrent requests per host, 10 s timeout, 4 MiB response cap, 100,000
  requests per run.
- **Tags**: `dos` templates never run. `intrusive` and `fuzz` are off unless
  switched on for the run.
- **Proxy**: direct connections by default; proxy environment variables are
  ignored. An explicit proxy can be set in settings.
- TLS certificates are not verified (targets are often self-signed); the
  certificate facts are available to `ssl` templates.
- User-Agent identifies oxAudit and the version unless a template sets one.
- **Server**: `scan_templates` with live targets returns a refusal unless the
  server was started with `--allow-live-targets`
  (`OXAUDIT_SERVER_ALLOW_LIVE_TARGETS=1`). Local-path template scans work
  without it.
- Outcome honesty: a template that could not be evaluated, a target that
  could not be reached, and requests refused by scope are each reported as
  not evaluated. Zero matches is not a statement that a target is safe.

Protocol clients: HTTP via `reqwest` (manual redirects, per-template cookie
jar), DNS via `hickory-resolver` (A, AAAA, CNAME, NS, MX, TXT, SOA, PTR, CAA,
SRV), TCP via tokio (`data`, `hex`, `read`, `read-size`, `tls://`), SSL via
rustls handshake with certificate fields parsed.

### Surfaces

Commands (Tauri and server dispatch, same engine functions):

- `validate_signature_pack`, `install_signature_pack`, `list_signature_packs`,
  `set_signature_pack_enabled`, `remove_signature_pack`
- `scan_yara`, `scan_templates`; cancel through the existing
  `cancel_scan_work`.

Events: `yara://progress`, `template://progress`, plus `run://event`.

CLI:

```
oxaudit-cli yara PATH [--rules FILE|DIR]... [--pack ID]... [--pack-db FILE]
oxaudit-cli template (--path DIR | --target T... | --target-file F)
    [--templates FILE|DIR]... [--pack ID]... --i-am-authorized
    [--tags a,b] [--exclude-tags a,b] [--severity s] [--rate-limit N]
    [--include-intrusive]
oxaudit-cli signature-pack install|list|enable|disable|remove
```

Both scans support `--format text|json|sarif` and `--fail-on`. SARIF gains
mappings for byte-offset matches and network matches.

Frontend:

- Rule Library: a "Signature packs" section (kind, licence, counts, skipped
  files, enable switch, remove).
- YARA Scan page: target, pack selection, matches with rule, tags, string
  offsets and excerpts, skipped files.
- Template Scan page: mode switch (local path / live targets), targets field,
  authorization checkbox, tag and severity filters, intrusive switch,
  matches with request and response excerpts, a "not evaluated" list.
- Settings: Live scanning section (rate, concurrency, timeout, proxy).

## Testing

- Pure crates: unit tests per matcher, extractor, DSL function, payload
  attack, and YARA module; fixtures authored in this repo.
- Host: loopback HTTP, TCP and TLS test servers; scope tests proving an
  off-scope redirect, an off-scope `Host`, and a metadata address are
  refused; cancellation; manifest tamper detection.
- Server: live-target refusal without the flag.
- CLI end-to-end for `yara` and `template --path`.
- Playwright: YARA scan smoke; template scan against a loopback fixture
  server started by the harness.
- All existing gates stay green, including `cargo deny`.

## Build order

1. `oxaudit-yara` crate.
2. `oxaudit-nuclei` crate (model, DSL, matchers, extractors, planning).
3. Domain additions and the signature pack store with its commands.
4. YARA engine, command, CLI, SARIF mapping.
5. Template engine for the file protocol, command, CLI.
6. Live executors and scope policy; server flag.
7. Frontend: Rule Library section, YARA Scan, Template Scan, settings.
8. Docs (`docs/yara.md`, `docs/template-scanning.md`, README egress
   statement, `docs/headless-server.md`, `docs/cli.md`), `NOTICE`,
   `CHANGELOG.md`, Playwright smokes.

## As built

The design above was written before implementation. These are the differences
found when the guides were written from the code.

YARA and packs:

- `include` is not supported at all; the design had it resolve inside the pack
  root. A file using it is skipped with that reason, and the compiler never
  reads other files.
- Match excerpts are returned as lowercase hex (`excerptHex`), not as text.
  The 64-byte and 32-per-rule caps are as designed.
- A single rule file over 1 MiB, or any compiled `.yarc` (or a file starting
  `YARA`), refuses the whole import rather than skipping that file. Import also
  caps directory entries and archive members at 200,000.
- Incomplete is broader than designed: a pack that fails verification, an
  unreadable pack store, a YARA engine error on a file, and the 100,000-match
  cap also make a run incomplete, besides timeouts and the file cap
  (1,000,000 files). Rule files that do not compile, and files skipped for size,
  links or read errors, do not.
- The `yara` projection carries more than the designed fields: `state`,
  `runId`, `target`, `bytesScanned`, `matchesDropped`, `skippedDropped`,
  `rulesSkippedTotal`, `notes` and `durationMs`.
- The per-file timeout is 30 s but YARA-X checks it against a clock with
  one-second granularity.
- A zip with a single top-level folder has that folder stripped on import, and
  a licence file is detected only at the pack root.

Templates:

- Not implemented DSL helpers are more than designed: `resolve` and `rand_ip`
  as well as the gadget generators, `aes_gcm`, `print_debug` and `wait_for`;
  `generate_jwt` supports only HS256, HS384, HS512 and `none`; `ip_format`
  indexes 10 and 11 fail at evaluation.
- Not evaluated beyond the designed list: payload wordlist files, `file`
  templates with `mime-type` or `archive: true`, `global-matchers`, response
  analyzers, HTTP digest authentication, request signing, unknown raw
  annotations, several `ssl` options (version and cipher enumeration,
  `cipher_suites`, some `scan_mode` values), and DNS `trace` and record types
  outside the ten listed. `@tls-sni` is accepted and ignored. TLS is 1.2 and
  1.3 only.
- DNS goes to the system resolvers only, `recursion: false` is not honoured and
  `retries` is the resolver's.
- Scope is stricter and more detailed than designed: at most 1,000 targets;
  subdomains are not in scope for connections (they are for DNS questions); a
  bare host or CIDR member is every port; a URL on its default port is ports 80
  and 443; an off-scope redirect leaves the 3xx as the final response; metadata
  endpoints cover more addresses and names than the three listed, and metadata
  or link-local DNS answers are dropped.
- Limits beyond the five designed: at most 10 redirects, a target is
  unreachable after 30 consecutive connection failures, response cap range 1 to
  32,768 KiB. The CLI adds `--concurrency`, `--timeout`, `--max-requests`,
  `--proxy`, `--id`, `--max-file-size-mb`, `--db`, `--output` and `--format`
  `oxaudit-json`, and reads no settings file; out-of-range flags are usage
  errors, whereas settings are clamped with a note.
- Redaction of credential-bearing output is keyed to template tags (`token`,
  `keys`, `secret`, `secrets`, `credentials`, `creds`, `password`, `api-key`,
  `apikey`, `private-key`; not `exposure`, a common tag for non-credential findings):
  values are masked and the stored response body withheld. The design only
  redacted headers.
- The stored exchange is `NetworkExchangeEvidence` with `matcher_names` and
  `response_truncated`; it has no single `matcher_name`.
- The Template Scan page has no per-run rate-limit field; the setting (or the
  CLI flag) supplies it. The page's authorization statement is limited to 200
  characters, the engine's to 500.
- The server exposes whether live targets are allowed to the GUI through
  `/env.js` (`liveTargetsAllowed`), and also accepts `true` for the environment
  variable.
