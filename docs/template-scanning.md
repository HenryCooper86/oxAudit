# Template scanning

oxAudit runs [Nuclei](https://docs.projectdiscovery.io/templates/introduction)
templates you supply. It implements the template format natively and invokes
no `nuclei` binary. Two kinds of scan use the same engine on the desktop, in
`oxaudit-cli template` and on the headless server:

- a **local-path scan** runs templates that use the `file` protocol against
  files and folders on disk, and sends nothing over the network;
- a **live-target scan** runs `http`, `dns`, `tcp` and `ssl` templates against
  targets you name, and sends network traffic to them.

oxAudit ships no templates. You import your own, or ones you are licensed to
use, as a **signature pack**. oxAudit is not affiliated with ProjectDiscovery
or VirusTotal. Nuclei is the name of ProjectDiscovery's project, and YARA of
VirusTotal's; the template format is implemented independently, from its
public documentation, and behaves differently in places (see the
[compatibility matrix](#compatibility-matrix)).

A scan reports the templates that matched. It does not report a target as
clean, safe or secure. "No template matched" covers only the templates that
ran, against what they could reach; every template, check and target that was
not evaluated is listed with the reason.

- [Before you scan](#before-you-scan)
- [Import template packs](#import-template-packs)
- [Local-path scans](#local-path-scans)
- [Live-target scans](#live-target-scans)
- [Scope](#scope)
- [Limits](#limits)
- [Which templates run](#which-templates-run)
- [Compatibility matrix](#compatibility-matrix)
- [Not evaluated](#not-evaluated)
- [Credential redaction](#credential-redaction)
- [Results, run states and exit codes](#results-run-states-and-exit-codes)
- [Headless server](#headless-server)
- [Building without templates](#building-without-templates)

## Before you scan

**Only scan systems you own or are explicitly authorized to test.** Templates
are written to find vulnerabilities and exposures; run against a system you
have no permission to test, they can be illegal, and even against your own they
can disrupt it.

A live-target scan will not start until you acknowledge this for that run:

- **Desktop and server.** Tick **I am authorized to test these targets** under
  **Authorization (required for each run)**. You may add a **Statement
  (optional)** (an engagement reference, or who approved the test; 200
  characters in the app). Editing the targets clears the tick.
- **Command line.** Pass `--i-am-authorized`. Without it the command exits `2`
  and sends nothing.

The acknowledgement is stored with the run: the fact that it was given, your
statement (the CLI records the fixed statement "The operator confirmed on the
command line, with --i-am-authorized, that they are authorized to test these
targets.") and the time. It is **not remembered between runs**; you give it
again each time. It records your statement. oxAudit does not verify it.

What traffic is sent:

- **HTTP templates:** requests to the target's web server, with each
  redirect hop that stays in scope. Bare hosts get one probe first, `GET
  https://host/` and then `GET http://host/`.
- **DNS templates:** questions about the target's name (and subdomains of it)
  to your system's DNS resolvers.
- **TCP templates:** connections to the target on the ports the template or
  target names, with the bytes the template sends.
- **SSL templates:** a TLS handshake to read the certificate.
- Every HTTP request identifies itself with
  `User-Agent: oxAudit/<version> (authorized security scan)` unless the
  template sets its own. Before the scan, each host name you typed is resolved
  once through the system resolver.
- Certificates are **not verified**: targets are often self-signed, and the
  scan assesses them rather than trusting them.
- Templates tagged `dos` never run. Templates tagged `intrusive` or `fuzz` run
  only when you switch them on for the run.

## Import template packs

Import works as for [YARA rules](yara.md#import-rules-as-a-signature-pack):
**Rule Library**, **Import signature rules**, kind **Nuclei**, or

```sh
oxaudit-cli signature-pack install --db packs.sqlite3 --kind nuclei \
  --name "My templates" --license MIT templates/
```

A licence is required, a pack is a file, folder or `.zip`, files are copied
into a `sigpacks` folder beside the pack database with a hash manifest, and the
pack is re-verified before every scan (a pack that fails is not applied and the
run is incomplete). Template packs read `.yaml` and `.yml` files, up to 1 MiB
per template; the other import limits are those of YARA packs. A YAML file with
no top-level `id` (a workflow, a config, a CI file) is not a template and is
only counted as ignored. A file that does not parse, or lacks an `id` or
`info.name`, is skipped with the reason. A repeated template id keeps the first
copy and lists the others. The preview shows supported templates per protocol
and how many **Not evaluated** templates the pack holds, each listed with its
reasons.

You can also pass templates for one scan only, without installing them:
`--templates FILE|DIR` (repeatable) on the CLI.

## Local-path scans

```sh
oxaudit-cli template --path ./tgt --templates ./templates
```

```text
Template scan of /work/tgt (path): 1 of 3 loaded template(s) run from 1 pack(s); 1 file(s) scanned (33 bytes).
1 template match(es) in 1 location(s).

app.cfg
  [high] Example token in a config file  (adhoc/doc-example-token)  tags: config, token
    2:1  … (6 chars)
    2:7  abcd… (16 chars)
    token: abcd… (16 chars)

2 template(s) or template check(s) were not evaluated:
  1 x needs a live target; a local path scan runs file templates only
  1 x uses the headless protocol; has no supported protocol block (http, dns, tcp, ssl, file)
note: 2 template(s) or template checks were not evaluated; each is listed with its reason.
note: 1 file(s) were not read because no selected template's file extensions apply to them.
```

(The matched text is masked here because the template carries the `token`
tag; see [credential redaction](#credential-redaction).)

- Only templates with a `file` block run; others are listed as not evaluated
  ("needs a live target").
- The walk reads every file under the path. Ignore files are not applied and
  symbolic links are not followed (a link is listed as skipped). Files over the
  size limit (64 MiB by default; `--max-file-size-mb`, 1 to 1,024) are listed
  as skipped. Files are read into memory whole, under a read budget of at
  most 2 GiB shared by the parallel workers (as for YARA scans).
- A file is read only when some selected template's block applies to it:
  `extensions` (or `all`), the block's `denylist`, `no-recursive`, and the
  block's `max-size` (default 5 MiB; `max-size: no` removes it). When
  `extensions` is empty or `all`, a built-in denylist of media, archive,
  binary and document extensions still applies: `3g2 3gp 7z apk arj avi axd bmp
  css csv deb dll doc drv eot exe flv gif gifv gz h264 ico iso jar jpeg jpg
  lock m4a m4v map mkv mov mp3 mp4 mpeg mpg msi ogg ogm ogv otf pdf pkg png ppt
  psd rar rm rpm svg swf sys tar tar.gz tif tiff ttf txt vob wav webm wmv woff
  woff2 xcf xls xlsx zip`. Naming an extension in `extensions` overrides its
  denylist entry. The count of unread files is shown in a note.
- `archive: true` is not honored: oxAudit does not open archives in template
  scans, and the template is listed as not evaluated for that reason.
- A match lists the matched lines (line, column, text), capped at 50 lines of
  300 characters, and extracted values.

## Live-target scans

In the app, open **Template Scan**, switch the mode to **Live targets**, enter
one target per line, tick the authorization, set tags and severities if you
want, and select **Run live scan**. On the command line:

```sh
oxaudit-cli template --target https://staging.example.com \
  --target 10.0.0.5:8080 --templates ./templates --i-am-authorized
```

`--target-file FILE` reads targets one per line (blank lines and `#` comments
ignored; at most 1 MiB). `--path` and `--target`/`--target-file` are separate
scans; give one. A real run against a loopback test server:

```text
Template scan of live targets http://127.0.0.1:18765: 2 of 2 loaded template(s) run from 1 pack(s); 2 request(s) sent.
2 template match(es) on 1 target(s).

http://127.0.0.1:18765
  [info] Follows an arbitrary URL  (adhoc/doc-offscope-redirect, http)
    matched at: http://127.0.0.1:18765/admin
    request: GET http://127.0.0.1:18765/admin HTTP/1.1
    response: HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 ...

Scope:
  requests sent: 2
  requests refused by scope (not sent): 1; refused hosts: 203.0.113.9
  unreachable targets: none
note: 1 request(s) were refused by scope and not sent; refused hosts: 203.0.113.9.
```

The second path in that template named a host the scan was not given, so the
request was refused and counted rather than sent.

Live scans run only templates that have a network protocol block; a
file-protocol-only template is listed as not evaluated ("needs a local path").
Work runs as template and target pairs, up to 25 at a time, under the
[limits](#limits).

## Scope

The targets you type are the scope. Every connection (each HTTP request and
redirect hop, each TCP session, each TLS probe) and every DNS question is
checked against it immediately before it is made. Anything else is refused and
counted, and the refused host names (host only, never a full URL) are reported.

### Accepted target forms

| Form | Examples |
| --- | --- |
| `http://` or `https://` URL, optional port and path | `https://staging.example.com/app`, `http://10.0.0.5:8080` |
| Host name | `staging.example.com` |
| `host:port`, IPv4, IPv6, `ip:port`, `[v6]:port` | `10.0.0.5:8443`, `::1`, `[::1]:8080` |
| CIDR | `10.0.0.0/28`, `fd00::/124` |

At most 1,000 targets, and at most 256 addresses across all CIDR ranges (for
IPv4 blocks of `/30` and wider the network and broadcast addresses are
skipped). Rejected: empty entries, URLs with credentials (`user:pass@`), other
schemes, wildcards, names that are not valid DNS names, numeric hosts that are
not plain dotted quads (`127.1`), port 0, and unspecified, multicast and
broadcast addresses. A bad target is named in the error and nothing is sent.
Host names are lower-cased, converted to punycode, and have a trailing dot
removed. An IPv4-mapped IPv6 address counts as the IPv4 address.

### Port rules

| You type | In scope |
| --- | --- |
| A bare host or IP (`example.com`, `10.0.0.5`), or a CIDR member | **Every port** on that host, because network templates probe service ports |
| `host:port` or `ip:port` | That port only |
| A URL with an explicit non-default port | That port only |
| A URL on the default port, written or not (`https://example.com`) | Ports 80 and 443, so an HTTP to HTTPS redirect stays in scope |

Targets that name the same host merge; a bare host makes every port of that
host in scope.

### What is and is not in scope

- **Subdomains are not in scope** for connections. Typing `example.com` does
  not allow a request to `api.example.com`.
- **Redirects** are followed by the scan itself, one hop at a time, each
  checked against scope. An off-scope redirect is not followed: the 3xx
  response is the final response and the refusal is counted. At most 10
  redirects, whatever the template asks for; `host-redirects` limits a template
  to the same host. A hop to another origin (a different scheme, host or port,
  including `https` to `http` on the same host) drops the template's
  `Authorization`, `Cookie` and `Proxy-Authorization` headers, and a hop to
  another host also drops `Host`. Cookies a response set are kept per host
  (any port, as a browser does) and only sent back to that host; a cookie set
  over `https`, or flagged `Secure`, is never sent over `http`.
- **A template's `Host` header** is sent as a header to the in-scope server
  (virtual-host testing) and never changes where the socket connects. A raw
  request's `@Host` annotation becomes the request URL and is checked like any
  URL. `@tls-sni` is ignored; the SNI is the URL host.
- **DNS questions** are allowed for an in-scope name and any subdomain of it,
  and for the reverse (`PTR`) name of an in-scope IP. Anything else is
  refused. DNS templates run against host-name targets; an IP target is not
  evaluated for DNS. DNS templates run even when the name did not resolve,
  since `NXDOMAIN` is often what they look for.
- **Pinned resolution.** Each host name is resolved once per run, and every
  connection to it uses only those addresses. The HTTP client is given a
  resolver that knows only the pinned names, so a DNS change mid-run cannot
  move a request. The resolved addresses are in the results. Answers that could
  never be a target (unspecified `0.0.0.0` or `::`, multicast, broadcast) are
  always dropped, and answers that are cloud metadata or link-local addresses
  are dropped (unless the name is itself a metadata name you typed). A NAT64
  answer (`64:ff9b::/96`, or the local-use `64:ff9b:1::/48`) is judged by the
  IPv4 address it embeds as well. Each dropped answer is named in the run
  notes. Private and loopback answers are kept, because you typed the name,
  and are noted in the run.
- **The DNS question sent** is the normalised name that scope checked
  (IDNA, lower case, no trailing dot), never the template's raw text.
- **Cloud metadata endpoints** are refused unless you typed that exact address
  or name as a target: `169.254.169.254`, `169.254.170.2`, `169.254.170.23`,
  `100.100.100.200`, `fd00:ec2::254`, `fd00:ec2::23`, and the names
  `metadata.google.internal`,
  `metadata.goog`, `metadata.azure.com`, `metadata`, `instance-data` and
  `instance-data.ec2.internal`. A CIDR range that covers one does not count as
  typing it: the address is left out, with a note.
- **Proxy.** Direct connections by default. Proxy environment variables
  (`HTTP_PROXY` and the like) are never read. An explicit `http://` or
  `https://` proxy (no credentials in the URL) from Settings or `--proxy`
  applies to HTTP templates only; DNS, TCP and SSL always connect directly.
  Scope is still checked on every request URL before it is sent, and the proxy
  host itself is resolved once and pinned.

### What can still reach beyond the listed hosts

Scope limits what oxAudit asks to be sent. It is not a network firewall:

- **DNS questions go to your system resolvers, which recurse.** A question
  about an in-scope name is answered by your resolver contacting other
  servers, including authoritative servers outside the list. `recursion:
  false` in a template is not honored, and the resolver is not configurable
  from a template.
- **Host names are resolved through the system resolver before the scan** to
  pin their addresses.
- **A proxy resolves target names itself.** With a proxy configured, oxAudit
  still pins and checks addresses, but the proxy looks the target name up and
  connects on its own; the run records a note saying so.
- **A bare host or IP is every port.** `10.0.0.5` allows connections to any
  port on that host, including ports you did not mean to test. Type
  `host:port` to limit it.
- **A CIDR range is every port of every address** in it.
- **Typing a name trusts what it resolves to.** A name that resolves to an
  internal address is used as such.
- **On a headless server started with `--allow-live-targets`, any holder of
  the access token can name internal or metadata addresses**, and the traffic
  comes from the server's network position. See [Headless server](#headless-server).

## Limits

| Setting | Default | Range | Settings label |
| --- | --- | --- | --- |
| Requests per second, across the whole run and all protocols | 50 | 1 to 1,000 | Requests per second |
| Requests in flight to one host | 10 | 1 to 100 | Concurrent requests per host |
| Connect and overall timeout of one request | 10 s | 1 to 120 s | Request timeout (seconds) |
| Response body (HTTP) or total read (TCP) cap | 4,096 KiB | 1 to 32,768 KiB | Max response size (KiB) |
| Outbound attempts per run | 100,000 | at least 1 | Max requests per run |
| Proxy (HTTP only) | none | `http://` or `https://` URL | Proxy (optional) |

The app keeps these in **Settings**, **Live scanning**. They apply to live
scans only. Saving settings (in the app or through the headless server)
refuses a value outside its range and a proxy that is not an `http://` or
`https://` URL or that carries a user name or password; the error says which
setting, and nothing is stored. A settings file written elsewhere is still
loaded as is: a value outside its range is clamped when a scan uses it, and
the run notes it. An unusable proxy (not a URL, a scheme other than http or
https, or credentials in the URL) stops the scan before anything is sent.

Other fixed limits: at most 10 redirects; an HTTP `@timeout` annotation is
clamped to 1 to 120 s; at most 10,000 payload combinations per request; at
most 100 variants for `iterate-all`; request conditions (`req-condition`,
`status_code_1` and the like) only for a block that sends at most 64
requests. When one of these planner caps cuts a template short against a
target, that template and target are listed as not evaluated with a reason
that starts `partly evaluated:` and says what was sent (for example "only
10000 of 40000 payload combinations were sent"), and the run is incomplete
(`template_plan_truncated`). Matcher evaluation problems the engine reports
(an unknown variable in a `dsl` matcher, for example) are kept as run notes,
deduplicated and capped at 200; reading a response stops at the cap and
the match records that it was truncated; a target is treated as unreachable
after 30 consecutive connection failures, or when no connection to it
succeeded; a target for which no request of any template was answered (for
example an IP target with only DNS templates, every request skipped for an
unresolved variable, or only protocol errors) is listed with the unreachable
targets and makes the run incomplete; reaching the request budget stops the
scan, which is then incomplete.

**Precedence.**

- The CLI reads no settings file. Its limits are the defaults above, replaced
  by `--rate-limit` (1 to 1,000), `--concurrency` (1 to 100), `--timeout`
  (1 to 120 seconds), `--max-requests` and `--proxy`. A value out of range is a
  usage error (exit `2`), not a clamp, so a CI job never runs with limits it
  did not ask for. These flags are accepted only with `--target`/
  `--target-file`. The CLI has no flag for the response cap; it uses 4 MiB.
- In the app and on the server, **Settings** supplies each limit. A per-run
  rate limit (the request field `rateLimit`, which the CLI sets with
  `--rate-limit`) replaces the requests-per-second setting for that run only.
  The Template Scan page does not expose a per-run rate limit.

## Which templates run

Filters are applied in this order. A template a filter leaves out is not
listed; every template left out after the filters is listed as not evaluated.

1. **`--id` / ids:** only templates with these ids.
2. **`--severity`:** only these severities (`info`, `low`, `medium`, `high`,
   `critical`; an unknown value is a usage error). A template whose severity is
   missing or unrecognised is reported as `info`.
3. **`--tags`:** only templates with any of these tags (comma separated).
4. **`--exclude-tags`:** never templates with any of these tags.

Then these rules apply whatever the filters say:

5. A template tagged **`dos` never runs**, even when you ask for that tag by
   name. It is listed as not evaluated.
6. A template oxAudit cannot evaluate is listed with its reasons.
7. A template tagged **`intrusive` or `fuzz` runs only with
   `--include-intrusive`** (the **Include intrusive templates** switch). It is
   off by default.
8. A template without request blocks is listed.
9. The mode must fit: a path scan runs templates with a `file` block, and a
   live scan runs templates with a network block (`http`, `dns`, `tcp` or
   `ssl`). A template with both can run in either mode, using the matching
   blocks.

Tags are compared lower-case. In the app, **Severities (none selected means
all)**, **Tags** and **Exclude tags** are the filters.

## Compatibility matrix

"Not evaluated" means the template loads but is not run, and is listed with the
reason; it never counts as a clean result.

### Protocols and top-level features

| Feature | Status |
| --- | --- |
| `http` (and the older `requests` key) | Supported |
| `dns` | Supported |
| `tcp` (and the older `network` key) | Supported |
| `ssl` | Supported |
| `file` | Supported, local-path scans only |
| `headless`, `javascript`, `code`, `websocket`, `whois` | Not evaluated. `code` templates are never executed under any setting |
| `flow`, `workflow`, `workflows` | Not evaluated |
| `self-contained` templates | Not evaluated |
| Out-of-band interaction (`interactsh` in any value, part or extractor) | Not evaluated |
| `variables` and `constants` | Supported |
| Template-level `stop-at-first-match` | Supported |
| Any `{{...}}` expression that does not parse or calls an unavailable function | Not evaluated |
| A regular expression Go accepts but the Rust `regex` crate does not (for example look-around or back-references) | Not evaluated, with the compile error |

### HTTP

| Feature | Status |
| --- | --- |
| `method`, `path`, `headers`, `body` | Supported |
| `raw` requests (well-formed), annotations `@Host`, `@timeout` | Supported |
| Raw annotation `@tls-sni` | Accepted and ignored; the SNI is the URL host |
| Other raw annotations | Not evaluated |
| `payloads` (inline lists) with `batteringram`, `pitchfork`, `clusterbomb` | Supported (10,000 combination cap) |
| Payload wordlist files | Not evaluated |
| `redirects`, `host-redirects`, `max-redirects` | Supported (hop cap 10) |
| Cookie reuse (`cookie-reuse`, `disable-cookie`) | Supported, per template |
| `stop-at-first-match`, `iterate-all`, `max-size`, `req-condition`, `skip-variables-check`, `disable-path-automerge` | Supported |
| Request history variables (`status_code_2`, `body_1`, ...) | Supported (up to 64 requests kept) |
| `unsafe`, `pipeline`, `race`, `global-matchers`, `fuzzing`, `analyzer`, HTTP digest authentication, `signature` | Not evaluated |
| Built-in variables `BaseURL`, `RootURL`, `Hostname`, `Host`, `Port`, `Path`, `File`, `Scheme`, `FQDN`, `RDN`, `DN`, `TLD`, `SD` | Supported |

### DNS, TCP, SSL, file

| Protocol | Supported | Not evaluated |
| --- | --- | --- |
| DNS | Record types A, AAAA, CNAME, NS, MX, TXT, SOA, PTR, CAA, SRV; classes inet, csnet, chaos, hesiod, none, any; payloads | Other record types, unknown classes, `trace` |
| TCP | `host` (with `tls://`), `port`, `exclude-ports`, `inputs` of type text or hex with `data`, `read` and `name`, `read-size`, `read-all`, payloads | Other input types, non-numeric ports |
| SSL | `address`, `min_version`, `max_version` of `tls12` or `tls13`, certificate and handshake facts | `tls_version_enum`, `tls_cipher_enum`, `tls_cipher_types`, `cipher_suites`, `scan_mode` other than auto or ctls, unknown versions |
| File | `extensions`, `denylist`, `max-size`, `no-recursive` | `mime-type` matching, `archive: true` |

### Matchers and extractors

| Item | Status |
| --- | --- |
| Matcher types `status`, `size`, `word`, `regex`, `binary`, `dsl` | Supported |
| Matcher fields `part`, `condition`, `negative`, `case-insensitive`, `encoding: hex`, `match-all`, `internal`, `name`, `matchers-condition` | Supported |
| Matcher type `xpath`; encodings other than `hex` | Not evaluated |
| Extractor types `regex` (with `group`), `kval`, `dsl`, and `internal` extractors that feed later requests | Supported |
| Extractor types `json` (jq) and `xpath` | Not evaluated |

Parts available to matchers and extractors (`part`):

| Protocol | Parts |
| --- | --- |
| HTTP | `body` (default), `header`, `all_headers`, `raw`, `response`, `all`, `status_code`, `content_length`, `request`, `host`, `url`, `matched`, `duration`, `cookies_from_response`, `headers_from_response`, and, over HTTPS, the certificate parts below |
| DNS | `raw` (default; also `body`, `all`), `rcode`, `question`, `answer`, `ns`, `extra`, `request`, `host` |
| TCP | `data` (default), `raw` (also `body`, `all`), `request`, `host` |
| SSL | `response` (default; a JSON document), `host`, `port`, `ip`, `sni`, `tls_version`, `tls_connection`, `cipher`, `key_exchange`, `probe_status`, `subject_cn`, `subject_dn`, `subject_org`, `subject_an`, `issuer_cn`, `issuer_dn`, `issuer_org`, `serial`, `not_before`, `not_after`, `fingerprint_hash`, `expired`, `self_signed`, `mismatched`, `wildcard_certificate`, `domains`, `emails` |
| File | `raw` (default; also `all`, `body`, `data`), `path` |

### DSL

Operators, all implemented: `+ - * / %`, `**`, `& | ^ ~`, `<< >>`, `==`, `!=`,
`<`, `<=`, `>`, `>=`, `&&`, `||`, `!`, `=~`, `!~`, `in`, the ternary `?:`,
string, integer and float literals (single, double and back-tick quoted), and
variables. Every expression in a template is parsed when the template loads, so
an unsupported one marks the template not evaluated before any request is sent.

Helper functions, implemented:

| Group | Functions |
| --- | --- |
| Encoding and hashing | `base64`, `base64_decode`, `base64_py`, `hex_encode`, `hex_decode`, `html_escape`, `html_unescape`, `url_encode`, `url_decode`, `md5`, `sha1`, `sha256`, `sha512`, `mmh3`, `hmac`, `gzip`, `gzip_decode`, `zlib`, `zlib_decode`, `generate_jwt` (HS256, HS384, HS512 and `none` only) |
| Strings | `concat`, `contains`, `contains_all`, `contains_any`, `starts_with`, `ends_with`, `equals_any`, `line_starts_with`, `line_ends_with`, `join`, `len`, `regex`, `regex_all`, `regex_any`, `remove_bad_chars`, `repeat`, `replace`, `replace_regex`, `reverse`, `to_lower`, `tolower`, `to_upper`, `toupper`, `trim`, `trim_left`, `trim_right`, `trim_prefix`, `trim_suffix`, `trim_space`, `json_minify`, `json_prettify` |
| Numbers and versions | `bin_to_dec`, `dec_to_hex`, `hex_to_dec`, `oct_to_dec`, `to_number`, `to_string`, `compare_versions`, `ip_format` (indexes 10 and 11 fail at evaluation) |
| Time and random | `date_time`, `to_unix_time`, `unix_time`, `rand_base`, `rand_char`, `rand_int`, `rand_text_alpha`, `rand_text_alphanumeric`, `rand_text_numeric` |

Not implemented (a template using any of them is not evaluated):
`generate_java_gadget`, `generate_dotnet_gadget`, `aes_gcm`, `print_debug`,
`wait_for`, `resolve`, `rand_ip`, `generate_jwt` with any other algorithm, and
any function name not in the table above.

### Behavioural differences from the reference `nuclei` scanner

Where a template is evaluated, oxAudit can still differ from `nuclei`. These
are known; confirm anything that matters by running both against a test system
you own.

- **HTTP/1.1 only.** There is no HTTP/2 support in the client.
- **TLS 1.2 and 1.3 only**, for `ssl` templates and `tls://` TCP. A probe that
  needs an older version is reported as not evaluated.
- **`@tls-sni` is ignored**; the SNI is always the URL host.
- **Certificates are never verified.**
- **Header names and order on the wire are chosen by the HTTP client**, and
  are not guaranteed to match the template. Templates that depend on exact
  header casing or order may behave differently.
- **Default headers.** `User-Agent: oxAudit/<version> (authorized security
  scan)`, `Accept: */*` and `Accept-Language: en` are added when the template
  does not set them.
- **Bare hosts** get an `https` then `http` probe, and the first scheme that
  answers is used for every HTTP template against that target.
- **DNS `recursion: false` is not honored** and `retries` is the resolver's
  own; DNS questions go to the system resolvers only.
- **Redirects** are capped at 10 and checked against scope at every hop;
  301, 302 and 303 become `GET` without a body, 307 and 308 keep method and
  body.
- **`gzip()` and `zlib()` output** is produced by a different compressor, so
  the compressed bytes can differ from Go's even though they decompress to the
  same data.
- **The `File` variable** is the last path segment, and is empty at the root
  (`/`).
- **`RDN` has no public-suffix list.** The registrable domain is taken as the
  last two labels, so `a.example.co.uk` gets `RDN` `co.uk`.
- **Regular expressions** use the Rust `regex` crate, not Go's RE2; patterns
  that only differ in unsupported syntax mark the template not evaluated.
- **Wordlist files for payloads** are not read; only inline payload lists.
- **File scans** apply a built-in extension denylist that includes `txt` when
  `extensions` is empty or `all`.
- **Severity** that is missing or unrecognised is reported as `info`.

## Not evaluated

A template can be left out for any of the reasons in the matrix, because of a
tag rule, or because it does not fit the scan mode. In live scans, a check can
also be left out for a target: no HTTP service answered on `https` or `http`,
a host did not resolve, a target stopped answering, a probe needed a TLS version
that is not available, or the request budget ran out.

Each case is listed with the template id, pack, file, protocol, target (live
scans) and reason, grouped by reason in the text report and shown in the **Not
evaluated** panel in the app. **Not evaluated never means clean.** A template
that was not evaluated tells you nothing about the target. Zero matches means
only that the templates that ran, against what they could reach, did not match:
it is not a statement that a target is free of issues. The text report says so
when no template matched.

Not-evaluated templates do not by themselves make a run incomplete. An
unreachable target does, and so does a run in which nothing was evaluated at
all: templates were selected but no file was evaluated by any of them (path
scans, for example a folder with no file a selected template applies to), or
no request of any of them was answered (live scans). That run ends
`incomplete` with `template_nothing_evaluated`, and the text report says
nothing was evaluated instead of "No template matched".

## Credential redaction

Stored excerpts are bounded and redacted. Each stored request and response
excerpt is at most 4 KiB, with a `[truncated]` marker when cut; binary bodies
are shown as a hex preview.

- **Headers.** The values of `Authorization`, `Proxy-Authorization`, `Cookie`,
  `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, and any header whose name contains
  `token`, `secret`, `password`, `passwd`, `api-key`, `api_key` or `apikey` are
  replaced by `[REDACTED]`.
- **URLs.** In stored request lines, in `Location`, `Content-Location` and
  `Referer` header values, in a match's `matchedAt`, and in every error
  message, user info and the values of query (and fragment) parameters whose
  names contain `token`, `key`, `secret`, `password`, `passwd`, `pwd`, `auth`,
  `signature`, `sig`, `session`, `sid`, `jwt`, `bearer`, `credential`,
  `apikey`, `api_key`, `access_token` or `client_secret` (any case) are
  replaced by `[REDACTED]`. Connection and exchange errors name only the
  scope-checked `host:port`, never the URL. For a credential template (below)
  every query value of the request line and of `matchedAt` is redacted.
- **Credential templates.** For a template tagged any of `token`, `keys`,
  `secret`, `secrets`, `credentials`, `creds`, `password`, `api-key`, `apikey`
  or `private-key`, the
  matched and extracted values (and, for file matches, the matched lines) are
  masked to the first four characters plus the length (`AKIA... (20 chars)`;
  values of 8 characters or fewer show only the length). The stored response
  body is withheld and replaced by a marker (an HTTP response keeps its status
  line and redacted headers), and matched values are masked wherever they
  appear in the stored request. The text report prints `response: withheld
  (this template reports credentials)`. The common `exposure` tag does not
  trigger this: it marks many findings that are not credentials. The header
  redaction above applies to every template whatever its tags.
- Authorization statements are stored as you typed them. Do not put secrets in
  one. A proxy URL with credentials is refused, and a proxy URL is never echoed
  in an error.

## Results, run states and exit codes

A match lists the template id and name, severity, tags, pack, protocol, where it
matched, matcher names, extracted values, the template's description,
references, classification and remediation, and for live matches the stored
exchange (request, response excerpt). The **Scope** panel and the text report's
`Scope:` section show requests sent, requests refused by scope with the refused
hosts, the addresses each host name was pinned to, unreachable targets, and the
recorded authorization.

| State | Meaning |
| --- | --- |
| `completed` | Everything selected ran or was listed, and no cap or failure applied |
| `incomplete` | Coverage is not total; matches are real |
| `cancelled` | You cancelled; no result is returned |
| `failed` | The scan could not run (for example an invalid target or proxy, or no templates); nothing was sent for an invalid target |

A run is **incomplete** when a selected pack failed verification or the store
was unreadable, a target was unreachable or no request of any template
against it was answered, the request budget ran out, a planner cap cut a
template short, nothing at all was evaluated (see above), the live scan did
not finish for another reason, the target holds more than 1,000,000 files,
or more than 100,000 matches were found. An incomplete run exits `3` from the
CLI, so a scan that evaluated nothing never exits `0`.

CLI exit codes: `0` completed and nothing at or above `--fail-on`; `1`
completed with a match at or above `--fail-on`; `2` a usage error (no `--path`
or target, both given, a live scan without `--i-am-authorized`, a limit flag
out of range, a live-only flag on a path scan, an unknown severity, an
unsupported `--format`, an invalid target such as a wildcard, an oversized
CIDR, a URL with credentials, an unsupported scheme or more than 1,000
targets); `3` the scan failed while running, or ended incomplete (the report
is printed and the reasons go to stderr; incomplete wins over `1`), or
`--strict` found a template file that did not load.

A scan with no runnable template fails (exit `3`) and the message says why: the
installed packs failed verification, your tag, severity or id filters left
nothing, the templates are tagged `dos`, none applies to this scan mode, or no
file loaded as a template.

`--strict` makes template files that fail to load (invalid YAML, no `id`,
unreadable, or a repeated id) a failure: after printing the report the command
exits `3` with the count and the first few files. Templates that are "not
evaluated" because they use unsupported features or belong to the other scan
mode do not count, since any real pack has them. Without `--strict`, files
that did not load are reported in the output but do not change the exit code.

`--format` is `text` (default), `json`, `sarif` or `oxaudit-json`; any other
value is rejected by the command line as a usage error. SARIF maps
file matches to line regions and live matches to their endpoint, with the
template's metadata on the rule. The inventory, VEX, ticket CSV, JUnit and
GitLab formats are refused for template runs. `--db FILE` saves the run for
`oxaudit-cli runs --kind template` and `export`.

## Headless server

`oxaudit-server` refuses live-target scans unless it was started with
`--allow-live-targets` (or `OXAUDIT_SERVER_ALLOW_LIVE_TARGETS=1`; `true` also
works, any other value leaves them refused). It is off by default because a
live scan sends traffic from the server's own network position: anyone with the
access token could otherwise use the server to probe the network it sits in,
including internal hosts, cloud metadata and services bound to its loopback.
The refusal happens before any target is parsed or contacted. Local-path
template scans work either way. With the flag set, the server logs that anyone
with the access token can make it send traffic to targets they name, and the
page in the browser shows whether live targets are allowed. See
[the headless server](headless-server.md).

## Building without templates

Template scanning is a Cargo feature, `templates`, on by default. Without it,
`scan_templates` and `oxaudit-cli template` fail with "no template engine in
this build", and Nuclei packs cannot be validated or imported. Missing support is
reported as unavailable, never as an empty result.

```sh
cargo build --manifest-path src-tauri/Cargo.toml --no-default-features \
  --features grammars-all,yara
```
