# oxAudit

**Find vulnerabilities and leaked credentials in source, dependencies, and
binaries — on your machine, in your pipeline, and without sending your code
anywhere.**

A desktop workbench and a command line over the same engine, so a finding in CI
and a finding on a workstation are the same finding.

<!-- SCREENSHOT: a populated Source Scan — findings list, one finding selected,
     detail pane showing the review gates. 1440x900, both themes if practical.
     Capture with `npm run tauri dev` against benchmarks/corpus. -->

![Tauri 2](https://img.shields.io/badge/Tauri-2-24c8db)
![React 19](https://img.shields.io/badge/React-19-61dafb)
![Rust 1.97](https://img.shields.io/badge/Rust-1.97-dea584)
![Licence Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue)

---

## Install

> **No release has been cut yet.** Build from source for now — see
> [Development](#development). The release pipeline is in place and unused.

When the first release lands, builds for macOS, Windows, and Linux will be
published on the [releases page](https://github.com/HenryCooper86/oxAudit/releases),
each signed and notarized, with a SHA-256 checksum, a SLSA build-provenance
attestation, and a CycloneDX SBOM of oxAudit itself, so a download can be
verified rather than trusted:

```bash
sha256sum -c SHA256SUMS.txt
gh attestation verify <file> --repo HenryCooper86/oxAudit
```

The desktop app and `oxaudit-cli` ship together.

## Sixty seconds

```bash
# What is in this project?
oxaudit-cli scan .

# Put it in a pipeline. --fail-on is opt-in, so this reports without
# breaking your build until you ask it to.
oxaudit-cli scan . --format sarif --output oxaudit.sarif --fail-on high
```

In GitHub Actions:

```yaml
- run: oxaudit-cli scan . --format sarif --output oxaudit.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: oxaudit.sarif
```

Adopting a scanner on an existing codebase means meeting a backlog. Gate on what
the change introduced and leave the rest visible:

```bash
# On main, once: capture where you are today.
oxaudit-cli scan . --format json --output baseline.json

# On every pull request: fail only on what this change added.
oxaudit-cli scan . --baseline baseline.json --fail-on-new high
```

Reviewed something and decided it is not a problem? Record it in
[`.oxaudit/policy.json`](#suppressing-a-finding) and it stops failing the build —
with a reason, an expiry, and a pull request.

## What makes it different

- **It tells you how accurate it is.** [Detection quality](#detection-quality) is
  measured against a committed corpus and published per rule, including the
  numbers that are not flattering. CI fails if they regress.
- **Every finding says how far it was verified** — `syntax` when a parser
  confirmed the match sits in code rather than a comment, `text` when no grammar
  was available.
- **Nothing is sent anywhere.** Scanning is local. oxAudit contacts NVD, OSV,
  CISA KEV, and FIRST EPSS, plus whatever AI endpoint you configure — and
  nothing else. There is no telemetry to opt out of.
- **Dismissals are decisions, not deletions.** A suppressed finding stays in the
  report with its reason and its author, and expires.
- **The assistant asks before it reaches the network**, and cannot reach your
  own machine or network at all. See [Security notes](#security-notes).

---

## Features

| Capability | What it does |
|---|---|
| **Source code scanning** | 79 dangerous-code patterns across JavaScript/TS, Python, Java, Go, C/C++, C#, Kotlin, Swift, PHP, Ruby, Rust, plus generic rules (eval, exec, SQL injection, unsafe deserialization, `shell=True`, `strcpy`, XXE, weak randomness, weak crypto, hardcoded passwords, …), each mapped to a CWE with remediation guidance, and flagged when that weakness class is actively exploited in the wild (CISA KEV) |
| **Secret scanning** | 30+ regex rules (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, npm/PyPI tokens, private keys, JWTs, bearer tokens, generic high-entropy API keys/passwords…) with **Shannon entropy** filtering and placeholder suppression |
| **Dependency scanning** | Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `Pipfile.lock`, `Gemfile.lock`, `composer.lock`, `pom.xml`, `requirements.txt` and checks every pinned package against the **OSV** vulnerability database (batch queries, fixed-version extraction, CVSS score computation from vector strings), then ranks each finding by CISA KEV and EPSS — same exploitation signal as the binary scanner |
| **CVE research** | Search the **NVD** API (keyword search, recent-modified filter, pagination, rate-limit aware, optional NVD API key), per-package OSV advisories, full CVE detail pages with affected products, references, CWEs, raw OSV records, and a CISA KEV / EPSS exploitation badge |
| **AI assistant** | Chat with any **OpenAI-compatible** endpoint (OpenAI, Ollama, LM Studio, vLLM, Groq, OpenRouter…). **Streaming responses** with live reasoning display, typed error handling with automatic retry, **per-conversation token & cost tracking**, cancellable turns, and an **agentic tool loop**: the AI can read files, grep/glob the scanned project, run scans, search NVD, query OSV, and fetch web pages — every tool call rendered live with a status card, gated by an allow/ask/deny permission pipeline with HITL approval, a loop guard, and dual iteration/call budgets. One-click "Ask AI" on every finding and "Generate research briefing" on every CVE |
| **Binary scanning** | Detects vulnerable components bundled inside compiled binaries and firmware images (statically linked OpenSSL, zlib, zstd, sqlite, …) with oxAudit's **own scanner** — no database to download, no external tool required — then looks each component up in NVD and OSV, and ranks every finding by CISA KEV (actively exploited?) and EPSS (exploitation probability). Optionally also runs [cve-bin-tool](https://github.com/ossf/cve-bin-tool) or [grype](https://github.com/anchore/grype) if you have them installed; neither is bundled |
| **Durable evidence and inventory** | Source, Dependency, Binary, and imported SBOM runs use one persisted Artifact → Component → Observation → Evidence → Finding graph. Runs survive restart, unflagged components remain visible, provider/rule snapshots preserve historical meaning, and every scan family shares the same lifecycle timeline |
| **Rules, data, and quality** | A GUI Rule Library exposes provenance and fixture health and safely validates bounded declarative packs; Data Sources exposes immutable advisory snapshots and offline readiness; Quality Lab runs committed ground truth and reports precision, recall, misses, runtime, corpus size, and regression honestly |
| **Standards and verification** | Preview and export oxAudit JSON, SARIF 2.1.0, CycloneDX 1.6, SPDX 2.3, OpenVEX, and CycloneDX VEX. Preview bounded imports with conflict/unmapped records, import SBOM inventory separately, and retain strictly mapped SARIF/VEX assertions as immutable `external-unverified` claims that cannot alter local findings or reviews. Independent verification records bind a separate verifier to an immutable input hash |
| **Compliance readiness and reports** | GUI-first evidence checks for ISO 26262, ISO/SAE 21434, UNECE R155/R156, GDPR, CCPA/CPRA, NIST Privacy Framework, and ISO/IEC 27001; append-only qualified reviews; and professional JSON, CSV, Markdown, self-contained HTML, and paginated PDF reports. Readiness is never presented as certification or legal conformity |
| **Dashboard** | At-a-glance stats, quick actions, recent scan history |
| **Sessions** | Every AI conversation is **persisted** (JSONL transcripts + index) with a searchable session sidebar, resume-on-launch, auto-titles, per-session token/cost totals, and tool-call history that survives reload |

## Screens

- **Dashboard** — overview and quick actions
- **Source Scan** — folder picker, scan options, live progress, filterable findings grouped by file, JSON report export
- **Dependencies** — lockfile discovery, OSV check, vulnerable-package table with fixed versions and reference links
- **Binary Scan** — file/folder target, cve-bin-tool detection with a first-class "not installed" state, live progress, components grouped with their CVEs
- **Inventory** — all normalized components, versions, aliases, purl/CPE identities, source artifacts, confidence, and advisory matches—including components with no match
- **Rule Library** — built-in provenance/fixture health plus safe validation of external declarative TOML packs without installation or script execution
- **Quality Lab** — reproducible ground-truth metrics, misses, false positives, limitations, history, and regression state
- **Data Sources** — provider source/terms, immutable snapshot hashes, refresh state, and honest offline readiness
- **Export Center** — validated JSON/SARIF/SBOM/VEX preview/export plus bounded import and conflict preview
- **Verification** — producer-independent human verification bound to immutable finding evidence
- **Compliance Center** — framework selection, bounded local evidence collection, durable control matrices, and append-only human decisions
- **Report Studio** — professional multi-format report metadata, disclosure controls, preview, atomic save, and content receipts
- **CVE Research** — NVD search + OSV package lookup + detail view with AI briefing
- **AI Assistant** — chat with code/context attachment
- **Settings** — AI endpoint config, scan defaults, ignored directories, NVD API key, allowed fetch hosts, diagnostics

Press <kbd>⌘K</kbd> (<kbd>Ctrl</kbd>+<kbd>K</kbd> on Windows and Linux) to reach any
screen — or any project you have scanned before — from the keyboard. Type what
you know it as: `sarif`, `lockfile`, `precision`, `epss`, or a client directory
name. Each project shows what is still open beside it, so switching between a
dozen codebases does not mean opening a file dialog.

In a findings list, <kbd>j</kbd>/<kbd>k</kbd> move, <kbd>x</kbd> selects, and
<kbd>shift</kbd> extends a selection — then review the whole selection at once
with one reason.

## Command line

`oxaudit-cli` runs the same scanners, rules, and policy evaluation as the desktop
app — it is a second adapter over the same core, not a second engine, so a
finding reported in CI and a finding reported in the window are the same finding.

```bash
# Human-readable, grouped by file
oxaudit-cli scan .

# SARIF for GitHub code scanning and most CI viewers
oxaudit-cli scan . --format sarif --output oxaudit.sarif

# Gate a build. Opt-in: --fail-on defaults to `none`
oxaudit-cli scan . --fail-on high

# Fail only on what this change introduced, not the existing backlog
oxaudit-cli scan . --baseline baseline.json --fail-on-new high

# Lockfiles against OSV
oxaudit-cli deps . --format json

# Keep the run so the desktop app can open it
oxaudit-cli scan . --db ~/.oxaudit/findings.sqlite3
oxaudit-cli export --db ~/.oxaudit/findings.sqlite3 --run <id> --format cyclonedx
```

Progress goes to stderr and the report to stdout, so `oxaudit-cli scan . --format
sarif > out.sarif` needs no extra flags.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran to completion; nothing at or above `--fail-on` |
| `1` | Ran to completion; findings at or above `--fail-on` |
| `2` | The command was not usable — bad path, bad flag, bad format |
| `3` | The scan itself failed |

### In GitHub Actions

```yaml
- name: Scan
  run: oxaudit-cli scan . --format sarif --output oxaudit.sarif

- name: Upload to code scanning
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: oxaudit.sarif
```

oxAudit runs this against its own repository on every push
([`self-scan.yml`](.github/workflows/self-scan.yml)).

## Detection quality

Measured, not asserted. `oxaudit-cli benchmark` runs the committed corpus in
[`benchmarks/corpus/`](benchmarks/corpus) and reports precision and recall per
rule.

| | Before | After |
|---|---|---|
| Corpus precision | 46.2% | **100%** |
| Corpus recall | 85.7% | **100%** |
| Corpus size | 26 fixtures | **155 fixtures** |
| Findings on this repository | 142 | **32** |
| …still shown after scope triage | 142 | **5** |

The corpus is 155 fixtures, 87 of them negatives, and none of the negatives were
invented: each is a shape oxAudit was observed firing on when it scanned its own
source or a real dependency tree — type declarations, prose in Markdown,
comments, environment lookups, function parameters, JSON schemas, UI labels,
hardened XML parsers, non-security uses of `Math.random()`, and the detector
code that searches for PEM headers.

The corpus is deliberately vulnerable, so it is excluded from the repository
figure above: a full scan of this checkout returns 106 findings, 74 of which are
the fixtures doing their job.

A corpus you tuned against proves little, so the last two rows are the ones that
matter: this repository is held-out data, and the fixtures that were tuned
against are excluded from it.

All 32 findings that remain are secrets. Twenty-five are deliberately fake
credentials in oxAudit's own tests and two are prose in a planning document.
None of those are suppressed — they are *classified*, and the difference is the
point of the next section. What is left in the default view is five findings:
two UI labels, the corpus builder's own detector strings, and the code that
searches for PEM headers. A scanner that looks for credential shapes will always
contain credential shapes.

### Measured against ground truth nobody here wrote

The corpus above is written by the same people who write the rules. It answers
*"does it still do what we meant?"* and cannot answer *"is it any good?"* — so
100% on it proves less than the number looks like.

The [OWASP Benchmark](https://owasp.org/www-project-benchmark/) is the
counterweight: 2,740 generated Java servlets, each labelled vulnerable or safe
by the project that generated them. It is fetched rather than vendored, because
it is GPL-2.0 (oxAudit is Apache-2.0) and 239MB.

```bash
node tools/fetch-external-benchmark.mjs
cargo run --release --bin oxaudit-cli -- external-benchmark
```

Over the six categories oxAudit has Java rules for — 1,998 of the 2,740 cases:

| | First run | After acting on it |
|---|---|---|
| Cases with a rule to score | 1,998 of 2,740 | **2,740 of 2,740** |
| Precision | 67.0% | 65.3% |
| Recall | 6.1% | **85.4%** |
| False positive rate | 3.0% | 48.5% |
| Youden index (recall − FPR) | 0.030 | 0.369 |

The two columns do not measure the same population. Rules were written for all
five categories that had none, moving 742 cases *into* the scored set, and they
arrived carrying the same false positives as everything else here — so the
Youden index reads lower than an intermediate run that covered fewer
categories. Coverage went from 73% of the benchmark to all of it; that is the
row to read.

The first column is what a corpus written by the rules' own authors had been
reporting as 100%. Five rules were wrong in ways no internal fixture caught,
and the two columns are the before and after of fixing them:

| Category | First run | Now | What was wrong |
|---|---|---|---|
| `xss` | no rule | **237 / 246** | Nothing was written for it |
| `ldapi` | no rule | **27 / 27** | Nothing was written for it |
| `xpathi` | no rule | **15 / 15** | Nothing was written for it |
| `securecookie` | no rule | **36 / 36** | Nothing was written for it |
| `trustbound` | no rule | 33 / 83 | Nothing was written for it |
| `crypto` | 0 / 130 | **130 / 130** | The rule read the *mode*, so `DES/CBC/PKCS5Padding` passed |
| `weakrand` | 0 / 218 | **218 / 218** | The rule needed a secret-ish variable name nearby |
| `cmdi` | 33 / 126 | **126 / 126** | The rule needed the whole `Runtime.getRuntime().exec(` chain in one expression |
| `sqli` | 0 / 272 | 174 / 272 | The rule needed the concatenation *inside* the execute call |
| `hash` | 28 / 129 | 89 / 129 | `SHA1` and `SHA-1` name the same hash; only one was matched |
| `pathtraver` | 0 / 133 | **123 / 133** | The rule needed the concatenation *inside* the constructor, and could not match `new java.io.File` at all |

Every one of those is the same kind of mistake: a rule written against the
shape its author pictured, and a fixture written by the same person to match.
`Runtime r = Runtime.getRuntime(); r.exec(cmd)` is not an exotic way to write
Java, and oxAudit missed 100% of command injections written that way.

`crypto` and `weakrand` reached 100% precision *and* 100% recall — those
discriminators are exact (an algorithm name, a class name), so there was
nothing to trade. The remaining figures are not good, and two separate things
produce them.

**The benchmark is built to require what oxAudit deliberately does not do.**
Its safe and vulnerable cases are frequently identical in the file being
scanned. This pair differs in nothing a reader of either file could see:

```java
// BenchmarkTest00008 — labelled vulnerable
String param = request.getHeader("BenchmarkTest00008");
String sql = "{call " + param + "}";
connection.prepareCall(sql);

// BenchmarkTest00052 — labelled safe
String param = scr.getTheValue("BenchmarkTest00052");   // returns "bar",
String sql = "{call " + param + "}";                    // in another file
connection.prepareCall(sql, TYPE_FORWARD_ONLY, ...);
```

Telling those apart requires a cross-file call graph. oxAudit is
intraprocedural on purpose — the limitation is stated above, and the reason is
that a wrong call graph produces confident nonsense. So a share of this
benchmark is not measuring accuracy oxAudit lacks; it is measuring an analysis
oxAudit declines to attempt. Scores here are not comparable with a tool that
builds one.

**The rest is real, and worth having found.** `sqli` scored 0 true positives
out of 272, because `java-sql-concat` required the concatenation to appear
*inside* the execute call while the benchmark — like most code — builds the
query into a variable first. That is a recall hole in the flagship Java rule
that the internal corpus never revealed, because every fixture written for it
happened to use the inline shape: they were written by someone who already knew
what the rule matched. Widening it to any prepare-or-execute taking a variable,
and letting dataflow resolve what that variable holds, took sqli from 0 to 174
true positives and the overall recall from 6.1% to 23.3%.

That is the second column, and it cost precision. The rule now also reports 150
of the benchmark's safe cases, and those false positives turned out not to be
fixable — an attempt and what it cost is written up under *A trade that was
measured and refused* below. On ordinary code it still discriminates, and there
are fixtures and tests holding that line:

```java
String sql = "SELECT * FROM users WHERE id = ?";   // not reported
String sql = "SELECT * FROM users WHERE id = " + request.getParameter("id");  // reported
```

Taking the trade follows from a principle stated further up rather than from
the score: undetermined keeps the finding, because a false negative in a
security scanner costs more than a false positive.

Every category the Benchmark scores now has a rule, so nothing is counted in
the separate "no rule" column. It still exists, because which categories belong
there is read from the rule table rather than listed anywhere: each rule added
moved its category on its own, and each time the test asserting that category
was uncovered failed exactly as it should have.

`securecookie` reached 100% precision and 100% recall — `setSecure(false)` is
an unambiguous statement about a cookie, and 36 of 36 vulnerable cases make it.

`trustbound` is at 39.8% recall on purpose. The Benchmark counts two things
under CWE-501: an attacker choosing the *session key*, and any request value
stored in the session at all. oxAudit reports the first and not the second,
because the second is what every login form does:

```java
session.setAttribute(request.getParameter("key"), value);   // reported
session.setAttribute("userId", request.getParameter("id"));  // not reported
```

That costs 50 true positives here. It is the same trade already made for path
traversal and SSRF, for the same reason: a rule nobody leaves switched on
catches nothing.

`pathtraver` went from 0 true positives to 123 of 133, and the whole of that
came from finding out that the rule could not fire at all. It matched
`new File(` and a `+` in the same parentheses; a servlet writes the
concatenation a statement earlier and spells the type `new java.io.File`, so
the pattern was unfirable on every one of the 133 vulnerable cases. Rewriting
it to match the sink and let the dataflow analysis decide exposed four things
the analysis could not follow — a loop variable bound by `for (Cookie c :
request.getCookies())`, a value read back out of an array or a cast, a method
called on tainted data, and a value handed through any unmodelled call at all.
Each is now followed, and the last one only in the direction that adds taint:
a tainted operand makes the call tainted, while a constant one still leaves it
`Unknown`. Folding the operands and returning the fold is the textbook version
and it stays refused, for the reason under *A trade that was measured and
refused*.

The cost is 114 false positives out of 135 safe cases, and they are the same
dead-branch puzzles that defeat `cmdi` below — a `switch` on `"ABC".charAt(1)`,
a `list.remove(0)` before a `get(1)`. Not one of the 135 uses a real defense;
the rule's own remediation, canonicalise and check containment, is recognised
and suppresses the finding when it appears. What keeps the rule usable on
ordinary code is unchanged: CWE-22 still requires an inbound origin, so a path
that merely arrives as a parameter is not reported.

One limit is worth naming as a limit rather than as work outstanding: the 40
`hash` cases still missed read their algorithm out of a properties file, so the
weak value is never in the source at all.

And `cmdi` now scores a Youden index of **0.000** — it finds all 126
vulnerable cases and flags all 125 safe ones. That is worth being plain about
rather than burying, because it looks like the rule discriminates nothing. On
ordinary code it does: a literal command is suppressed and a request-derived
one is reported, and there are fixtures for both. What defeats it here is how
the Benchmark builds a safe case:

```java
int num = 86;
if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;                    // dead: 294 − 86 is always > 200
String[] args = {a1, a2, "echo " + bar};
```

Separating that from the vulnerable version needs constant folding and
dead-branch elimination. oxAudit's documented behaviour is the exact opposite
— *a variable reassigned in a branch counts as tainted if any reaching
definition is tainted* — chosen deliberately to over-approximate toward
reporting. So these are the stated design producing the result it was designed
to produce, and the fix is not a better `cmdi` rule.

Taking the recall was still right. Missing every command injection written in
two statements is a hole no amount of benchmark score justifies keeping.

#### A trade that was measured and refused

The 150 false SQL reports break down as 105 values passed through a helper
resolved by reflection, 33 carried through a `HashMap` or `StringBuilder` and
back out, and the rest dead branches guarded by arithmetic that is always true.

The first group has an obvious fix, and it is the standard one: treat an
unmodelled callee as a function of its arguments, so `doSomething("literal")`
is constant and `doSomething(param)` is not. Implemented and measured, that
removed **28 false positives** — and introduced **11 false negatives**:

```java
String param = scr.getTheParameter("BenchmarkTest00043");   // request data
String sql = "INSERT INTO users ... '" + param + "'";       // no longer reported
```

An accessor taking a constant key and returning request data is not a corner
case; `getProperty`, `config.get`, and every framework's parameter helper have
that shape. The trade was 28 reports a reviewer dismisses in a second against
11 hidden SQL injections, so it was reverted. A test pins the shape, and names
the measurement, so the same trade cannot be made again by accident.

Two smaller findings from the same investigation *were* sound, and both fix
real code even though the Benchmark cannot show it — its SQL values are never
constant, so an unresolved argument beside them changes nothing there:

```java
statement.execute(sql, Statement.RETURN_GENERATED_KEYS);  // was reported
runtime.exec(new String[] {"ls", "-la"});                 // was reported
```

One unresolved argument makes a whole call unresolved, so a flags constant or
a literal array sitting *next to* the argument a rule cares about was deciding
the outcome. A SCREAMING_SNAKE_CASE member now reads as the compile-time
constant it is, and a collection of literals as the constant it is. The second
needs no convention; the first is drawn tightly enough that `config.userInput`
cannot qualify, and there is a test for that.

Whether a weak generator matters is a question the tool refuses to answer on
its own. `java-insecure-random` asks whether a *secret* came from one and is
high severity when it can tell; `java-weak-prng` says only that the generator
is not cryptographic, at low severity, and asks a person to decide. The precise
rule supersedes the broad one at the same site, so a reviewer is never asked
the vague question and the sharp one about the same line.

### Scope: which files, and where inside them

Scope ranks and annotates rather than deleting, because "usually noise" is not
"always noise". A hardcoded credential in a fixture is nearly always benign; a
misconfigured `nginx.conf` under `test/` is not, so infrastructure outranks
every exclusion.

Path answers *which file*, and it is right about files. It is silent about
*position*, and in Rust that silence was most of the noise: `#[cfg(test)]`
modules sit at the bottom of the production file they exercise, so their fixture
credentials were reported at full production priority — 20 of 32 findings here,
the largest single category of benign results and indistinguishable from real
ones. A further five sit in `*_tests.rs` files, where the `#[cfg(test)]` marker
is in the *parent* module and the file name is the only local evidence.

Reclassifying hides findings from the default view, so every position signal is
one a compiler or test framework enforces, never a naming habit:

| Language | Signal |
|---|---|
| Rust | `#[cfg(test)]`, `#[test]` — not compiled into a release binary at all |
| Java | JUnit's `@Test` family, including lifecycle annotations that build fixtures |
| Python | `def test_*`, `class Test*` — what pytest and unittest collect on |
| Go | `func TestXxx(t *testing.T)`, keyed on the `testing` parameter, not the name |

`#[cfg(not(test))]` is the opposite claim and is explicitly not matched: it marks
code that exists *only* in release builds, which is the last place to hide a
finding.

JavaScript and TypeScript are deliberately absent. `describe`, `it`, and `test`
are ordinary identifiers an application file may legitimately define, and the
path rules already cover `.test.ts`, `.spec.ts`, and `__tests__/`. The marginal
recall was not worth a rule that could hide a real finding in shipped code.

Two defects the corpus found on its first run:

- `generic-password` matched `\bpassword\b`, and an underscore is a word
  character, so `DB_PASSWORD` and `DATABASE_PASSWORD` never matched. The rule
  responsible for 111 of the 142 findings here also missed the commonest real
  credential shape there is.
- Its separator class `[^A-Za-z0-9]{0,10}` included newlines, so the word
  "secret" on one line paired with an unrelated token three lines below.

### Throughput

`cargo bench --bench scanning` measures the per-file work. Figures below are the
median of a run on an Apple M-series laptop, so treat them as ratios rather than
absolutes:

| Stage | Throughput |
|---|---|
| Source pattern rules | 400–840 MiB/s |
| Secret rules (33 rules over every file) | 210–290 MiB/s |
| Syntax analysis (tree-sitter parse + span collection) | 15–21 MiB/s |

Throughput is flat across three orders of magnitude of input size, which is the
property that actually matters: a rule change that made matching quadratic would
show up here as throughput falling as files grow.

Syntax analysis is roughly 40× more expensive than rule matching and dominates
scan time — it is the entire cost of the precision improvement above. End to
end, this repository (329 files, 5.1 MB) scans in about 2.2 seconds.

### Dataflow

A pattern rule can say "this is `eval(`". It cannot say whether the argument is
a string literal or something a request body controls — and that is the whole
difference between a finding and a nuisance.

For the supported languages, oxAudit now traces the value reaching a sink within
its enclosing function:

```js
eval("2 + 2")               // constant — not reported
const E = "1 + 1"; eval(E)  // resolves to a literal — not reported
eval(userInput)             // parameter — reported
eval(req.body.expr)         // request data — reported
```

A call chain is one expression: if any link takes a value an attacker chooses,
the whole chain does.

```rust
Command::new("sh").arg("-lc").arg("ls").status()   // fixed — not reported
Command::new("sh").arg("-lc").arg(user).status()   // reported
```

A transform that neutralizes the sink's weakness clears it:

```js
eval(parseInt(userInput, 10))   // coerced to a number — not reported
eval(escapeHtml(userInput))     // escapes markup, not code — still reported
```

Sanitizers are matched to the CWE they actually neutralize, never applied
generically. `escapeHtml` clears an XSS sink and nothing else; `shlex.quote`
clears command injection and nothing else. A transform that is merely *named*
like a sanitizer counts for nothing — guessing there produces a false negative,
which is the expensive direction.

### When the weakness is the call, not its input

Two classes added in this round are not about a value flowing into a sink at
all, which is what makes them worth stating separately.

**XXE (CWE-611)** is a property of how a parser was *configured*.
`DocumentBuilderFactory.newInstance()` takes no arguments; there is no input to
trace. What decides it is whether the hardening appears anywhere in the file:

```java
var factory = DocumentBuilderFactory.newInstance();                  // reported
factory.setFeature(DISALLOW_DOCTYPE_DECL, true);                     // not reported
```

**Weak randomness (CWE-338)** depends on what the value is *for*, not where it
came from. `Math.random()` is correct for animation jitter and wrong for a
session token, and the same call site is both.

Rule guards are matched against code **and string literals, but never
comments**. The distinction is load-bearing in both directions: a
`// TODO: switch to defusedxml` is a plan rather than a mitigation, while
`setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` puts
the only evidence of the real fix inside a quoted feature URI.

Both directions were caught by fixtures rather than by reasoning — first a
fixture whose own explanatory comment suppressed the finding it existed to
prove, then a hardened-parser fixture that passed only because it happened to
call `setExpandEntityReferences(false)` as well, masking a guard that could
never fire on the commonest spelling of the fix.

### When the call is the defect, restated

The XXE and weak-randomness work above established that some weaknesses are
about the call rather than its input. Adding three languages showed that the
same idea has a second half: for those classes, argument taint must not be
allowed to *clear* a finding either.

```js
crypto.createHash("md5")                      // reported
Math.random().toString(36).slice(2)           // reported
```

Both were being suppressed. `createHash("md5")` takes one argument and it is
the constant naming the broken hash — read as "nobody can choose this value,
so nothing can go wrong". `Math.random()` was cleared by the constant `2` in a
downstream `.slice(2)`, because the chain it sits in is what supplies the
arguments.

Neither is subtle once stated, and both hid for the same reason: the first only
misreported when the call stood alone, since a chained `.update(data)` made the
chain tainted and reported it anyway. Weakness classes CWE-338, CWE-611,
CWE-327, and CWE-295 are now exempt from argument-based clearing.

### What the analysis tells a reviewer

The review model treats a finding as a *candidate* until something tries to
disprove it, through five falsification gates. The dataflow analysis is an
automated attempt at exactly that, so it answers the gates in the same
vocabulary a person uses, and the review form starts from its answers:

| What it found | Gate | Verdict |
|---|---|---|
| The value traces to a parameter or external input | Attacker control | survives |
| Sanitization is present but covers a different weakness | Effective sanitization | survives |

The second row is the one worth having. `eval(escapeHtml(userInput))` reports
with *"passes through `escapeHtml()`, which neutralizes CWE-79 and not CWE-95"* —
someone wrote that call believing it made the line safe, and saying so is more
useful than either hiding the finding or reporting it bare.

**No suggestion ever eliminates a finding.** An eliminating verdict is a
dismissal, and the review model requires a person to make one — the same line
the assistant is held to. A recorded human answer is never overwritten by a
machine one.

### Known limitation: caller-supplied values

For two weakness classes, a caller-supplied value is the ordinary case rather
than the defect. An HTTP helper takes a URL; a path helper takes a name.

```js
async function get(url) { return fetch(url); }        // NOT reported
app.get("/p", (req) => fetch(req.query.url));         // reported
```

Path traversal (CWE-22) and SSRF (CWE-918) are therefore reported only when the
value traces to an inbound source — a request, argv, an environment read —
rather than to any parameter. Whether a parameter is reachable from a request
handler needs a call graph oxAudit does not build.

This is a deliberate trade of recall for usability, and it is a large one:
reporting these on any parameter fired 148 times across a single dependency
tree, half of every finding. A rule nobody leaves switched on catches nothing.
Every other weakness class still reports on any non-constant value.

Three limits, stated because they bound what the result means:

- **Twelve languages.** JavaScript/TypeScript, Python, Java, Rust, Go, PHP,
  Ruby, C, C++, C#, Kotlin, and Swift. A language without a grammar is never
  suppressed on a guess — it is scanned on text alone, and every match stands.
  Grammars are selected at build time, so `oxaudit-cli languages` tells you
  which ones are in the binary you are holding.
- **Intraprocedural.** Analysis stops at the enclosing function. Following a
  value across call boundaries needs a call graph, and a wrong one produces
  confident nonsense.
- **Undetermined keeps the finding.** Only a value *positively shown* to be
  constant is suppressed. Every case the analysis cannot decide is still
  reported — a false negative in a security scanner costs more than a false
  positive.
- **Not flow-sensitive.** A variable reassigned in a branch counts as tainted if
  any reaching definition is tainted, which over-approximates toward reporting.

Adding the constant-argument cases to the corpus dropped precision from 100% to
71.4% without changing a single rule. Dataflow returns it to 100% with recall
unchanged.

### Confidence tiers

Every finding records how far oxAudit could qualify it:

- **`syntax`** — a grammar parsed the file and the match sits in code, not in a
  comment or a string literal. Available for JavaScript/TypeScript, Python,
  Java, Rust, and Go.
- **`text`** — the rule matched raw file text; no grammar was available.

A language without a grammar is never suppressed on a guess. A false negative in
a security scanner is worse than a false positive, so the absence of a parser
means every match stands and says so.

## Suppressing a finding

A finding that has been reviewed and dismissed should not be raised again on
every push. `.oxaudit/policy.json` records that decision **in the repository**,
so it arrives through a pull request, is reviewed like any other change, and is
attributed to the project rather than to whoever last ran a scan.

```json
{
  "version": 1,
  "entries": [
    {
      "kind": "suppression",
      "ruleId": "generic-password",
      "pathPattern": "tests/**",
      "state": "suppressed",
      "reason": "Synthetic credential fixtures; see tests/README.md.",
      "expiresAt": "2027-01-01T00:00:00Z"
    },
    {
      "kind": "finding",
      "fingerprintVersion": 1,
      "fingerprint": "…",
      "category": "vulnerability",
      "state": "falsePositive",
      "reason": "The affected branch is excluded from production builds.",
      "gates": [
        {
          "gate": "reachable",
          "verdict": "eliminates",
          "evidence": "The production feature manifest excludes this branch."
        }
      ],
      "decidingGate": "reachable"
    }
  ]
}
```

A `suppression` entry dismisses a rule across a path pattern. A `finding` entry
dismisses one specific finding by fingerprint, and for a vulnerability it must
name the gate that eliminates it and show the evidence — asserting "false
positive" is not the same as arguing it.

Four properties this has, and why:

- **A reason is required.** A dismissal with no justification looks reviewed
  without being reviewed.
- **`expiresAt` is honoured.** An expired decision returns the finding to the
  queue, so a temporary exception cannot quietly become permanent.
- **A dismissed finding still appears in reports**, marked with its state and
  `"origin": "projectPolicy"`. Suppression changes whether something gates the
  build, not whether it happened — the decision has to stay auditable.
- **A malformed policy stops the scan.** Ignoring an unparseable file would
  silently un-suppress everything the team agreed to, and the run would not mean
  what it appears to mean. Pass `--ignore-invalid-policy` to scan anyway.

## Architecture

```
src/                  React + TypeScript + Tailwind v4 frontend
  pages/              one file per screen
  features/           domain-focused GUI workflows and pure view models
  components/         shared workbench UI (findings, badges, progress…)
  lib/                typed invoke() wrappers, zustand stores, formatting
src-tauri/            Rust backend (Tauri v2)
  crates/             compiler-enforced domain, application, scanner, and benchmark cores
    oxaudit-domain/       stable records, identities, evidence and state invariants
    oxaudit-application/  ports, run coordinator, manifests and sequenced events
    oxaudit-scanners/     bounded declarative rules and optional object analysis
    oxaudit-benchmark/    resumable ground-truth contracts and metrics
    oxaudit-compliance/   declarative readiness profiles and evidence evaluation
  src/adapters/       SQLite, scanner mapping, providers and standards reporting
  src/presentation/   canonical Tauri event projection
  src/models.rs       shared serde models (camelCase ⇄ TypeScript types)
  src/scanners/       secrets.rs (rules + entropy engine), patterns.rs (source rules)
  src/deps/           lockfiles.rs (parsers), osv.rs (OSV client + CVSS math)
  src/binscan/        native binary scanner plus optional external-tool adapters
  src/findings/       durable runs, evidence, review, policy, diff and SQLite storage
  src/triage/         scope, falsification gates and silent-drop manifest
  src/agent/          bounded read-only tool loop and permission guardrails
  src/cve.rs          NVD client with rate limiting + caching, OSV enrichment
  src/ai/             OpenAI-compatible chat client + prompt builders
  src/commands.rs     Tauri presentation commands
```

All *oxAudit* scanning is local. oxAudit itself contacts only NVD, OSV, CISA KEV,
FIRST.org EPSS, and the AI endpoint you configure — all free and key-less except
the optional NVD API key.

The default **native binary scanner is local and needs no external tool or advisory
database bootstrap**. If you explicitly select cve-bin-tool, that separate program
makes its own network calls—to its mirror at `cveb.in` and the advisory feeds it
aggregates—unless you tick **Offline**. The optional external adapter is inert until
you install cve-bin-tool; the native scanner is not.

The application now has a compiler-enforced domain/application core and one durable
run/evidence pipeline for source, dependency, binary, and inventory-import workflows.
The full
[upstream architecture study](docs/architecture/2026-08-21-upstream-architecture-study.md),
[GUI-first target architecture](docs/architecture/2026-08-21-gui-first-target-architecture.md),
the [implementation plan](docs/superpowers/plans/2026-08-21-oxaudit-architecture-strengthening.md),
and the [implementation status](docs/architecture/2026-08-21-implementation-status.md)
record what is being adopted from cve-bin-tool, VulHunt, and VulnHunter, what is
deliberately rejected, and how licence-safe provenance is preserved.

The [compliance and reporting architecture](docs/compliance-and-reporting.md)
documents profile licensing boundaries, status semantics, bounded evidence collection,
append-only review history, and the shared professional report model.

## Development

Prerequisites: [Node.js ≥ 20](https://nodejs.org), [Rust ≥ 1.77](https://rustup.rs),
and the platform Tauri prerequisites (Xcode CLT on macOS, WebView2 on Windows,
webkit2gtk on Linux — see [Tauri docs](https://v2.tauri.app/start/prerequisites/)).

```bash
npm install
npm run tauri dev        # run the app with hot reload
npm run build            # type-check + build the frontend
cd src-tauri && cargo test --workspace --all-features  # run every Rust package
npm run tauri build      # produce a distributable bundle
```

### Choosing grammars at build time

Each language grammar is an optional dependency behind a Cargo feature. The
default is every grammar, which is what a release ships; a size-constrained
build can take fewer.

```bash
cargo build --release --bin oxaudit-cli                        # all twelve
cargo build --release --bin oxaudit-cli \
  --no-default-features --features grammars-core               # the original five
cargo build --release --bin oxaudit-cli \
  --no-default-features --features grammar-python,grammar-go   # pick your own
```

Leaving a grammar out does not make oxAudit quieter about that language — it
makes it **louder**. With no grammar, nothing can prove a match sits in a
comment or a string, so every match stands and the analysis answers Unknown
rather than suppressing on a guess. The trade is precision for size, never
recall — and the corpus measures that rather than asserting it:

| Build | CLI binary | Corpus precision | Corpus recall |
|---|---|---|---|
| `default` — all twelve | 29.2 MB | 100% | 100% |
| `grammars-core` — the original five | 10.2 MB | 82.6% | **100%** |
| `--no-default-features` | 7.6 MB | text tier throughout | **100%** |

Recall does not move. Kotlin, Swift, and C# account for most of the difference;
the original five grammars cost 2.6 MB between them.

Because two binaries of the same version can therefore disagree about how
precisely they read a language, `oxaudit-cli languages` prints what is
compiled in, and `oxaudit-cli benchmark` names any grammar it is missing
rather than letting the score be read as a rule regression.

`cargo test` expects the default feature set — most of the suite asserts what a
grammar does with a language. CI checks that the reduced configurations still
compile.

## Configuring the AI

1. Open **Settings → AI engine**.
2. Pick any OpenAI-compatible endpoint: set **Base URL** (e.g. `https://api.openai.com/v1`,
   `http://localhost:11434/v1` for Ollama, `http://localhost:1234/v1` for LM Studio),
   the **model** name, and an API key if required.
3. Enable the toggle and press **Test connection**.
4. Findings and CVEs now get an **Ask AI / Generate research briefing** button.

> The NVD API key (optional) raises the NVD rate limit from 5 to 50 requests per
> 30 seconds — get one free at https://nvd.nist.gov/developers/request-an-api-key.

## Binary scanning (cve-bin-tool)

oxAudit does **not** bundle [cve-bin-tool](https://github.com/ossf/cve-bin-tool). It is
GPL-3.0-or-later; bundling it would make oxAudit a distributor of GPL software, whereas
invoking a copy you installed is arms-length. Install it yourself:

```bash
pipx install cve-bin-tool     # recommended
# or: pip install cve-bin-tool
```

oxAudit finds it on PATH, falling back to `python3 -m cve_bin_tool`. If you keep it in a
specific environment, set the path in **Settings → Binary Scanning**; an explicit path
suppresses the fallbacks so you always scan with the copy you meant.

The first run downloads a CVE database and can take several minutes — the page shows
cve-bin-tool's own progress while it works, and the scan is cancellable.

> **Upstream bugs, and the workaround (checked 2026-08-20).** cve-bin-tool 3.4 cannot
> populate its CVE database out of the box: its NVD bootstrap aborts on a `403` from
> `nvd.nist.gov/rest/public/dashboard/statistics`, and a failed run then records an
> update timestamp that routes every later run into an empty incremental fetch. Both
> are small bugs — the container image in `docker/cve-bin-tool/` carries the fix, after
> which the fetch runs normally. **Set an NVD API key first**: the unauthenticated rate
> limit makes the initial download take hours. Full investigation, and a measured
> comparison against grype, in
> [`docs/binary-scanning-runtime.md`](docs/binary-scanning-runtime.md).

An experimental container runtime lives in `docker/cve-bin-tool/Dockerfile`. It supplies
the external programs cve-bin-tool needs but does not declare (`gsutil` for its mirror,
plus `cabextract`, `rpm2cpio`, `p7zip`, `zstd`). Build it yourself — the file is a
recipe, so oxAudit never distributes GPL software:

```bash
docker build -t oxaudit/cve-bin-tool:3.4 docker/cve-bin-tool
```

Lockfile scanning is deliberately **not** routed through it: **Dependencies** already
parses ten lockfile formats natively and queries OSV directly.

## Security notes

- API keys are stored by the operating system credential manager, never in ordinary
  settings or the scanned project. Public settings are committed atomically and use
  owner-only Unix permissions. Upgrades checkpoint a safe, idempotent migration from
  `com.vulncompanion.app` to `com.oxaudit.desktop`, retain a sanitized legacy backup,
  and fail closed on symlinks or conflicting destination files.
- The secret scanner is heuristic: always confirm a finding is a real credential
  before rotating anything, and beware false positives from test fixtures.
- Binary scanning shells out to cve-bin-tool with arguments passed directly — never
  through a shell — and the target is canonicalized to an absolute path first. Note that
  cve-bin-tool extracts archives (ZIP/RPM/DEB/CAB/APK) to inspect them, so pointing it at
  untrusted firmware runs third-party extraction code on attacker-supplied input.
- Live verification of secrets (calling AWS/GitHub to check tokens) is intentionally
  **not** performed; treat findings as candidates.

## Measured next steps

- Expand deterministic source, secret, dependency, binary, and cross-platform
  corpora before making representative recall claims.
- Add an explicit trust/mapping workflow before SARIF or VEX imports can affect
  local findings or review state.
- Migrate built-in source/secret snapshots into the declarative pack format only
  as each rule gains positive/negative fixture provenance.
- Consider CFG/data-flow work only if the bounded object tier demonstrates
  benchmark value; it is intentionally not a decompiler today.

See the [implementation status](docs/architecture/2026-08-21-implementation-status.md)
for shipped evidence and deliberate limits.

## Licence

oxAudit is licensed under the **[Apache License 2.0](LICENSE)**. See
[`NOTICE`](NOTICE) for attribution, which the licence requires derivative works
to carry forward.

Two things the notice records, because they are easy to get wrong:

- **The external scanners are not distributed with oxAudit.** Binary scanning
  executes a copy of [cve-bin-tool](https://github.com/ossf/cve-bin-tool)
  (GPL-3.0-or-later) or [grype](https://github.com/anchore/grype) (Apache-2.0)
  that *you* installed. Invoking a program at arm's length carries no licensing
  obligation; bundling one would. `docker/cve-bin-tool/Dockerfile` is a recipe
  built on your machine, not an image we publish.
- **The detection signatures are original work.** They were derived from
  binaries whose versions were known independently — see
  [`docs/binary-signatures.md`](docs/binary-signatures.md) — and deliberately
  not transcribed from cve-bin-tool's GPL checkers.

Methodology studied and reimplemented from
[VulnHunter](https://github.com/capitalone/VulnHunter),
[VulHunt](https://github.com/vulhunt-re/vulhunt) and
[y-agent](https://github.com/gorgiaxx/y-agent) is credited in `NOTICE`. No source
was copied from any of them.
