# What oxAudit can learn from VulnHunter

> Studied 2026-08-20 against `capitalone/VulnHunter@main` (Apache-2.0, 937 stars,
> actively maintained). Companion to the other adoption studies in this folder.

## 1. What it actually is

Not a scanner binary and not a library. VulnHunter is **three Claude Code skills**
— markdown phase prompts — plus a Python harness:

| Component | What it is |
|---|---|
| `vulnhunt/` | The scanner: `SKILL.md` + 9 phase prompts (Recon → Hunt → Adversarial Verify → Reproduce → Report) |
| `vulnhunter-fix/` | TDD remediation: writes an exploit, a failing test, a fix, then a PR |
| `vulnhunt-fix-verify/` | Independent read-only verifier (no Bash, no network) |
| `vulnhunter-agent/` | Headless CI runtime that clones, scans, and files GitHub issues |
| `harness/` | Batch scanning and a benchmark with ground-truth corpora |

**They are already installed on this machine** at `~/.claude/skills/{vulnhunt,
vulnhunter-fix,vulnhunt-fix-verify}`. So there is nothing to integrate to *use*
them — `/vulnhunt` works today. The question is what oxAudit should borrow.

Because it is prompt architecture rather than code, the licence question that
dominated the cve-bin-tool decision does not arise: Apache-2.0, and we would be
adopting a method, not vendoring a program.

## 2. The idea worth taking: a falsification filter

VulnHunter's thesis is that ordinary SAST reasons *backward from dangerous sinks*
and therefore drowns users in pattern hits. It reasons *forward from entry
points*, then runs every candidate through five gates whose job is to **disprove**
it:

| Gate | Question | Eliminates |
|---|---|---|
| **0** | Is this the application doing what it was designed to do? | Features mistaken for flaws (proxies forwarding, gateways routing) |
| **1** | Is the code reachable? | Dead code. "One tool call — never skip it." |
| **2a** | Is the input genuinely attacker-controlled? | Framework/internal metadata mistaken for user input |
| **2b** | Is there effective sanitization between source and sink? | Already-defended paths — but *only* if **all** call sites sanitize |
| **3** | Does the attacker gain a **new** capability? | Findings where the attacker could already do this |

Two disciplines around the gates matter as much as the gates:

- **Adversarial verification is a mandatory separate phase.** The prompt states
  plainly that "~50% of candidate findings are false positives" and requires the
  model to argue the opposing case for each one.
- **A candidate manifest with a matching row count.** Before verifying, list every
  candidate and count them; the verdict table must have exactly that many rows.
  "A candidate that was never listed in the table was never evaluated — that is a
  verification failure, not an implicit rejection." That is a *silent-drop guard*,
  and it is the kind of property worth encoding as a test rather than a hope.

Gate 2b has a sharp corollary worth stealing verbatim: **a sanitizer whose scope
does not match the sink is a finding, not a mitigation** — `encodeURIComponent()`
in front of SQL, `htmlspecialchars()` in front of a shell command.

## 3. Why this fits oxAudit specifically

oxAudit is, today, exactly the tool VulnHunter is a reaction against. Our source
scanner is **50 regex rules** (`scanners/patterns.rs`) and a `Finding` carries:

```
id, category, rule_id, rule_name, severity, title, description,
file_path, line, column, match_text, context, language, cwe, recommendation
```

There is no entry point, no data flow, no reachability, and no notion of whether
the hit is exploitable. Every finding is a *candidate* that we present as a
result.

But the machinery the gates need is **already built**. The P2 agentic layer gave
us `grep_project`, `read_file` and `glob` — precisely the tools every gate is
written against — inside a bounded loop with a permission pipeline. And every
finding already has an "Ask AI" button. Triage is a new prompt over existing
parts, not a new subsystem.

## 4. Ranked proposals

### 1. Gate-based finding triage · value: high · effort: M
Add a **Triage** action on a finding that runs our existing agent loop with a
gate-structured prompt, and records a verdict with evidence. Extend `Finding`:

```rust
pub struct Triage {
    pub status: TriageStatus,     // confirmed | dead-code | not-attacker-controlled
                                  // | sanitized | no-new-capability | unverified
    pub entry_point: Option<String>,
    pub data_flow: Option<String>,
    pub gate_notes: Vec<GateNote>, // which gate decided it, and why
    pub reviewed_at: String,
}
```

The payoff is the difference between showing 200 regex hits and showing the 12
that survived, each with a traced path. That is the single biggest quality jump
available to the scanner, and it does not require touching the rules.

### 2. Batch triage with the silent-drop guard · value: high · effort: S
Run triage across a whole scan, carrying the candidate-manifest discipline: the
number of verdicts must equal the number of candidates. Encode that as an
assertion, not a convention — it is exactly the class of bug (quietly dropping
findings) that a security tool must not have.

### 3. A benchmark with ground truth · value: high · effort: M
We ship 50 rules and have **never measured their precision or recall**. VulnHunter's
`harness/local_harness/benchmark/` is directly adoptable in shape: a
`ground_truth/<repo>.json` corpus, a judge, and a tally. Without it, "improving
the rules" is guesswork, and any triage layer's own accuracy is unmeasurable too.

### 4. Severity calibration rules · value: medium · effort: S
Their tier discipline factors attacker identity (unauthenticated → higher) and
preconditions (race, chain, specific config → lower). Ours is a static per-rule
constant, which is why a hardcoded password in a test fixture and one in a
production auth path score identically.

### 5. Scope exclusions · value: medium · effort: S
Their production-code-only rule (skip tests, vendored, generated, docs — with a
deliberate exception for security-relevant infra config like nginx `set_real_ip_from`)
is more nuanced than our `ignoredDirs` list, and directly reduces noise.

## 5. What not to take

- **`vulnhunter-agent/`** — a CI runtime that clones repos and files GitHub issues.
  Different product; oxAudit is a desktop workbench.
- **`vulnhunter-fix/`** — writes exploits, fixes and PRs. oxAudit's agent tools are
  **read-only by design**, and that is a stated security property, not an accident.
  Adopting a PR-writing loop would trade it away.
- **Subgraph partitioning and parallel trace agents** — machinery for scanning
  large unfamiliar codebases at scale. We triage a finding at a time.
- **Their skill packaging** — the skills are already installed; duplicating them
  inside oxAudit would just fork someone else's prompts.

## 6. The free move

`/vulnhunt` is installed and works now. oxAudit is a security tool that has never
had a security review, and it has genuinely interesting attack surface: it spawns
subprocesses (cve-bin-tool, grype, docker), parses untrusted lockfiles and
binaries, fetches URLs via a `web_fetch` agent tool, and runs an LLM tool loop
over attacker-influenceable scan output.

Running it on ourselves costs nothing and is the fastest way to judge whether the
methodology is worth building into the product.
