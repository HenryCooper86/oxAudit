# Compliance readiness and professional reporting

oxAudit's Compliance Center is an evidence-readiness workflow. It does not certify a product, reproduce copyrighted standards, provide legal advice, or determine conformity. Automated checks only answer a narrow question: "Does this project contain evidence with the expected shape, and are relevant completed oxAudit runs available?" Qualified reviewers own applicability, adequacy, residual risk, and approval decisions.

## Architecture

The implementation has five deliberately separate boundaries:

1. `oxaudit-compliance` is a presentation- and storage-independent Rust crate. It validates declarative profiles, evaluates bounded evidence snapshots, and calculates reproducible coverage summaries.
2. Built-in profiles are versioned data in `src-tauri/crates/oxaudit-compliance/profiles/builtin.json`. The public schema is `compliance/schema/compliance-profile.schema.json`.
3. The desktop adapter collects filenames, metadata, eligible document hashes, and matching completed canonical runs. It never follows symlinks, skips dependency/build/vendor trees, caps traversal depth at 8, caps files at 10,000, hashes individual files only up to 2 MiB, and enforces a 32 MiB total hashing budget.
4. SQLite stores immutable assessments, append-only reviewer decisions, and report receipts. Report receipts include format, destination, timestamp, metadata, and the final SHA-256 digest.
5. Report Studio compiles JSON, CSV, Markdown, self-contained HTML, and paginated PDF from the same report document. User-controlled HTML is escaped, CSV is quoted, writes are atomic, and all formats carry the same claim boundary.

## From the command line

`oxaudit-cli compliance` runs the same workflow without the desktop app, which
suits CI jobs and scheduled evidence collection. It calls the same engine
functions as the Compliance Center and Report Studio, so assessments, reviews
and report receipts land in the same database tables, and the PDF comes from
the same generator.

```bash
# Store a completed run so it counts as evidence, then assess
oxaudit-cli deps . --db ~/.oxaudit/findings.sqlite3
oxaudit-cli compliance assess . --db ~/.oxaudit/findings.sqlite3 \
  --profile soc-2-tsc --profile owasp-top-10-2021 \
  --organization "Example Corp" --assessor "Dana Reviewer"

# Record a qualified decision, then compile the latest SOC 2 assessment
oxaudit-cli compliance review --db ~/.oxaudit/findings.sqlite3 --assessment <id> \
  --control soc-cc1 --status not-applicable --note "Covered by the parent programme" --by "Dana Reviewer"
oxaudit-cli compliance report --db ~/.oxaudit/findings.sqlite3 --latest --profile soc-2-tsc \
  --format pdf --output soc2-readiness.pdf
```

`compliance profiles` lists the profile ids, and `compliance list` and
`compliance show` read stored assessments. Every text result ends with the
claim boundary. See the [CLI reference](cli.md#compliance) for every option
and exit code.

## Built-in starter profiles

- ISO 26262:2018 functional safety
- ISO/SAE 21434:2021 automotive cybersecurity
- UNECE Regulation No. 155 (CSMS and vehicle cybersecurity)
- UNECE Regulation No. 156 (SUMS and software updates)
- EU General Data Protection Regulation
- California CCPA/CPRA regulations effective in 2026
- NIST Privacy Framework 1.0
- ISO/IEC 27001:2022 information security management
- OWASP Top 10:2021 web application security risks (original paraphrased categories, official publication linked)
- SOC 2 Trust Services Criteria common criteria (original paraphrased controls; AICPA-licensed guidance required for the authoritative criteria)

ISO and ISO/SAE profiles contain original high-level readiness objectives and official catalogue links only. Teams must obtain the applicable official standards and licensed guidance for authoritative requirements.

## Status semantics

- `supported`: all configured evidence groups matched. This is not a pass or conformity claim.
- `partial`: some configured evidence groups matched.
- `gap`: no configured evidence group matched.
- `manualReview`: the decision cannot be automated.
- `notApplicable`: a reviewer recorded that the control does not apply, with an audit note.

Automated status remains immutable. Human reviews are separate append-only events, so the application always preserves what the tool observed and what a person later decided.

## Adding a profile

1. Add a profile that conforms to `compliance-profile.schema.json`.
2. Use original control objectives; do not copy restricted normative text.
3. Link an official HTTPS source and include the copyright and readiness disclaimers.
4. Keep each evidence rule bounded. File patterns support case-insensitive `*` wildcards and may not contain parent traversal.
5. Add engine fixtures that prove expected matches, gaps, manual controls, and profile validation.
6. Have a subject-matter expert and counsel review scope, terminology, licensing, and the claim boundary before release.

## Report contents

Professional reports contain document identity and classification, executive summary, assessment scope and collection method, evidence-readiness metrics, a control matrix, detailed objectives and evidence, optional latest review decisions, official source links, and a prominent non-certification disclaimer. PDF output includes repeating headers, footers, assessment identity, and page numbering.

CSV includes the evidence-readiness/non-certification qualification in a
`claim_boundary` column on every control row, preserving ordinary CSV parsing.
Excluded reviewer decisions, names and notes are not emitted. JSON also honors
the source-reference disclosure option.

PDFs embed a licensed font rather than relying on installed system fonts. Latin
text with precomposed accents and supported Chinese characters remain searchable
and extractable; wrapping uses measured glyph widths. Characters the font or
renderer cannot faithfully represent cause an explicit error before a report is
saved. Use HTML or JSON for those inputs. See the
[font provenance and coverage](../src-tauri/assets/fonts/README.md) for the exact
limits; PDF support is not a claim of universal Unicode shaping.

## Standards exports and imported inventories

SARIF 2.1.0, CycloneDX 1.6, SPDX 2.3 and OpenVEX 0.2 reports are validated against
bundled, versioned official schemas, including nested records, before delivery.
Validation runs offline and refuses unbundled schema references. Source hashes,
licenses and provenance are retained beside the schemas. A schema-valid document
does not establish the truth or completeness of its findings, nor compatibility
with every receiving product. OpenVEX requires at least one advisory statement;
an inventory without advisory statements should be exported as an SBOM instead.

Inventory import maps unambiguous source component references to the new run's
canonical IDs and retains dependency edges. Detailed original license metadata
is retained alongside the canonical license summary for same-format re-export.
Duplicate or dangling references and relationship types without a canonical
equivalent are disclosed; their source records are retained as evidence instead
of being silently turned into different dependency assertions. Cross-format
exports disclose metadata they cannot represent faithfully.
