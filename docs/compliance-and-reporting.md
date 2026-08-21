# Compliance readiness and professional reporting

oxAudit's Compliance Center is an evidence-readiness workflow. It does not certify a product, reproduce copyrighted standards, provide legal advice, or determine conformity. Automated checks only answer a narrow question: "Does this project contain evidence with the expected shape, and are relevant completed oxAudit runs available?" Qualified reviewers own applicability, adequacy, residual risk, and approval decisions.

## Architecture

The implementation has five deliberately separate boundaries:

1. `oxaudit-compliance` is a presentation- and storage-independent Rust crate. It validates declarative profiles, evaluates bounded evidence snapshots, and calculates reproducible coverage summaries.
2. Built-in profiles are versioned data in `src-tauri/crates/oxaudit-compliance/profiles/builtin.json`. The public schema is `compliance/schema/compliance-profile.schema.json`.
3. The desktop adapter collects filenames, metadata, eligible document hashes, and matching completed canonical runs. It never follows symlinks, skips dependency/build/vendor trees, caps traversal depth at 8, caps files at 10,000, hashes individual files only up to 2 MiB, and enforces a 32 MiB total hashing budget.
4. SQLite stores immutable assessments, append-only reviewer decisions, and report receipts. Report receipts include format, destination, timestamp, metadata, and the final SHA-256 digest.
5. Report Studio compiles JSON, CSV, Markdown, self-contained HTML, and paginated PDF from the same report document. User-controlled HTML is escaped, CSV is quoted, writes are atomic, and all formats carry the same claim boundary.

## Built-in starter profiles

- ISO 26262:2018 functional safety
- ISO/SAE 21434:2021 automotive cybersecurity
- UNECE Regulation No. 155 (CSMS and vehicle cybersecurity)
- UNECE Regulation No. 156 (SUMS and software updates)
- EU General Data Protection Regulation
- California CCPA/CPRA regulations effective in 2026
- NIST Privacy Framework 1.0
- ISO/IEC 27001:2022 information security management

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
