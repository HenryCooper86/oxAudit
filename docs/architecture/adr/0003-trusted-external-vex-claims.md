# ADR 0003: Trusted external VEX claims inform; humans decide

Date: 2026-09-25
Status: Accepted

## Context

oxAudit imports SARIF, CycloneDX VEX, and OpenVEX documents and retains their
assertions as immutable `external-unverified` claims. A claim can never change
a local finding or review — the import surface says so, by design, because a
third-party status must not silently close locally produced evidence.

That boundary is correct and stays. But it leaves a real workflow unserved: a
team publishes a VEX document stating that a given advisory does not affect a
given product (with a justification), and consumers of that document have no
way to let it inform their triage at all — every imported claim is inert
regardless of how much the source is trusted.

## Decision

1. **Trust is granted explicitly, per document, content-addressed.**
   `oxaudit-cli vex trust --sha <content-sha256>` records a trust grant for
   one imported claim set, captured by the SHA-256 of the imported document —
   the same hash the importer pinned in its preview. A grant records who made
   it, when, and an optional note. Grants are revocable. Nothing is trusted by
   default, and trust never attaches to a producer name across documents.

2. **Trusted claims may suggest. They may not decide.**
   A trusted `not_affected` claim whose subject resolves to a locally recorded
   vulnerability is reported as a *suggestion*: the advisory, the package
   identity, the justification text, and the trusted document's hash and grant.
   Suggestions are report output (`vex suggest`), not state changes. Review
   decisions keep their existing path — a person, the falsification gates, the
   commit-reviewed policy file.

3. **Mapping is exact-identity only.**
   A claim matches a local vulnerability only when the claim's vulnerability
   identifier equals the advisory id or one of its aliases, *and* one of the
   claim's subject identifiers equals the component's exact package identity
   (purl `pkg/<ecosystem>/<name>@<version>` or
   `<ecosystem>:<name>@<version>`, case-insensitive). No fuzzy matching, no
   name-only matching: a claim about `left-pad@1.2.0` does not apply to
   `left-pad@1.3.0`, and a claim naming only "left-pad" applies to nothing.

4. **Unmatched and untrusted stay visible.**
   `vex suggest` reports claims it did not consult (untrusted documents) and
   claims it could not map, with reasons. Silence would read as "no
   suggestions", which is a different statement than "none matched".

## Consequences

- The importer's trust boundary warning remains true: imported claims cannot
  change local findings or reviews. What changes is that a deliberately
  trusted document can now surface as annotated triage input.
- Trust grants live in the findings database and are auditable (who, when,
  note, document hash). Revoking a grant removes its suggestions from future
  `vex suggest` runs without touching anything else.
- A future slice may let the desktop offer one-click adoption of a suggestion
  into the normal review-recording flow — passing through the same gates as a
  human-entered decision, attributed to the adopting user with the claim's
  provenance. That will be its own decision, not a side effect of this one.
