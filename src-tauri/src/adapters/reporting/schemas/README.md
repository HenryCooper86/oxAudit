# Bundled export schemas

These are complete, unmodified upstream JSON Schemas, embedded into the application for offline export validation. `provenance.json` records each immutable upstream URL and SHA-256 checksum. Do not replace these with marker checks or abbreviated local schemas.

- SARIF 2.1.0, OASIS TC, errata01 schema. Repository license/IPR notice: `LICENSE-sarif.md`.
- CycloneDX 1.6, revision 1.6.2, OWASP/CycloneDX contributors, Apache-2.0 (`LICENSE-cyclonedx`). Its SPDX license enumeration and JSON Signature Format 0.82 references are bundled unchanged alongside it.
- SPDX 2.3, SPDX contributors, release v2.3, CC-BY-3.0 (`LICENSE-spdx`). This specification/schema license is distinct from the `CC0-1.0` dataLicense of generated SPDX documents.
- OpenVEX 0.2.0, OpenVEX contributors, CC0-1.0 (`LICENSE-openvex`). The schema was added after the v0.2.0 spec tag, so it is pinned to the commit listed in the provenance file; its `$id` identifies schema version 0.2.0.

The Rust validator enables format checking and uses each schema's declared draft. HTTP/file resolution features are disabled. A closed resolver serves only the two bundled CycloneDX references; unknown references fail. Validators are compiled once and cached. An exported document's `$schema` field never determines which schema to load.

Validation checks the entire JSON tree against the selected official schema, including optional fields when supplied. This is structural validation, not a claim of complete semantic conformance, vulnerability verification, or certification. Canonical dependency edges are checked separately for unresolved component IDs. OpenVEX requires a nonempty statement list; an export with no advisory observations is rejected rather than inventing a statement.

For an update, choose immutable upstream commits, retain the original schema bytes and license notices, update provenance checksums, and run the reporting tests including malformed nested records and remote-reference rejection.
