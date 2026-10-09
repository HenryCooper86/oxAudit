# Local image content identity

Local image receipts retain `localEvidence` alongside inventory and advisory
results. This identifies content observed before the native scan, rather than
identifying a mutable directory or filename as immutable content. The receipt
explicitly warns that a path can change after inspection; it does not prove the
later scanner read identical bytes. Registry receipts separately retain their
resolved manifest digest and verified downloaded layer identities.

For an ordinary saved image or firmware file, inspection streams SHA-256 with a
64 KiB scratch buffer. It hashes at most 128 MiB plus one un-hashed EOF probe.
`sha256` is populated only after reaching EOF. A larger or growing input gets
`prefixSha256`, `bytesHashed`, `complete: false`, and an explicit full-digest
unknown note. `sizeBytes` comes from the bytes streamed to EOF when available;
otherwise `sizeSource` identifies open-file metadata as the size observation.
Length and modification-time snapshots report known changes or unknown
stability; they are not a filesystem snapshot guarantee.

OCI layout inspection retains the root `index.json` SHA-256 and records indexed
manifest, nested index, configuration and layer descriptors. Each descriptor
separates the declared digest/size from actual SHA-256/size and a `verified`
flag. A digest or size mismatch retains the failed comparison. A missing,
symlinked, unsupported or oversized blob remains unverified with a reason;
declared layer hashes are never promoted to verified content without hashing
the entire blob. The receipt contains hashes and metadata, not configuration
or layer bodies.

The OCI metadata contract follows the archive parser's layout recognition and
one-level index expansion. Inspection bounds the root index at 64 KiB, each
manifest/index document at 256 KiB, eight root/nested index entries, sixteen
resolved manifests, sixty-four layers per manifest and 128 layers in total.
All successful metadata/configuration/layer hashes share the 128 MiB allowance.
Oversized layer files are measured from file metadata without an extra whole
file read. Metadata reads retain at most their cap plus one probe byte, and a
metadata prefix is never parsed as a complete document. Cancellation is checked
between descriptors and read chunks; it cannot interrupt an already blocked
filesystem read.

The archive parser's existing `read_layout()` verifies entire layer files without
a cancellable byte allowance. Identity inspection therefore uses its layout
recognition and compatible descriptor format while performing its own bounded
reads, avoiding a second unbounded content pass. Non-OCI directories receive an
explicit unknown identity and no tree digest claim.

Focused tests exercise file mutation and capped prefix semantics, valid OCI
manifest/configuration/layer identities, malformed or missing configuration,
digest and size mismatches, metadata
and count limits, oversized layer declarations, symlink refusal and cancellation
between reads. These establish the receipt contract; native inventory coverage
and advisory accuracy remain separate properties.
