use std::fs;
use std::path::PathBuf;

use oxaudit_benchmark::BenchmarkSuite;
use sha2::{Digest, Sha256};

#[test]
fn committed_ground_truth_is_valid_and_content_addressed() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../benchmarks/ground-truth/source-smoke");
    let suite: BenchmarkSuite =
        serde_json::from_slice(&fs::read(root.join("suite.json")).unwrap()).unwrap();
    suite.validate().unwrap();
    assert_eq!(
        suite.targets.len(),
        10,
        "keep the corpus-size claim explicit"
    );
    let mut corpus_digest = Sha256::new();
    for target in &suite.targets {
        let bytes = fs::read(root.join(&target.input_path)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            target.input_sha256,
            "fixture {} changed without a suite version/hash update",
            target.id
        );
        corpus_digest.update(target.id.as_bytes());
        corpus_digest.update([0]);
        corpus_digest.update(target.input_sha256.as_bytes());
        corpus_digest.update(b"\n");
    }
    assert_eq!(
        format!("{:x}", corpus_digest.finalize()),
        suite.provenance.content_sha256,
        "suite provenance must address the ordered target identities"
    );
}
