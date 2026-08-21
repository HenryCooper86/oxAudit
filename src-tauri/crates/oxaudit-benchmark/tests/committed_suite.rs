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
        2,
        "keep the corpus-size claim explicit"
    );
    for target in suite.targets {
        let bytes = fs::read(root.join(&target.input_path)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            target.input_sha256,
            "fixture {} changed without a suite version/hash update",
            target.id
        );
    }
}
