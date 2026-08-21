use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_DEPENDENCIES: &[&str] = &["tauri", "rusqlite", "reqwest"];
const FORBIDDEN_SOURCE_REFERENCES: &[&str] = &[
    "tauri::",
    "rusqlite::",
    "reqwest::",
    "presentation::",
    "commands::",
];

fn rust_files(root: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, output);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            output.push(path);
        }
    }
}

#[test]
fn core_crates_cannot_import_outward_adapters() {
    let application = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates = [application.join("../oxaudit-domain"), application.clone()];

    for crate_root in crates {
        let manifest_text = fs::read_to_string(crate_root.join("Cargo.toml")).unwrap();
        let manifest: toml::Value = toml::from_str(&manifest_text).unwrap();
        let dependencies = manifest
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .unwrap();
        for forbidden in FORBIDDEN_DEPENDENCIES {
            assert!(
                !dependencies.contains_key(*forbidden),
                "{} must not depend on {forbidden}",
                crate_root.display()
            );
        }

        let mut files = Vec::new();
        rust_files(&crate_root.join("src"), &mut files);
        for file in files {
            let source = fs::read_to_string(&file).unwrap();
            for forbidden in FORBIDDEN_SOURCE_REFERENCES {
                assert!(
                    !source.contains(forbidden),
                    "{} crosses the dependency wall with {forbidden}",
                    file.display()
                );
            }
        }
    }
}
