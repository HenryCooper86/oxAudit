use std::io::Write;
use std::path::Path;

use super::source::{self, MAX_FILES};
use super::store::{is_valid_pack_id, pack_id_for};
use super::*;
use sha2::Digest;

const RULE_ALPHA: &str = r#"rule marker_alpha {
    meta:
        severity = "high"
    strings:
        $a = "OXAUDIT-FIXTURE-ALPHA"
    condition:
        $a
}
"#;

const RULE_BETA: &str = r#"rule marker_beta {
    strings:
        $b = { 4F 58 42 45 54 41 }
    condition:
        $b
}
"#;

const NOW: &str = "2026-11-18T00:00:00Z";

fn meta(name: &str) -> PackMetadata {
    PackMetadata {
        name: name.into(),
        license: "Apache-2.0".into(),
        ..Default::default()
    }
}

fn store_in(dir: &Path) -> SigPackStore {
    SigPackStore::open(&dir.join("data").join("rule-packs.sqlite3")).unwrap()
}

fn write(path: &Path, text: impl AsRef<[u8]>) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, text).unwrap();
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        writer
            .start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn imports_a_single_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("alpha.yar");
    write(&file, RULE_ALPHA);
    let store = store_in(dir.path());
    let pack = store
        .install(PackKind::Yara, &file, &meta("Alpha pack"), NOW)
        .unwrap();
    assert_eq!(pack.file_count, 1);
    assert_eq!(pack.rule_count, 1);
    assert!(pack.enabled);
    assert!(is_valid_pack_id(&pack.id), "{}", pack.id);
    assert!(pack.id.starts_with("alpha-pack-"));
    assert!(pack.id.ends_with(&pack.content_sha256[..12]));
    let stored = dir
        .path()
        .join("data/sigpacks/yara")
        .join(&pack.id)
        .join("alpha.yar");
    assert_eq!(std::fs::read_to_string(stored).unwrap(), RULE_ALPHA);
}

#[test]
fn imports_a_directory_recursively_and_counts_ignored_files() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    write(&src.join("a/alpha.yar"), RULE_ALPHA);
    write(&src.join("b/c/beta.YARA"), RULE_BETA);
    write(&src.join("README.md"), "docs");
    write(&src.join("notes.txt"), "notes");
    write(&src.join(".git/hooks/hook.yar"), RULE_ALPHA);
    let preview = validate_pack(PackKind::Yara, &src).unwrap();
    assert_eq!(preview.file_count, 2);
    assert_eq!(preview.ignored_count, 2);
    assert_eq!(preview.rule_count, 2);
    assert!(preview.skipped.is_empty());
    assert_eq!(
        preview.total_bytes,
        (RULE_ALPHA.len() + RULE_BETA.len()) as u64
    );
    // Validation wrote nothing.
    assert!(!dir.path().join("data").exists());
}

#[test]
fn imports_a_zip_and_strips_a_single_top_level_folder() {
    let dir = tempfile::tempdir().unwrap();
    let zip = dir.path().join("pack.zip");
    std::fs::write(
        &zip,
        zip_of(&[
            ("rules-main/alpha.yar", RULE_ALPHA.as_bytes()),
            ("rules-main/sub/beta.yara", RULE_BETA.as_bytes()),
            ("rules-main/LICENSE", b"MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software"),
            ("rules-main/README.md", b"hello"),
        ]),
    )
    .unwrap();
    let store = store_in(dir.path());
    let preview = validate_pack(PackKind::Yara, &zip).unwrap();
    assert_eq!(preview.file_count, 2);
    assert_eq!(preview.ignored_count, 2);
    assert_eq!(preview.detected_license.as_deref(), Some("MIT"));
    let pack = store
        .install(PackKind::Yara, &zip, &meta("zipped"), NOW)
        .unwrap();
    assert!(dir
        .path()
        .join("data/sigpacks/yara")
        .join(&pack.id)
        .join("sub/beta.yara")
        .is_file());
}

#[test]
fn licence_in_a_directory_root_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("p/alpha.yar"), RULE_ALPHA);
    write(
        &dir.path().join("p/COPYING"),
        "GNU GENERAL PUBLIC LICENSE\n Version 2, June 1991",
    );
    let preview = validate_pack(PackKind::Yara, &dir.path().join("p")).unwrap();
    assert_eq!(preview.detected_license.as_deref(), Some("GPL-2.0"));
}

#[test]
fn a_zip_member_that_escapes_the_root_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let zip = dir.path().join("evil.zip");
    std::fs::write(
        &zip,
        zip_of(&[
            ("alpha.yar", RULE_ALPHA.as_bytes()),
            ("../escape.yar", RULE_BETA.as_bytes()),
        ]),
    )
    .unwrap();
    let error = validate_pack(PackKind::Yara, &zip).unwrap_err();
    assert!(error.contains("escapes"), "{error}");
}

#[cfg(unix)]
#[test]
fn symlinks_are_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    write(&outside.join("secret.yar"), RULE_BETA);
    let src = dir.path().join("src");
    write(&src.join("alpha.yar"), RULE_ALPHA);
    std::os::unix::fs::symlink(outside.join("secret.yar"), src.join("link.yar")).unwrap();
    std::os::unix::fs::symlink(&outside, src.join("linkdir")).unwrap();
    let preview = validate_pack(PackKind::Yara, &src).unwrap();
    assert_eq!(preview.file_count, 1);
    assert_eq!(preview.ignored_count, 2);
    // A symlink given as the import source itself is refused.
    let error = validate_pack(PackKind::Yara, &src.join("link.yar")).unwrap_err();
    assert!(error.contains("symbolic link"), "{error}");
}

#[test]
fn a_file_over_one_mebibyte_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    write(&src.join("alpha.yar"), RULE_ALPHA);
    write(&src.join("big.yar"), vec![b' '; 1024 * 1024 + 1]);
    let error = validate_pack(PackKind::Yara, &src).unwrap_err();
    assert!(error.contains("per-file limit"), "{error}");
    // Exactly at the limit is accepted by the reader (it is only whitespace).
    write(&src.join("big.yar"), vec![b' '; 1024 * 1024]);
    let collected = source::collect(PackKind::Yara, &src).unwrap();
    assert_eq!(collected.files.len(), 2);
}

#[test]
fn more_than_twenty_thousand_files_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    for i in 0..=MAX_FILES {
        write(&src.join(format!("d{}/r{i}.yar", i % 50)), "// x");
    }
    let error = source::collect(PackKind::Yara, &src).unwrap_err();
    assert!(error.contains("more than 20000 rule files"), "{error}");
}

#[test]
fn more_than_256_mebibytes_in_total_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    let filler = vec![b' '; 1024 * 1024];
    for i in 0..=256 {
        write(&src.join(format!("r{i}.yar")), &filler);
    }
    let error = source::collect(PackKind::Yara, &src).unwrap_err();
    assert!(error.contains("in total"), "{error}");
}

#[test]
fn compiled_rules_are_refused_with_an_explanation() {
    let dir = tempfile::tempdir().unwrap();
    let magic = dir.path().join("compiled.yar");
    write(&magic, b"YARA\x02\x00\x00\x00binary");
    let error = validate_pack(PackKind::Yara, &magic).unwrap_err();
    assert!(error.contains("compiled"), "{error}");
    assert!(error.contains("source rules"), "{error}");
    let yarc = dir.path().join("rules.yarc");
    write(&yarc, b"anything");
    let error = validate_pack(PackKind::Yara, &yarc).unwrap_err();
    assert!(error.contains("compiled"), "{error}");
    // Inside a folder, one compiled file refuses the whole import.
    let src = dir.path().join("src");
    write(&src.join("ok.yar"), RULE_ALPHA);
    write(&src.join("bad.yar"), b"YARA-X\0\0 compiled");
    assert!(validate_pack(PackKind::Yara, &src)
        .unwrap_err()
        .contains("compiled"));
}

#[test]
fn a_file_that_is_not_utf8_is_skipped_with_a_reason() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    write(&src.join("alpha.yar"), RULE_ALPHA);
    write(&src.join("latin1.yar"), [0x72u8, 0x75, 0xE9, 0xFF]);
    let preview = validate_pack(PackKind::Yara, &src).unwrap();
    assert_eq!(preview.file_count, 1);
    assert_eq!(preview.skipped.len(), 1);
    assert_eq!(preview.skipped[0].file, "latin1.yar");
    assert!(preview.skipped[0].message.contains("UTF-8"));
}

#[test]
fn rules_that_do_not_compile_are_reported_and_the_rest_still_count() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    write(&src.join("alpha.yar"), RULE_ALPHA);
    write(
        &src.join("broken.yar"),
        "rule broken { condition: $missing }",
    );
    let preview = validate_pack(PackKind::Yara, &src).unwrap();
    assert_eq!(preview.file_count, 2);
    assert_eq!(preview.rule_count, 1);
    assert_eq!(preview.skipped.len(), 1);
    assert_eq!(preview.skipped[0].file, "broken.yar");
}

#[test]
fn nuclei_import_accepts_yaml_and_counts_files() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("t");
    write(&src.join("one.yaml"), "id: one\n");
    write(&src.join("two.yml"), "id: two\n");
    write(&src.join("rule.yar"), RULE_ALPHA);
    let preview = validate_pack(PackKind::Nuclei, &src).unwrap();
    assert_eq!(preview.file_count, 2);
    assert_eq!(preview.ignored_count, 1);
    assert_eq!(preview.rule_count, 2);
    assert!(validate_pack(PackKind::Yara, &src.join("one.yaml")).is_err());
}

#[test]
fn a_tampered_stored_file_is_skipped_at_resolve_with_its_reason() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("alpha.yar");
    write(&file, RULE_ALPHA);
    let store = store_in(dir.path());
    let pack = store
        .install(PackKind::Yara, &file, &meta("alpha"), NOW)
        .unwrap();
    let ok = store.resolve(PackKind::Yara, None).unwrap();
    assert_eq!(ok.packs.len(), 1);
    assert!(ok.skipped.is_empty());

    let stored = dir
        .path()
        .join("data/sigpacks/yara")
        .join(&pack.id)
        .join("alpha.yar");
    std::fs::write(&stored, "rule evil { condition: true }").unwrap();
    let resolved = store.resolve(PackKind::Yara, None).unwrap();
    assert!(resolved.packs.is_empty());
    assert_eq!(resolved.skipped.len(), 1);
    assert_eq!(resolved.skipped[0].0, pack.id);
    assert!(
        resolved.skipped[0].1.contains("modified"),
        "{}",
        resolved.skipped[0].1
    );
}

#[test]
fn a_manifest_rewritten_to_match_tampered_files_is_still_caught() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("alpha.yar");
    write(&file, RULE_ALPHA);
    let store = store_in(dir.path());
    let pack = store
        .install(PackKind::Yara, &file, &meta("alpha"), NOW)
        .unwrap();
    let pack_dir = dir.path().join("data/sigpacks/yara").join(&pack.id);
    let evil = "rule evil { condition: true }";
    std::fs::write(pack_dir.join("alpha.yar"), evil).unwrap();
    let manifest = serde_json::json!({
        "schemaVersion": 1,
        "files": [{"path": "alpha.yar", "sha256": hex::encode(sha2::Sha256::digest(evil)), "bytes": evil.len()}]
    });
    std::fs::write(pack_dir.join("manifest.json"), manifest.to_string()).unwrap();
    let resolved = store.resolve(PackKind::Yara, None).unwrap();
    assert!(resolved.packs.is_empty());
    assert!(
        resolved.skipped[0].1.contains("content hash"),
        "{}",
        resolved.skipped[0].1
    );
}

#[test]
fn a_deleted_pack_directory_is_skipped_not_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("alpha.yar");
    write(&file, RULE_ALPHA);
    let store = store_in(dir.path());
    let pack = store
        .install(PackKind::Yara, &file, &meta("alpha"), NOW)
        .unwrap();
    std::fs::remove_dir_all(dir.path().join("data/sigpacks/yara").join(&pack.id)).unwrap();
    let resolved = store.resolve(PackKind::Yara, None).unwrap();
    assert!(resolved.packs.is_empty());
    assert_eq!(resolved.skipped.len(), 1);
}

#[test]
fn installing_identical_content_twice_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("alpha.yar");
    write(&file, RULE_ALPHA);
    let store = store_in(dir.path());
    let first = store
        .install(PackKind::Yara, &file, &meta("alpha"), NOW)
        .unwrap();
    store.set_enabled(&first.id, false).unwrap();
    let second = store
        .install(
            PackKind::Yara,
            &file,
            &meta("alpha"),
            "2027-01-01T00:00:00Z",
        )
        .unwrap();
    assert_eq!(second.id, first.id);
    assert_eq!(second.installed_at, NOW);
    assert_eq!(store.list().unwrap().len(), 1);
    assert!(
        !store.list().unwrap()[0].enabled,
        "re-import must not re-enable"
    );
    // A damaged copy is repaired by importing the same content again.
    let stored = dir
        .path()
        .join("data/sigpacks/yara")
        .join(&first.id)
        .join("alpha.yar");
    std::fs::write(&stored, "changed").unwrap();
    store
        .install(PackKind::Yara, &file, &meta("alpha"), NOW)
        .unwrap();
    assert_eq!(std::fs::read_to_string(&stored).unwrap(), RULE_ALPHA);
}

#[test]
fn same_name_with_different_content_is_a_different_pack() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.yar");
    let b = dir.path().join("b.yar");
    write(&a, RULE_ALPHA);
    write(&b, RULE_BETA);
    let store = store_in(dir.path());
    let first = store
        .install(PackKind::Yara, &a, &meta("same"), NOW)
        .unwrap();
    let second = store
        .install(PackKind::Yara, &b, &meta("same"), NOW)
        .unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(store.list().unwrap().len(), 2);
}

#[test]
fn enable_disable_remove_and_explicit_selection() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("alpha.yar");
    write(&file, RULE_ALPHA);
    let store = store_in(dir.path());
    let pack = store
        .install(PackKind::Yara, &file, &meta("alpha"), NOW)
        .unwrap();

    store.set_enabled(&pack.id, false).unwrap();
    assert!(store
        .resolve(PackKind::Yara, None)
        .unwrap()
        .packs
        .is_empty());
    let selected = store
        .resolve(PackKind::Yara, Some(&[pack.id.clone(), "nope".into()]))
        .unwrap();
    assert_eq!(
        selected.packs.len(),
        1,
        "explicit selection applies a disabled pack"
    );
    assert_eq!(selected.skipped.len(), 1);
    assert!(selected.skipped[0].1.contains("not installed"));
    let wrong_kind = store
        .resolve(PackKind::Nuclei, Some(std::slice::from_ref(&pack.id)))
        .unwrap();
    assert!(wrong_kind.packs.is_empty());
    assert!(wrong_kind.skipped[0].1.contains("yara pack"));

    let pack_dir = dir.path().join("data/sigpacks/yara").join(&pack.id);
    assert!(pack_dir.is_dir());
    store.remove(&pack.id).unwrap();
    assert!(!pack_dir.exists());
    assert!(store.list().unwrap().is_empty());
    assert!(store.remove(&pack.id).is_err());
    assert!(store.set_enabled(&pack.id, true).is_err());
    assert!(store.remove("../../etc").is_err());
}

#[test]
fn the_stored_table_lives_in_the_rule_pack_database() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("rule-packs.sqlite3");
    let rule_packs = crate::rulepack_store::RulePackStore::open(&db).unwrap();
    let sig = SigPackStore::open(&db).unwrap();
    let file = dir.path().join("alpha.yar");
    write(&file, RULE_ALPHA);
    sig.install(PackKind::Yara, &file, &meta("alpha"), NOW)
        .unwrap();
    assert!(rule_packs.list().unwrap().is_empty());
    let conn = rusqlite::Connection::open(&db).unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(tables.contains(&"signature_packs".to_string()));
    assert!(tables.contains(&"rule_packs".to_string()));
    assert!(dir.path().join("sigpacks/yara").is_dir());
}

#[test]
fn name_and_licence_are_required_and_ids_are_well_formed() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("alpha.yar");
    write(&file, RULE_ALPHA);
    let store = store_in(dir.path());
    let mut m = meta("");
    assert!(store.install(PackKind::Yara, &file, &m, NOW).is_err());
    m = meta("ok");
    m.license = "   ".into();
    assert!(store
        .install(PackKind::Yara, &file, &m, NOW)
        .unwrap_err()
        .contains("licence"));
    m.license = "x".repeat(201);
    assert!(store.install(PackKind::Yara, &file, &m, NOW).is_err());
    assert!(store.list().unwrap().is_empty());

    for good in ["a", "a1", "abc.def_g-h", &format!("a{}", "b".repeat(63))] {
        assert!(is_valid_pack_id(good), "{good}");
    }
    for bad in ["", "-a", ".a", "A", "a b", "a/b", &"a".repeat(65)] {
        assert!(!is_valid_pack_id(bad), "{bad}");
    }
    let hash = "0123456789abcdef".repeat(4);
    for name in [
        "Ünïcode / Pack!!",
        "***",
        &"x".repeat(300),
        "  Spaced  Name  ",
    ] {
        let id = pack_id_for(name, &hash);
        assert!(is_valid_pack_id(&id), "{name:?} -> {id}");
    }
}
