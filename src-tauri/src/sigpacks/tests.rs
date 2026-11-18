use std::io::Write;
use std::path::Path;

use super::source::{self, MAX_FILES};
#[cfg(feature = "templates")]
use super::store::PackProtocols;
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
fn zip_limits_are_enforced_while_reading_not_after_inflating_everything() {
    // Many members that compress to almost nothing but inflate to 16 KiB
    // each. With a 64 KiB budget the reader must stop at the fifth member
    // instead of inflating all of them and checking afterwards.
    let dir = tempfile::tempdir().unwrap();
    let filler = vec![b' '; 16 * 1024];
    let names: Vec<String> = (0..100).map(|i| format!("r{i:03}.yar")).collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|name| (name.as_str(), filler.as_slice()))
        .collect();
    let zip = dir.path().join("bomb.zip");
    std::fs::write(&zip, zip_of(&entries)).unwrap();
    assert!(std::fs::metadata(&zip).unwrap().len() < 100 * 1024);

    let (result, read) =
        source::collect_zip_with_limits(PackKind::Yara, &zip, MAX_FILES, 64 * 1024);
    let error = result.unwrap_err();
    assert!(error.contains("in total"), "{error}");
    assert_eq!(read, 5, "members inflated before the refusal");

    // The file-count limit also stops the read at the first excess member.
    let tiny: Vec<(&str, &[u8])> = names
        .iter()
        .map(|name| (name.as_str(), &b"// x"[..]))
        .collect();
    std::fs::write(&zip, zip_of(&tiny)).unwrap();
    let (result, read) = source::collect_zip_with_limits(PackKind::Yara, &zip, 10, u64::MAX);
    let error = result.unwrap_err();
    assert!(error.contains("more than 10 rule files"), "{error}");
    assert_eq!(read, 10, "members inflated before the refusal");

    // Members that are not rule files are never inflated.
    let blobs: Vec<String> = (1..100).map(|i| format!("x{i}.bin")).collect();
    let mut other: Vec<(&str, &[u8])> = vec![("r.yar", RULE_ALPHA.as_bytes())];
    other.extend(blobs.iter().map(|name| (name.as_str(), filler.as_slice())));
    std::fs::write(&zip, zip_of(&other)).unwrap();
    let (result, read) =
        source::collect_zip_with_limits(PackKind::Yara, &zip, MAX_FILES, 64 * 1024);
    let collected = result.unwrap();
    assert_eq!(collected.files.len(), 1);
    assert_eq!(collected.ignored, 99);
    assert_eq!(read, 1);
}

#[test]
fn paths_that_collide_on_case_or_normalisation_insensitive_filesystems_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let zip = dir.path().join("case.zip");
    std::fs::write(
        &zip,
        zip_of(&[
            ("rules/A.yar", RULE_ALPHA.as_bytes()),
            ("rules/a.yar", RULE_BETA.as_bytes()),
        ]),
    )
    .unwrap();
    let error = validate_pack(PackKind::Yara, &zip).unwrap_err();
    assert!(
        error.contains("A.yar") && error.contains("a.yar"),
        "{error}"
    );
    assert!(error.contains("case-insensitive"), "{error}");

    // The same name in NFC (precomposed) and NFD (decomposed) form.
    let nfc = "caf\u{e9}.yar";
    let nfd = "cafe\u{301}.yar";
    std::fs::write(
        &zip,
        zip_of(&[(nfc, RULE_ALPHA.as_bytes()), (nfd, RULE_BETA.as_bytes())]),
    )
    .unwrap();
    let error = validate_pack(PackKind::Yara, &zip).unwrap_err();
    assert!(error.contains(nfc) && error.contains(nfd), "{error}");

    // Folders that differ only by case collide too.
    std::fs::write(
        &zip,
        zip_of(&[
            ("Sub/x.yar", RULE_ALPHA.as_bytes()),
            ("sub/x.yar", RULE_BETA.as_bytes()),
        ]),
    )
    .unwrap();
    assert!(validate_pack(PackKind::Yara, &zip)
        .unwrap_err()
        .contains("Sub/x.yar"));
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

const T_FILE: &str = "id: file-one\ninfo:\n  name: File one\n  severity: low\nfile:\n  - extensions: [conf]\n    matchers:\n      - type: word\n        words: [needle]\n";
#[cfg(feature = "templates")]
const T_HTTP: &str = "id: http-one\ninfo:\n  name: Http one\n  severity: low\nhttp:\n  - path: ['{{BaseURL}}/x']\n    matchers:\n      - type: status\n        status: [200]\nfile:\n  - extensions: [conf]\n    matchers:\n      - type: word\n        words: [needle]\n";
#[cfg(feature = "templates")]
const T_DNS: &str = "id: dns-one\ninfo:\n  name: Dns one\n  severity: info\ndns:\n  - name: '{{FQDN}}'\n    type: A\n    matchers:\n      - type: word\n        words: ['1.2.3.4']\n";
#[cfg(feature = "templates")]
const T_HEADLESS: &str = "id: headless-one\ninfo:\n  name: Headless one\n  severity: info\nheadless:\n  - steps:\n      - action: navigate\n        args:\n          url: '{{BaseURL}}'\n";

#[cfg(feature = "templates")]
#[test]
fn nuclei_import_loads_templates_and_reports_what_it_cannot_evaluate() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("t");
    write(&src.join("a/file.yaml"), T_FILE);
    write(&src.join("a/http.yml"), T_HTTP);
    write(&src.join("dns.yaml"), T_DNS);
    write(&src.join("headless.yaml"), T_HEADLESS);
    write(&src.join("dup.yaml"), T_FILE); // repeats id file-one
    write(&src.join("broken.yaml"), "id: broken\ninfo: [oops\n");
    write(&src.join("noname.yaml"), "id: noname\n");
    write(
        &src.join("workflow.yaml"),
        "workflows:\n  - template: a.yaml\n",
    );
    write(&src.join("ci.yml"), "name: ci\non: push\n");
    write(&src.join("rule.yar"), RULE_ALPHA);
    let preview = validate_pack(PackKind::Nuclei, &src).unwrap();
    assert_eq!(preview.file_count, 9, "every yaml file is kept in the pack");
    assert_eq!(
        preview.ignored_count,
        1 + 2,
        "the .yar file and the two yaml files with no top-level id"
    );
    // file-one, http-one, dns-one load and are supported.
    assert_eq!(preview.rule_count, 3);
    assert_eq!(preview.not_evaluated_count, 1);
    assert_eq!(
        preview.protocols,
        Some(PackProtocols {
            http: 1,
            dns: 1,
            tcp: 0,
            ssl: 0,
            file: 2
        })
    );
    let by_file = |name: &str| {
        preview
            .skipped
            .iter()
            .find(|skip| skip.file == name)
            .map(|skip| skip.message.clone())
            .unwrap_or_default()
    };
    assert!(by_file("headless.yaml").starts_with("not evaluated: "));
    assert!(by_file("headless.yaml").contains("headless"));
    assert!(by_file("dup.yaml").contains("duplicate template id `file-one`"));
    assert!(
        by_file("broken.yaml").contains("invalid YAML"),
        "{}",
        by_file("broken.yaml")
    );
    assert!(by_file("noname.yaml").contains("info.name"));
    assert_eq!(preview.skipped.len(), 4);
    assert!(validate_pack(PackKind::Yara, &src.join("dns.yaml")).is_err());
}

#[cfg(feature = "templates")]
#[test]
fn nuclei_pack_statistics_survive_install_and_a_database_from_before_the_column() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("t");
    write(&src.join("file.yaml"), T_FILE);
    write(&src.join("headless.yaml"), T_HEADLESS);
    let store = store_in(dir.path());
    let pack = store
        .install(PackKind::Nuclei, &src, &meta("fixtures"), NOW)
        .unwrap();
    assert_eq!(pack.rule_count, 1);
    assert_eq!(pack.not_evaluated_count, 1);
    assert_eq!(pack.protocols.unwrap().file, 1);
    let listed = store.list().unwrap();
    assert_eq!(listed[0].protocols, pack.protocols);
    assert_eq!(listed[0].not_evaluated_count, 1);
    let json = serde_json::to_value(&listed[0]).unwrap();
    assert_eq!(json["protocols"]["file"], 1);
    assert_eq!(json["notEvaluatedCount"], 1);

    // A table created before `stats_json` is upgraded in place.
    drop(store);
    let db = dir.path().join("data").join("rule-packs.sqlite3");
    {
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection
            .execute_batch("ALTER TABLE signature_packs DROP COLUMN stats_json")
            .unwrap();
    }
    let reopened = store_in(dir.path());
    let listed = reopened.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].protocols, None,
        "unknown until the pack is re-imported"
    );
    assert_eq!(listed[0].not_evaluated_count, 0);
}

#[cfg(not(feature = "templates"))]
#[test]
fn nuclei_import_without_the_template_engine_fails_explicitly() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("t");
    write(&src.join("file.yaml"), T_FILE);
    let error = validate_pack(PackKind::Nuclei, &src).unwrap_err();
    assert!(error.contains("no template engine"), "{error}");
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
