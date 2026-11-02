#![no_main]

use libfuzzer_sys::fuzz_target;
use oxaudit_parsers::{bdb_hash, go_buildinfo, go_inventory, os_packages, package_note, rpm_header, rulepack_index};

// The small parsers of image and download content, each cheap enough to run
// on every input: the ELF package note, the os-release and package databases
// read from extracted images, rpm header blobs and Berkeley DB files, and the
// rule-pack feed index.
fuzz_target!(|data: &[u8]| {
    if let Some(note) = package_note::read(data) {
        let _ = package_note::upstream_version(&note.version);
    }
    let _ = os_packages::parse_os_release(data);
    let _ = os_packages::parse_dpkg_status(data);
    let _ = os_packages::parse_apk_installed(data);
    if let Ok(package) = rpm_header::parse_header_blob(data) {
        let _ = (package.evr(), package.source_name());
    }
    if let Ok(values) = bdb_hash::values(data) {
        for value in values {
            let _ = rpm_header::parse_header_blob(&value);
        }
    }
    if let Ok(Some(info)) = go_buildinfo::read(data) {
        let _ = go_inventory::osv_go_version(&info.go_version);
    }
    let _ = rulepack_index::parse_index(data);
});
