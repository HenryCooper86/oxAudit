#![no_main]

use libfuzzer_sys::fuzz_target;
use oxaudit_parsers::{os_packages, package_note, rulepack_index};

// The small parsers of image and download content, each cheap enough to run
// on every input: the ELF package note, the os-release and package databases
// read from extracted images, and the rule-pack feed index.
fuzz_target!(|data: &[u8]| {
    if let Some(note) = package_note::read(data) {
        let _ = package_note::upstream_version(&note.version);
    }
    let _ = os_packages::parse_os_release(data);
    let _ = os_packages::parse_dpkg_status(data);
    let _ = os_packages::parse_apk_installed(data);
    let _ = rulepack_index::parse_index(data);
});
