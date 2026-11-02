#![no_main]

use libfuzzer_sys::fuzz_target;
use oxaudit_parsers::lockfiles::{parse_lockfile_content, LOCKFILE_NAMES, MSBUILD_FORMAT};
use oxaudit_parsers::msbuild;

// The first byte picks the format, the rest is the lockfile text: every
// parser stays reachable and a mutation keeps its format. Seeds under
// `fuzz/seeds/parse_lockfile` carry the selector byte of their format.
fuzz_target!(|data: &[u8]| {
    let Some((&selector, content)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(content);
    // Selector 255 is the .NET project-file format, which has no fixed file
    // name; with it, the props reader is fuzzed on the same input.
    if selector == 255 {
        let _ = parse_lockfile_content(MSBUILD_FORMAT, &text);
        let _ = msbuild::parse_central_versions(&text);
        return;
    }
    let name = LOCKFILE_NAMES[usize::from(selector) % LOCKFILE_NAMES.len()];
    let _ = parse_lockfile_content(name, &text);
});
