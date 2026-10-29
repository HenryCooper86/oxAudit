#![no_main]

use libfuzzer_sys::fuzz_target;

// Report import reads a file the user picked: SARIF, CycloneDX, SPDX,
// OpenVEX or an oxAudit report. `inspect` sniffs the format itself.
fuzz_target!(|data: &[u8]| {
    let _ = oxaudit_parsers::report_import::inspect(data);
});
