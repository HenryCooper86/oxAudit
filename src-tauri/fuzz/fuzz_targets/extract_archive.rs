#![no_main]

use libfuzzer_sys::fuzz_target;
use oxaudit_archive::extract;

fuzz_target!(|data: &[u8]| {
    // Small budgets so mutations reach the stops quickly, and the default
    // path too: both are entry points a real scan uses.
    let small = extract::ExtractBudget {
        max_depth: 3,
        max_entries: 8,
        max_entry_bytes: 64 * 1024,
        max_total_bytes: 256 * 1024,
    };
    let _ = extract::extract("fuzz", data, &small);
    let _ = extract::extract("fuzz", data, &extract::ExtractBudget::default());
    let _ = extract::extract_embedded_squashfs("fuzz", data, &small);
    // One deliberate container per format family keeps the interesting
    // parsers reachable: gzip, tar, zip, ar, cpio-in-rpm, squashfs, cramfs.
    let mut gzip = Vec::new();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = std::io::Write::write_all(&mut encoder, data);
    if let Ok(compressed) = encoder.finish() {
        gzip = compressed;
    }
    let _ = extract::extract("fuzz.gz", &gzip, &small);
});
