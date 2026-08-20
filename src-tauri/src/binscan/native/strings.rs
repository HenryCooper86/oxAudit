//! Extracting printable strings from a binary.
//!
//! This is the `strings(1)` algorithm, with two additions that matter for
//! component detection:
//!
//! - **UTF-16LE runs are extracted too.** Windows binaries store most of their
//!   text that way, and an ASCII-only pass sees almost nothing in them.
//! - **Runs are joined with `\n`.** Version signatures routinely need to see
//!   two adjacent strings together — "OpenSSL 3.0.2" followed by the build
//!   date, say — and the separator is what lets a pattern anchor between them.
//!
//! The output is one flat blob rather than a list, because the matcher runs
//! regular expressions over it in a single pass.

use std::io::Read;

/// Shortest run kept. Four is the `strings(1)` default; below it, ordinary
/// binary data produces enough accidental words to matter.
pub const MIN_RUN: usize = 4;

/// Most bytes of a single file we will read.
///
/// A firmware image can be arbitrarily large, and reading one per worker
/// thread is how a scanner runs a machine out of memory. Version strings sit
/// in read-only data near the front, so a prefix is nearly as good — but the
/// caller is told when this bites, because "we did not look at all of it" must
/// not be indistinguishable from "there was nothing there".
pub const MAX_FILE_BYTES: usize = 128 * 1024 * 1024;

pub struct Capped {
    pub bytes: Vec<u8>,
    /// True when the file was larger than [`MAX_FILE_BYTES`] and only a prefix
    /// was read.
    pub truncated: bool,
}

fn is_printable(byte: u8) -> bool {
    matches!(byte, 0x09 | 0x20..=0x7e)
}

/// Pull ASCII runs out of `bytes`, appending each followed by a newline.
fn push_ascii_runs(bytes: &[u8], out: &mut String) {
    let mut run = String::new();
    for &byte in bytes {
        if is_printable(byte) {
            run.push(byte as char);
            continue;
        }
        if run.len() >= MIN_RUN {
            out.push_str(&run);
            out.push('\n');
        }
        run.clear();
    }
    if run.len() >= MIN_RUN {
        out.push_str(&run);
        out.push('\n');
    }
}

/// Pull UTF-16LE runs out of `bytes` — printable ASCII in the low byte, NUL in
/// the high byte. Both alignments are tried, because a run's parity is set by
/// where it happens to sit in the file, not by the file's own alignment.
fn push_utf16le_runs(bytes: &[u8], out: &mut String) {
    for start in 0..2usize {
        let mut run = String::new();
        let mut index = start;
        while index + 1 < bytes.len() {
            let low = bytes[index];
            let high = bytes[index + 1];
            if high == 0 && is_printable(low) {
                run.push(low as char);
            } else {
                if run.len() >= MIN_RUN {
                    out.push_str(&run);
                    out.push('\n');
                }
                run.clear();
            }
            index += 2;
        }
        if run.len() >= MIN_RUN {
            out.push_str(&run);
            out.push('\n');
        }
    }
}

/// Extract every run from an in-memory buffer.
pub fn extract(bytes: &[u8]) -> String {
    let mut out = String::new();
    push_ascii_runs(bytes, &mut out);
    push_utf16le_runs(bytes, &mut out);
    out
}

/// Read at most [`MAX_FILE_BYTES`] from `reader`, reporting whether there was
/// more.
pub fn read_capped<R: Read>(mut reader: R) -> std::io::Result<Capped> {
    let mut bytes = Vec::new();
    let read = (&mut reader)
        .take(MAX_FILE_BYTES as u64)
        .read_to_end(&mut bytes)?;

    // One more byte would mean there was more file than we agreed to read.
    let mut probe = [0u8; 1];
    let truncated = read == MAX_FILE_BYTES && reader.read(&mut probe)? > 0;

    Ok(Capped { bytes, truncated })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_shorter_than_the_minimum_are_dropped() {
        let bytes = b"\x00ab\x00abcd\x00";
        let blob = extract(bytes);
        assert!(blob.contains("abcd"));
        assert!(
            !blob.lines().any(|line| line == "ab"),
            "two-character runs are noise, not strings"
        );
    }

    #[test]
    fn adjacent_runs_are_separated_so_a_pattern_can_anchor_between_them() {
        // Real signatures look like `\nOpenSSL ([0-9.]+)`; without the join
        // character there is nothing for `\n` to match against.
        let bytes = b"OpenSSL 3.0.2\x00\x00built on: reproducible\x00";
        let blob = extract(bytes);
        assert!(blob.contains("OpenSSL 3.0.2\nbuilt on: reproducible"));
    }

    #[test]
    fn utf16le_text_is_recovered() {
        // A Windows binary's version data is UTF-16; an ASCII-only pass reads
        // it as a stream of one-character runs and discards every one.
        let mut bytes = vec![0x00u8];
        for character in "ProductVersion".bytes() {
            bytes.push(character);
            bytes.push(0);
        }
        let blob = extract(&bytes);
        assert!(
            blob.contains("ProductVersion"),
            "expected the UTF-16 run to be recovered, got {blob:?}"
        );
    }

    #[test]
    fn a_utf16_run_is_found_at_either_alignment() {
        // The run's parity depends on where it lands in the file, so trying
        // only even offsets misses half of them.
        let mut even = Vec::new();
        let mut odd = vec![0xffu8];
        for character in "libcurl".bytes() {
            even.push(character);
            even.push(0);
            odd.push(character);
            odd.push(0);
        }
        assert!(extract(&even).contains("libcurl"));
        assert!(extract(&odd).contains("libcurl"));
    }

    #[test]
    fn a_run_at_the_very_end_of_the_buffer_is_not_lost() {
        // The flush-on-terminator loop drops the final run unless it is
        // flushed again after the loop.
        assert!(extract(b"\x00trailing").contains("trailing"));
    }

    #[test]
    fn reading_stops_at_the_cap_and_says_so() {
        let oversized = vec![b'A'; MAX_FILE_BYTES + 16];
        let capped = read_capped(&oversized[..]).expect("read");
        assert_eq!(capped.bytes.len(), MAX_FILE_BYTES);
        assert!(
            capped.truncated,
            "a partially-read file must not look like a fully-read one"
        );

        let small = b"\x00hello\x00".to_vec();
        let capped = read_capped(&small[..]).expect("read");
        assert!(!capped.truncated);
        assert!(extract(&capped.bytes).contains("hello"));
    }

    #[test]
    fn a_file_exactly_at_the_cap_is_not_reported_as_truncated() {
        // The boundary case: `read == MAX` is not by itself evidence that more
        // was there, and reporting it as truncated would cry wolf on every
        // file of exactly that size.
        let exact = vec![b'A'; MAX_FILE_BYTES];
        assert!(!read_capped(&exact[..]).expect("read").truncated);
    }
}
