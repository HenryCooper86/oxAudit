//! Deciding which files are worth extracting strings from.
//!
//! cve-bin-tool shells out to `file(1)` for this and treats its English output
//! as an API — it looks for the substrings "LSB", "Mach-O", ": data" and so on.
//! That is a subprocess per file, it is not available on Windows, and it breaks
//! under a localized `file`. We read magic bytes instead.
//!
//! The gate is deliberately permissive. Firmware images are frequently raw
//! blobs with no recognizable header, and those are exactly the targets this
//! scanner exists for, so anything that looks like binary data is scanned. Text
//! is skipped because a source tree would otherwise produce a flood of matches
//! from documentation and changelogs.

/// What a file appears to be, as far as the string extractor cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// A recognized executable or shared-object format.
    Executable(Format),
    /// Binary data with no header we recognize — a firmware image, a resource
    /// blob, a compressed archive. Worth scanning.
    OpaqueBinary,
    /// Text. Skipped: a version string in a README is not evidence that this
    /// build of the library is present.
    Text,
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    MachO,
    Pe,
    /// A Java class or jar; version strings live in the constant pool.
    Java,
    /// `.a` / `.deb` static archive.
    Ar,
}

impl Classification {
    /// Should the string extractor run on this file?
    pub fn is_scannable(self) -> bool {
        matches!(self, Classification::Executable(_) | Classification::OpaqueBinary)
    }
}

/// How many bytes we need to classify. Kept small so a caller can classify
/// cheaply before deciding to read the whole file.
pub const PROBE_BYTES: usize = 4096;

/// Classify from a prefix of the file.
pub fn classify(prefix: &[u8]) -> Classification {
    if prefix.is_empty() {
        return Classification::Empty;
    }
    if let Some(format) = executable_format(prefix) {
        return Classification::Executable(format);
    }
    if looks_binary(prefix) {
        Classification::OpaqueBinary
    } else {
        Classification::Text
    }
}

fn executable_format(prefix: &[u8]) -> Option<Format> {
    if prefix.starts_with(b"\x7fELF") {
        return Some(Format::Elf);
    }
    if prefix.starts_with(b"!<arch>\n") {
        return Some(Format::Ar);
    }
    // Java class files and the ZIP-based jar share no magic; only the class
    // file is identified here. A jar reads as OpaqueBinary, which still gets
    // scanned.
    if prefix.starts_with(b"\xca\xfe\xba\xbe") {
        // Ambiguous: this is both a Java class magic and a Mach-O fat binary
        // magic. A Mach-O fat header's next four bytes are an architecture
        // count, which is small; a Java class's are its version, which starts
        // at 0x2D or above in the minor/major pair.
        return match prefix.get(4..8) {
            Some(bytes) => {
                let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if value < 64 {
                    Some(Format::MachO)
                } else {
                    Some(Format::Java)
                }
            }
            None => Some(Format::Java),
        };
    }
    const MACH_O: [&[u8]; 5] = [
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xbe\xba\xfe\xca",
    ];
    if MACH_O.iter().any(|magic| prefix.starts_with(magic)) {
        return Some(Format::MachO);
    }
    if prefix.starts_with(b"MZ") && has_pe_header(prefix) {
        return Some(Format::Pe);
    }
    None
}

/// A DOS stub says `MZ`; only a PE has a `PE\0\0` signature at the offset
/// stored at 0x3c. Checking it keeps ordinary DOS-era files out.
fn has_pe_header(prefix: &[u8]) -> bool {
    let Some(bytes) = prefix.get(0x3c..0x40) else {
        return false;
    };
    let offset = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    matches!(prefix.get(offset..offset + 4), Some(b"PE\0\0"))
}

/// The usual heuristic: a NUL byte, or enough bytes outside the printable and
/// common-control range, means this is not text.
fn looks_binary(prefix: &[u8]) -> bool {
    if prefix.contains(&0) {
        return true;
    }
    let odd = prefix
        .iter()
        .filter(|&&byte| !matches!(byte, 0x09 | 0x0a | 0x0d | 0x20..=0x7e) && byte < 0x80)
        .count();
    // UTF-8 text has no C0 controls beyond tab/CR/LF; a few stray ones are
    // tolerated so a file with an escape sequence is still read as text.
    odd * 100 > prefix.len().max(1) * 2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf() -> Vec<u8> {
        let mut bytes = b"\x7fELF\x02\x01\x01".to_vec();
        bytes.extend_from_slice(&[0u8; 64]);
        bytes
    }

    #[test]
    fn executables_are_recognized_by_magic_rather_than_by_file_output() {
        assert_eq!(classify(&elf()), Classification::Executable(Format::Elf));
        assert_eq!(
            classify(b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"),
            Classification::Executable(Format::MachO)
        );
    }

    #[test]
    fn a_dos_stub_without_a_pe_signature_is_not_a_pe() {
        // `MZ` alone is not enough: plain DOS binaries and some scripts start
        // with it, and misreading them as PE would be a silent scope creep.
        let mut bytes = vec![0x4d, 0x5a];
        bytes.extend_from_slice(&[0u8; 200]);
        assert_ne!(classify(&bytes), Classification::Executable(Format::Pe));

        let mut pe = vec![0u8; 0x100];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(classify(&pe), Classification::Executable(Format::Pe));
    }

    #[test]
    fn a_mach_o_fat_binary_is_not_mistaken_for_a_java_class() {
        // Both start 0xcafebabe. Universal binaries are the common case on
        // macOS, so getting this backwards would misclassify every one of them.
        let fat = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02];
        assert_eq!(classify(&fat), Classification::Executable(Format::MachO));

        let class = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x41];
        assert_eq!(classify(&class), Classification::Executable(Format::Java));
    }

    #[test]
    fn headerless_binary_data_is_still_scanned() {
        // Firmware images are the reason this scanner exists and they rarely
        // carry a header we know.
        let blob = [0x1fu8, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe];
        assert_eq!(classify(&blob), Classification::OpaqueBinary);
        assert!(classify(&blob).is_scannable());
    }

    #[test]
    fn text_is_skipped_so_documentation_cannot_masquerade_as_a_component() {
        let readme = b"OpenSSL 1.0.2k is required to build this project.\nSee INSTALL.\n";
        assert_eq!(classify(readme), Classification::Text);
        assert!(!classify(readme).is_scannable());
    }

    #[test]
    fn an_empty_file_is_neither_binary_nor_text() {
        assert_eq!(classify(b""), Classification::Empty);
        assert!(!classify(b"").is_scannable());
    }
}
