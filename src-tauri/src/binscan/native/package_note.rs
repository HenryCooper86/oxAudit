//! Reading the ELF package-metadata note.
//!
//! Debian, Fedora and others stamp binaries with a `.note.package` entry — the
//! [ELF package metadata] convention: owner `FDO`, type `0xcafe1a7e`, and a
//! JSON payload naming the package and version the binary was built from.
//!
//! This matters more than it sounds. String signatures are inference: they
//! guess a component from text that happens to be embedded. The note is a
//! *statement by the builder*, and it is present in libraries that carry no
//! usable version string at all — zstd, sqlite3, pcre2, liblzma each have
//! nothing but ELF symbol tags, and a signature for them would be a guess. It
//! is also what lets grype find anything in a stripped root filesystem, which
//! is why grype found eleven components there and not zero.
//!
//! Neither cve-bin-tool nor a plain strings pass reads this note structurally.
//!
//! [ELF package metadata]: https://systemd.io/ELF_PACKAGE_METADATA/

use serde::Deserialize;

/// `FDO` note type carrying package metadata.
const NOTE_TYPE_PACKAGE: u32 = 0xcafe_1a7e;
const NOTE_OWNER: &[u8] = b"FDO";
const PT_NOTE: u32 = 4;

/// What the builder declared about this binary.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PackageNote {
    /// Package name, e.g. `libzstd`.
    pub name: String,
    /// Package version, e.g. `1.5.7+dfsg-1`.
    #[serde(default)]
    pub version: String,
    /// `deb`, `rpm`, …
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub os: String,
}

/// Strip a distribution's packaging from a version so it can be compared with
/// upstream advisories.
///
/// `1:8.14.1-2+deb13u4` is Debian's name for upstream `8.14.1`. Advisory feeds
/// key on the upstream number, so leaving the epoch and revision attached is
/// how a component silently fails to match any CVE at all — which is exactly
/// the defect that makes grype's `mariadb 1:11.8.6-0+deb13u1` and
/// cve-bin-tool's `11.8.6` fail to merge into one row.
pub fn upstream_version(raw: &str) -> String {
    let without_epoch = raw.split_once(':').map(|(_, rest)| rest).unwrap_or(raw);
    let cut = without_epoch
        .find(|c| c == '-' || c == '+' || c == '~')
        .unwrap_or(without_epoch.len());
    without_epoch[..cut].trim().to_string()
}

struct Reader<'a> {
    bytes: &'a [u8],
    little_endian: bool,
}

impl<'a> Reader<'a> {
    fn u16_at(&self, offset: usize) -> Option<u16> {
        let raw: [u8; 2] = self.bytes.get(offset..offset + 2)?.try_into().ok()?;
        Some(if self.little_endian {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    }

    fn u32_at(&self, offset: usize) -> Option<u32> {
        let raw: [u8; 4] = self.bytes.get(offset..offset + 4)?.try_into().ok()?;
        Some(if self.little_endian {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    }

    fn u64_at(&self, offset: usize) -> Option<u64> {
        let raw: [u8; 8] = self.bytes.get(offset..offset + 8)?.try_into().ok()?;
        Some(if self.little_endian {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        })
    }
}

/// Round up to the next 4-byte boundary, as the note format requires.
fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|v| v & !3)
}

/// Find the package note in an ELF image, if it has one.
///
/// Every field is bounds-checked against the buffer: the input is an untrusted
/// firmware image, and a truncated or hostile header must produce `None`, not
/// a panic in a scan the user cannot finish.
pub fn read(bytes: &[u8]) -> Option<PackageNote> {
    if !bytes.starts_with(b"\x7fELF") {
        return None;
    }
    let is_64 = match bytes.get(4)? {
        2 => true,
        1 => false,
        _ => return None,
    };
    let little_endian = match bytes.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let reader = Reader {
        bytes,
        little_endian,
    };

    let (phoff, phentsize_at, phnum_at) = if is_64 {
        (reader.u64_at(0x20)? as usize, 0x36, 0x38)
    } else {
        (reader.u32_at(0x1c)? as usize, 0x2a, 0x2c)
    };
    let phentsize = reader.u16_at(phentsize_at)? as usize;
    let phnum = reader.u16_at(phnum_at)? as usize;
    if phentsize == 0 {
        return None;
    }

    for index in 0..phnum {
        let header = phoff.checked_add(index.checked_mul(phentsize)?)?;
        if reader.u32_at(header)? != PT_NOTE {
            continue;
        }
        let (offset, size) = if is_64 {
            (
                reader.u64_at(header + 0x08)? as usize,
                reader.u64_at(header + 0x20)? as usize,
            )
        } else {
            (
                reader.u32_at(header + 0x04)? as usize,
                reader.u32_at(header + 0x10)? as usize,
            )
        };
        let end = offset.checked_add(size)?;
        let Some(segment) = bytes.get(offset..end.min(bytes.len())) else {
            continue;
        };
        if let Some(note) = scan_notes(segment, little_endian) {
            return Some(note);
        }
    }
    None
}

fn scan_notes(segment: &[u8], little_endian: bool) -> Option<PackageNote> {
    let reader = Reader {
        bytes: segment,
        little_endian,
    };
    let mut cursor = 0usize;
    while cursor + 12 <= segment.len() {
        let name_size = reader.u32_at(cursor)? as usize;
        let desc_size = reader.u32_at(cursor + 4)? as usize;
        let note_type = reader.u32_at(cursor + 8)?;
        cursor += 12;

        let name_end = cursor.checked_add(name_size)?;
        let name = segment.get(cursor..name_end.min(segment.len()))?;
        cursor = cursor.checked_add(align4(name_size)?)?;

        let desc_end = cursor.checked_add(desc_size)?;
        let Some(desc) = segment.get(cursor..desc_end.min(segment.len())) else {
            return None;
        };
        cursor = cursor.checked_add(align4(desc_size)?)?;

        let owner = name.split(|&b| b == 0).next().unwrap_or_default();
        if note_type == NOTE_TYPE_PACKAGE && owner == NOTE_OWNER {
            let json = desc.split(|&b| b == 0).next().unwrap_or_default();
            let parsed: PackageNote = serde_json::from_slice(json).ok()?;
            if parsed.name.trim().is_empty() {
                return None;
            }
            return Some(parsed);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 64-bit little-endian ELF carrying one PT_NOTE segment.
    fn elf_with_note(owner: &[u8], note_type: u32, payload: &[u8]) -> Vec<u8> {
        let mut note = Vec::new();
        let mut owner_field = owner.to_vec();
        owner_field.push(0);
        note.extend_from_slice(&(owner_field.len() as u32).to_le_bytes());
        note.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        note.extend_from_slice(&note_type.to_le_bytes());
        note.extend_from_slice(&owner_field);
        while note.len() % 4 != 0 {
            note.push(0);
        }
        note.extend_from_slice(payload);
        while note.len() % 4 != 0 {
            note.push(0);
        }

        let phoff = 0x40usize;
        let phentsize = 56usize;
        let note_offset = phoff + phentsize;

        let mut elf = vec![0u8; note_offset];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // 64-bit
        elf[5] = 1; // little-endian
        elf[0x20..0x28].copy_from_slice(&(phoff as u64).to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&(phentsize as u16).to_le_bytes());
        elf[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());

        elf[phoff..phoff + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
        elf[phoff + 0x08..phoff + 0x10].copy_from_slice(&(note_offset as u64).to_le_bytes());
        elf[phoff + 0x20..phoff + 0x28].copy_from_slice(&(note.len() as u64).to_le_bytes());

        elf.extend_from_slice(&note);
        elf
    }

    const REAL_PAYLOAD: &[u8] = br#"{"type":"deb","os":"Debian","name":"libzstd","version":"1.5.7+dfsg-1","architecture":"arm64","debugInfoUrl":"https://debuginfod.debian.net"}"#;

    #[test]
    fn a_package_note_is_read_from_an_elf() {
        // The payload is the exact note found in Debian's libzstd.so.1.5.7,
        // which is a library that carries no version string at all.
        let elf = elf_with_note(b"FDO", NOTE_TYPE_PACKAGE, REAL_PAYLOAD);
        let note = read(&elf).expect("note is present");
        assert_eq!(note.name, "libzstd");
        assert_eq!(note.version, "1.5.7+dfsg-1");
        assert_eq!(note.kind, "deb");
    }

    #[test]
    fn notes_from_other_owners_are_ignored() {
        // Every ELF has GNU build-id notes. Reading one as package metadata
        // would attribute a random hash to a component name.
        let elf = elf_with_note(b"GNU", 3, b"\x01\x02\x03\x04");
        assert_eq!(read(&elf), None);
    }

    #[test]
    fn a_matching_owner_with_the_wrong_type_is_ignored() {
        let elf = elf_with_note(b"FDO", 1, REAL_PAYLOAD);
        assert_eq!(read(&elf), None);
    }

    #[test]
    fn a_truncated_elf_yields_nothing_rather_than_panicking() {
        // Firmware images are untrusted input; a malformed header must not be
        // able to stop a scan.
        let elf = elf_with_note(b"FDO", NOTE_TYPE_PACKAGE, REAL_PAYLOAD);
        for cut in [4, 8, 0x20, 0x40, 0x50, elf.len() - 1] {
            let _ = read(&elf[..cut.min(elf.len())]);
        }
    }

    #[test]
    fn a_header_claiming_an_absurd_note_size_is_survivable() {
        let mut elf = elf_with_note(b"FDO", NOTE_TYPE_PACKAGE, REAL_PAYLOAD);
        let phoff = 0x40;
        elf[phoff + 0x20..phoff + 0x28].copy_from_slice(&u64::MAX.to_le_bytes());
        let _ = read(&elf);
    }

    #[test]
    fn a_non_elf_file_is_not_examined() {
        assert_eq!(read(b"MZ\x90\x00 not an elf"), None);
        assert_eq!(read(b""), None);
    }

    #[test]
    fn the_distribution_packaging_is_stripped_from_the_version() {
        // Advisory feeds key on the upstream number. Leaving Debian's epoch and
        // revision attached is why the same component reported by two scanners
        // fails to merge into one row.
        assert_eq!(upstream_version("1.5.7+dfsg-1"), "1.5.7");
        assert_eq!(upstream_version("1:8.14.1-2+deb13u4"), "8.14.1");
        assert_eq!(upstream_version("3.5.6-1~deb13u2"), "3.5.6");
        assert_eq!(upstream_version("2.44-3"), "2.44");
        assert_eq!(upstream_version("1:11.8.6-0+deb13u1"), "11.8.6");
    }

    #[test]
    fn a_plain_upstream_version_survives_stripping_unchanged() {
        assert_eq!(upstream_version("3.0.2"), "3.0.2");
        assert_eq!(upstream_version("1.38.0"), "1.38.0");
    }
}
