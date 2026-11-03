//! Go build information embedded in compiled binaries.
//!
//! Every Go binary since 1.18 carries a build-info blob: a 32-byte header
//! starting with the magic `\xff Go buildinf:`, a pointer-size byte and a
//! flags byte, then (when `flags & 2`) two length-prefixed strings inline —
//! the Go version that built it (`go1.21.3`) and the module information:
//! `path`, `mod`, `dep` and `=>` (replacement) lines, wrapped in 16-byte
//! sentinels. That is the exact standard library and module set the program
//! was linked with, which a go.mod can only approximate.
//!
//! Pre-1.18 binaries store pointers into the data segment instead; following
//! them needs the executable's section table, so they are reported, not read.
//! Everything here is untrusted image content: lengths are checked before
//! anything is allocated, and nothing panics.

const MAGIC: &[u8] = b"\xff Go buildinf:";
const HEADER_LEN: usize = 32;
const FLAG_INLINE_STRINGS: u8 = 0x2;
/// Cap on module lines read from one binary.
pub const MAX_DEPS: usize = 10_000;
/// Longest Go version string accepted (`go1.25.3 X:boringcrypto` and the
/// like are far shorter).
const MAX_VERSION_BYTES: usize = 128;
/// Largest version or module-information string read.
const MAX_STRING_BYTES: usize = 4 * 1024 * 1024;

/// What one binary's build information says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoBuildInfo {
    /// The Go version as written: `go1.21.3`, `devel go1.23-abc`.
    pub go_version: String,
    /// The main module `(path, version)`; version is often `(devel)`.
    pub main: Option<(String, String)>,
    /// Linked modules `(path, version)`, replacements applied.
    pub deps: Vec<(String, String)>,
    /// The dependency list stopped at [`MAX_DEPS`].
    pub truncated: bool,
}

/// Read the build information of a binary. `Ok(None)` when it has none (not
/// a Go binary); `Err` names why one could not be read.
pub fn read(bytes: &[u8]) -> Result<Option<GoBuildInfo>, &'static str> {
    // The magic can also appear as plain data — a Go string constant in
    // rodata ahead of the real blob, or inside any other binary — so a match
    // counts only if it looks like the linker's header: 16-byte aligned, a 4-
    // or 8-byte pointer size, known flag bits, and a version naming Go.
    let mut search = 0;
    let (version, mut modinfo) = loop {
        let Some(found) = bytes
            .get(search..)
            .and_then(|rest| memchr::memmem::find(rest, MAGIC))
        else {
            return Ok(None);
        };
        let start = search + found;
        search = start + 1;
        let Some(header) = bytes.get(start..start + HEADER_LEN) else {
            continue;
        };
        let (pointer_size, flags) = (header[MAGIC.len()], header[MAGIC.len() + 1]);
        if start % 16 != 0 || !matches!(pointer_size, 4 | 8) || flags & !0x3 != 0 {
            continue;
        }
        if flags & FLAG_INLINE_STRINGS == 0 {
            return Err("pre-1.18 Go binary; build info not read");
        }
        let mut at = start + HEADER_LEN;
        let Ok(version) = inline_string(bytes, &mut at) else {
            continue;
        };
        if version.len() > MAX_VERSION_BYTES
            || !(version.starts_with(b"go") || version.starts_with(b"devel"))
        {
            continue;
        }
        break (version, inline_string(bytes, &mut at)?);
    };
    // The linker wraps module information in 16-byte sentinels.
    // The linker wraps module information in 16-byte sentinels; anything
    // else is not trusted as module information (as Go's own reader does).
    modinfo = if modinfo.len() >= 33 && modinfo[modinfo.len() - 17] == b'\n' {
        &modinfo[16..modinfo.len() - 16]
    } else {
        &[]
    };
    let version = std::str::from_utf8(version).map_err(|_| "Go version is not UTF-8")?;
    let modinfo = std::str::from_utf8(modinfo).map_err(|_| "Go module information is not UTF-8")?;

    let mut info = GoBuildInfo {
        go_version: version.to_string(),
        ..Default::default()
    };
    // `=>` replaces the dependency on the line before it.
    let mut pending: Option<(String, String)> = None;
    let push = |info: &mut GoBuildInfo, dep: Option<(String, String)>| {
        let Some((path, version)) = dep else { return };
        if version == "(devel)" || version.is_empty() {
            return;
        }
        if info.deps.len() >= MAX_DEPS {
            info.truncated = true;
            return;
        }
        info.deps.push((path, version));
    };
    for line in modinfo.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["mod", path, version, ..] => info.main = Some((path.to_string(), version.to_string())),
            ["dep", path, version, ..] => {
                push(&mut info, pending.take());
                pending = Some((path.to_string(), version.to_string()));
            }
            ["=>", path, version, ..] if pending.is_some() => {
                pending = Some((path.to_string(), version.to_string()));
            }
            _ => {}
        }
    }
    push(&mut info, pending.take());
    Ok(Some(info))
}

/// One varint-length-prefixed string at `*at`, advancing past it.
fn inline_string<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a [u8], &'static str> {
    // Accumulate in u64, as Go's `binary.Uvarint` does: at most ten bytes,
    // the tenth no larger than 1, so no bit is ever shifted out.
    let mut length: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*at).ok_or("Go build info is truncated")?;
        *at += 1;
        if shift == 63 && byte > 1 {
            return Err("Go build info length does not terminate");
        }
        length |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err("Go build info length does not terminate");
        }
    }
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length <= MAX_STRING_BYTES)
        .ok_or("Go build info string is larger than the cap")?;
    let end = at.checked_add(length).ok_or("Go build info is truncated")?;
    let value = bytes.get(*at..end).ok_or("Go build info is truncated")?;
    *at = end;
    Ok(value)
}

fn varint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// A build-info blob for `version` and `modinfo`, padded the way the
/// linker leaves it inside surrounding data. Test support for the image
/// scanner, which has to build Go binaries to exercise reading them.
#[doc(hidden)]
pub fn encode_for_tests(version: &str, modinfo: &str) -> Vec<u8> {
    // An ELF-looking 16-byte prefix keeps the blob 16-byte aligned, as the
    // Go linker places it.
    let mut out = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
    out.extend_from_slice(MAGIC);
    out.push(8); // pointer size
    out.push(FLAG_INLINE_STRINGS);
    out.resize(out.len() + (HEADER_LEN - MAGIC.len() - 2), 0);
    varint(version.len(), &mut out);
    out.extend_from_slice(version.as_bytes());
    let sentinel_start = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6";
    let sentinel_end = b"\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2";
    let mut wrapped = sentinel_start.to_vec();
    wrapped.extend_from_slice(modinfo.as_bytes());
    wrapped.extend_from_slice(sentinel_end);
    varint(wrapped.len(), &mut out);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(b"\x00trailing data");
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use super::encode_for_tests as blob;

    const MODINFO: &str = "path\texample.com/app\nmod\texample.com/app\t(devel)\t\ndep\tgolang.org/x/net\tv0.17.0\th1:abc=\ndep\tgithub.com/old/thing\tv1.0.0\th1:def=\n=>\tgithub.com/fork/thing\tv1.0.1\th1:ghi=\nbuild\t-compiler=gc\n";

    #[test]
    fn reads_the_go_version_and_modules() {
        let info = read(&blob("go1.22.4", MODINFO))
            .expect("readable")
            .expect("a Go binary");
        assert_eq!(info.go_version, "go1.22.4");
        assert_eq!(
            info.main,
            Some(("example.com/app".into(), "(devel)".into()))
        );
        assert_eq!(
            info.deps,
            [
                ("golang.org/x/net".to_string(), "v0.17.0".to_string()),
                ("github.com/fork/thing".to_string(), "v1.0.1".to_string()),
            ]
        );
        assert!(!info.truncated);
    }

    #[test]
    fn devel_versions_are_skipped() {
        let info = read(&blob(
            "go1.22.4",
            "path\tx\nmod\tx\t(devel)\t\ndep\tlocal.dev/tool\t(devel)\t\ndep\tgolang.org/x/text\tv0.14.0\th1:x=\n",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            info.deps,
            [("golang.org/x/text".to_string(), "v0.14.0".to_string())]
        );
    }

    #[test]
    fn non_go_files_have_no_build_info() {
        assert_eq!(read(b"\x7fELF\x02\x01\x01 plain binary"), Ok(None));
        assert_eq!(read(b""), Ok(None));
    }

    #[test]
    fn pre_1_18_pointer_format_is_a_reason_not_a_guess() {
        let mut old = blob("go1.16.15", MODINFO);
        let flags = old.windows(MAGIC.len()).position(|w| w == MAGIC).unwrap() + MAGIC.len() + 1;
        old[flags] = 0;
        assert_eq!(read(&old), Err("pre-1.18 Go binary; build info not read"));
    }

    #[test]
    fn oversized_varints_and_truncated_blobs_are_rejected() {
        let good = blob("go1.22.4", MODINFO);
        let start = good.windows(MAGIC.len()).position(|w| w == MAGIC).unwrap();
        // A length claiming far more than remains.
        let mut huge = good[..start + HEADER_LEN].to_vec();
        huge.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        huge.extend_from_slice(b"go1");
        // A header whose version cannot be read is not taken for build
        // information: no panic, no allocation of the claimed size.
        assert_eq!(read(&huge), Ok(None));
        // A varint that never terminates.
        let mut endless = good[..start + HEADER_LEN].to_vec();
        endless.extend_from_slice(&[0x80; 16]);
        assert_eq!(read(&endless), Ok(None));
        // Cut inside the module information, after a valid version.
        let cut = good.len() - 30;
        assert!(read(&good[..cut]).is_err());
        // Cut inside the header.
        assert_eq!(read(&good[..start + 20]), Ok(None));
    }

    #[test]
    fn a_magic_string_before_the_real_blob_is_skipped() {
        // A Go program can hold the magic as a string constant in rodata,
        // ahead of the real blob in the data segment; other binaries (this
        // scanner, for one) contain it too.
        let mut bytes = vec![0u8; 64];
        bytes[7..7 + MAGIC.len()].copy_from_slice(MAGIC); // unaligned
        bytes[32..32 + MAGIC.len()].copy_from_slice(MAGIC); // aligned, nonsense header
        bytes[32 + MAGIC.len()] = b'i';
        let real = blob("go1.22.4", MODINFO);
        bytes.extend_from_slice(&real);
        assert_eq!(read(&bytes).unwrap().unwrap().go_version, "go1.22.4");
    }

    #[test]
    fn a_non_go_file_containing_the_magic_has_no_build_info() {
        let mut bytes = vec![0u8; 32];
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&[8, FLAG_INLINE_STRINGS]);
        bytes.resize(32 + HEADER_LEN, 0);
        // A plausible header followed by text that is not a Go version.
        bytes.push(15);
        bytes.extend_from_slice(b"on is not UTF-8");
        bytes.push(0);
        assert_eq!(read(&bytes), Ok(None));
    }

    #[test]
    fn unframed_module_information_is_ignored() {
        // Go's own reader drops module information whose sentinel framing
        // does not check out, rather than parsing whatever is there.
        let mut bytes = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&[8, FLAG_INLINE_STRINGS]);
        bytes.resize(16 + HEADER_LEN, 0);
        let version = b"go1.22.4";
        varint(version.len(), &mut bytes);
        bytes.extend_from_slice(version);
        let unframed =
            b"path\tx\nmod\tx\tv1.0.0\t\ndep\tgolang.org/x/net\tv0.17.0\th1:a=\nxxxxxxxxxxxxxxxxxx";
        varint(unframed.len(), &mut bytes);
        bytes.extend_from_slice(unframed);
        let info = read(&bytes).unwrap().unwrap();
        assert_eq!(info.go_version, "go1.22.4");
        assert!(info.deps.is_empty(), "{:?}", info.deps);
        assert_eq!(info.main, None);
    }

    #[test]
    fn varints_never_overflow_the_accumulator() {
        let good = blob("go1.22.4", MODINFO);
        let start = good.windows(MAGIC.len()).position(|w| w == MAGIC).unwrap();
        let mut long = good[..start + HEADER_LEN].to_vec();
        long.extend_from_slice(&[0xff; 9]);
        long.push(0x01);
        assert_eq!(read(&long), Ok(None));
    }

    #[test]
    fn a_tenth_varint_byte_above_one_overflows() {
        // Ten bytes carry 64 bits only when the last is 0 or 1, as Go's
        // `binary.Uvarint` reads them; anything larger loses bits.
        let mut bytes = vec![0x80; 9];
        bytes.push(0x02);
        bytes.extend_from_slice(b"rest");
        assert!(inline_string(&bytes, &mut 0).is_err());
        let mut one = vec![0x80; 9];
        one.push(0x01);
        assert_eq!(
            inline_string(&one, &mut 0),
            Err("Go build info string is larger than the cap")
        );
    }

    #[test]
    fn only_the_first_magic_counts() {
        let mut two = blob("go1.22.4", MODINFO);
        two.extend_from_slice(&blob("go1.10.0", ""));
        assert_eq!(read(&two).unwrap().unwrap().go_version, "go1.22.4");
    }

    #[test]
    fn incompatible_suffixes_are_kept() {
        let info = read(&blob(
            "go1.22.4",
            "path\tx\nmod\tx\t(devel)\t\ndep\tgithub.com/docker/docker\tv24.0.7+incompatible\th1:x=\n",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            info.deps,
            [(
                "github.com/docker/docker".to_string(),
                "v24.0.7+incompatible".to_string()
            )]
        );
    }

    #[test]
    fn dependency_lists_are_capped() {
        let mut modinfo = String::from("path\tx\nmod\tx\t(devel)\t\n");
        for index in 0..MAX_DEPS + 5 {
            modinfo.push_str(&format!("dep\texample.com/m{index}\tv1.0.0\th1:x=\n"));
        }
        let info = read(&blob("go1.22.4", &modinfo)).unwrap().unwrap();
        assert_eq!(info.deps.len(), MAX_DEPS);
        assert!(info.truncated);
    }
}
