//! RPM package headers, as stored in an image's rpm database.
//!
//! Each installed package in `rpmdb.sqlite` (and in the older Berkeley DB
//! `Packages` file) is one header blob: a big-endian index count and data
//! length, then that many 16-byte index entries (`tag`, `type`, `offset`,
//! `count`), then the data they point into. Unlike a header inside an `.rpm`
//! file, a database blob carries no magic or reserved prefix.
//!
//! Only the identity tags are read. Everything here is untrusted image content,
//! so every offset is bounds-checked and a malformed header is an error, never
//! a panic.

const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_EPOCH: u32 = 1003;
const TAG_ARCH: u32 = 1022;
const TAG_SOURCERPM: u32 = 1044;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_I18NSTRING: u32 = 9;

/// Largest index a header may claim. Real packages carry around a hundred
/// tags; the cap keeps a crafted count from driving the walk.
pub const MAX_INDEX_ENTRIES: usize = 4096;
/// Longest identity string (name, version, release, arch, source RPM) read.
/// Real values are tens of bytes; the bound keeps one string from being
/// scanned for its terminator across the whole data section.
pub const MAX_IDENTITY_BYTES: usize = 4096;
/// Largest data section a header may claim.
pub const MAX_DATA_BYTES: usize = 16 * 1024 * 1024;

/// An installed package's identity, as its header declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmPackage {
    pub name: String,
    pub epoch: Option<u32>,
    pub version: String,
    pub release: String,
    pub arch: Option<String>,
    /// The source RPM it was built from: `openssl-3.0.7-27.el9.src.rpm`.
    pub source_rpm: Option<String>,
}

impl RpmPackage {
    /// `[epoch:]version-release`, the form rpm's own ordering compares. The
    /// epoch appears only when the header sets one.
    pub fn evr(&self) -> String {
        match self.epoch {
            Some(epoch) => format!("{epoch}:{}-{}", self.version, self.release),
            None => format!("{}-{}", self.version, self.release),
        }
    }

    /// The source package name: the source RPM file name without its
    /// `.src.rpm` suffix and its last two `-` fields (version and release).
    pub fn source_name(&self) -> Option<String> {
        let file = self.source_rpm.as_deref()?;
        let stem = file
            .strip_suffix(".src.rpm")
            .or_else(|| file.strip_suffix(".nosrc.rpm"))?;
        let mut parts = stem.rsplitn(3, '-');
        let (_release, _version, name) = (parts.next()?, parts.next()?, parts.next()?);
        (!name.is_empty()).then(|| name.to_string())
    }
}

/// Decode one header blob.
pub fn parse_header_blob(blob: &[u8]) -> Result<RpmPackage, &'static str> {
    let entries = be_u32(blob, 0).ok_or("rpm header is shorter than its counts")? as usize;
    let data_len = be_u32(blob, 4).ok_or("rpm header is shorter than its counts")? as usize;
    if entries == 0 || entries > MAX_INDEX_ENTRIES {
        return Err("rpm header index count is out of range");
    }
    if data_len > MAX_DATA_BYTES {
        return Err("rpm header data section is out of range");
    }
    let index_end = 8 + entries * 16;
    let data = index_end
        .checked_add(data_len)
        .and_then(|end| blob.get(index_end..end))
        .ok_or("rpm header is shorter than its index and data claim")?;

    let mut package = RpmPackage {
        name: String::new(),
        epoch: None,
        version: String::new(),
        release: String::new(),
        arch: None,
        source_rpm: None,
    };
    let mut seen = [false; 6];
    for entry in 0..entries {
        let at = 8 + entry * 16;
        let field = |n: usize| be_u32(blob, at + n * 4).ok_or("rpm header index is truncated");
        let (tag, kind, offset) = (field(0)?, field(1)?, field(2)? as usize);
        // Each identity tag appears once in a real header; repeats would
        // only make decoding rescan the data.
        let slot = match tag {
            TAG_NAME => Some(0),
            TAG_VERSION => Some(1),
            TAG_RELEASE => Some(2),
            TAG_EPOCH => Some(3),
            TAG_ARCH => Some(4),
            TAG_SOURCERPM => Some(5),
            _ => None,
        };
        if let Some(slot) = slot {
            if std::mem::replace(&mut seen[slot], true) {
                return Err("rpm header repeats an identity tag");
            }
        }
        match tag {
            TAG_NAME | TAG_VERSION | TAG_RELEASE | TAG_ARCH | TAG_SOURCERPM => {
                if kind != TYPE_STRING && kind != TYPE_I18NSTRING {
                    return Err("rpm header identity tag is not a string");
                }
                let text = string_at(data, offset)?;
                match tag {
                    TAG_NAME => package.name = text,
                    TAG_VERSION => package.version = text,
                    TAG_RELEASE => package.release = text,
                    TAG_ARCH => package.arch = Some(text),
                    _ => package.source_rpm = Some(text),
                }
            }
            TAG_EPOCH => {
                if kind != TYPE_INT32 {
                    return Err("rpm header epoch is not an integer");
                }
                package.epoch = Some(be_u32(data, offset).ok_or("rpm header epoch is truncated")?);
            }
            _ => {}
        }
    }
    if package.name.is_empty() || package.version.is_empty() || package.release.is_empty() {
        return Err("rpm header lacks a name, version or release");
    }
    Ok(package)
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_be_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// A NUL-terminated UTF-8 string starting at `offset` inside the data, at
/// most [`MAX_IDENTITY_BYTES`] long.
fn string_at(data: &[u8], offset: usize) -> Result<String, &'static str> {
    let rest = data
        .get(offset..)
        .ok_or("rpm header string offset is out of range")?;
    let window = &rest[..rest.len().min(MAX_IDENTITY_BYTES + 1)];
    let end = window
        .iter()
        .position(|&byte| byte == 0)
        .ok_or("rpm header string is not terminated within the identity bound")?;
    std::str::from_utf8(&rest[..end])
        .map(str::to_string)
        .map_err(|_| "rpm header string is not UTF-8")
}

/// Encode a package as a database-style header blob. Test support for the
/// image scanner, which has to build rpm databases to exercise reading them.
#[doc(hidden)]
pub fn encode_header_blob(package: &RpmPackage) -> Vec<u8> {
    let mut strings: Vec<(u32, &str)> = vec![
        (TAG_NAME, &package.name),
        (TAG_VERSION, &package.version),
        (TAG_RELEASE, &package.release),
    ];
    if let Some(arch) = &package.arch {
        strings.push((TAG_ARCH, arch));
    }
    if let Some(source) = &package.source_rpm {
        strings.push((TAG_SOURCERPM, source));
    }
    let mut index = Vec::new();
    let mut data = Vec::new();
    let mut entry = |tag: u32, kind: u32, offset: usize| {
        for field in [tag, kind, offset as u32, 1] {
            index.extend_from_slice(&field.to_be_bytes());
        }
    };
    for (tag, text) in strings {
        entry(tag, TYPE_STRING, data.len());
        data.extend_from_slice(text.as_bytes());
        data.push(0);
    }
    if let Some(epoch) = package.epoch {
        entry(TAG_EPOCH, TYPE_INT32, data.len());
        data.extend_from_slice(&epoch.to_be_bytes());
    }
    let count = index.len() / 16;
    let mut blob = Vec::new();
    blob.extend_from_slice(&(count as u32).to_be_bytes());
    blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
    blob.extend_from_slice(&index);
    blob.extend_from_slice(&data);
    blob
}

#[cfg(test)]
mod tests {
    use super::*;

    enum Value<'a> {
        Str(&'a str),
        Int(u32),
    }

    /// A database-style header blob holding the given tags, in order.
    fn header(tags: &[(u32, Value)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for (tag, value) in tags {
            let offset = data.len() as u32;
            let (kind, count) = match value {
                Value::Str(text) => {
                    data.extend_from_slice(text.as_bytes());
                    data.push(0);
                    (TYPE_STRING, 1u32)
                }
                Value::Int(number) => {
                    data.extend_from_slice(&number.to_be_bytes());
                    (TYPE_INT32, 1u32)
                }
            };
            for field in [*tag, kind, offset, count] {
                index.extend_from_slice(&field.to_be_bytes());
            }
        }
        let mut blob = Vec::new();
        blob.extend_from_slice(&(tags.len() as u32).to_be_bytes());
        blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
        blob.extend_from_slice(&index);
        blob.extend_from_slice(&data);
        blob
    }

    fn openssl_libs(epoch: Option<u32>) -> Vec<u8> {
        let mut tags = vec![
            // An unrelated tag first, as real headers lead with region tags.
            (
                1004,
                Value::Str("Utilities from the general purpose cryptography library"),
            ),
            (TAG_NAME, Value::Str("openssl-libs")),
            (TAG_VERSION, Value::Str("3.0.7")),
            (TAG_RELEASE, Value::Str("27.el9")),
            (TAG_ARCH, Value::Str("x86_64")),
            (TAG_SOURCERPM, Value::Str("openssl-3.0.7-27.el9.src.rpm")),
        ];
        if let Some(epoch) = epoch {
            tags.push((TAG_EPOCH, Value::Int(epoch)));
        }
        header(&tags)
    }

    #[test]
    fn decodes_name_epoch_version_release_and_source() {
        let package = parse_header_blob(&openssl_libs(Some(1))).expect("header");
        assert_eq!(
            package,
            RpmPackage {
                name: "openssl-libs".into(),
                epoch: Some(1),
                version: "3.0.7".into(),
                release: "27.el9".into(),
                arch: Some("x86_64".into()),
                source_rpm: Some("openssl-3.0.7-27.el9.src.rpm".into()),
            }
        );
        assert_eq!(package.source_name().as_deref(), Some("openssl"));
    }

    #[test]
    fn encoded_headers_round_trip() {
        let package = parse_header_blob(&openssl_libs(Some(1))).expect("header");
        assert_eq!(
            parse_header_blob(&encode_header_blob(&package)),
            Ok(package)
        );
    }

    #[test]
    fn evr_omits_a_missing_epoch() {
        let without = parse_header_blob(&openssl_libs(None)).expect("header");
        assert_eq!(without.evr(), "3.0.7-27.el9");
        let with = parse_header_blob(&openssl_libs(Some(1))).expect("header");
        assert_eq!(with.evr(), "1:3.0.7-27.el9");
    }

    #[test]
    fn source_names_strip_version_release_and_suffix() {
        let named = |file: &str| {
            RpmPackage {
                name: String::new(),
                epoch: None,
                version: String::new(),
                release: String::new(),
                arch: None,
                source_rpm: Some(file.into()),
            }
            .source_name()
        };
        assert_eq!(
            named("openssl-3.0.7-27.el9.src.rpm").as_deref(),
            Some("openssl")
        );
        assert_eq!(
            named("python-urllib3-1.26.5-5.el9.noarch.src.rpm").as_deref(),
            Some("python-urllib3")
        );
        assert_eq!(
            named("glibc-2.34-100.el9.nosrc.rpm").as_deref(),
            Some("glibc")
        );
        assert_eq!(named("norelease.src.rpm"), None);
        assert_eq!(named("openssl-3.0.7-27.el9.rpm"), None);
    }

    #[test]
    fn a_header_without_name_version_or_release_is_an_error() {
        let blob = header(&[
            (TAG_NAME, Value::Str("bash")),
            (TAG_VERSION, Value::Str("5.1.8")),
        ]);
        assert!(parse_header_blob(&blob).is_err());
    }

    #[test]
    fn malformed_headers_are_errors_not_panics() {
        let good = openssl_libs(Some(1));
        assert!(parse_header_blob(&good).is_ok(), "intact before the damage");
        // Truncated anywhere: inside the counts, the index, or the data.
        for cut in [0, 3, 8, 20, good.len() - 1] {
            assert!(parse_header_blob(&good[..cut]).is_err(), "cut at {cut}");
        }
        // An index count far beyond the cap.
        let mut huge = good.clone();
        huge[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_header_blob(&huge).is_err());
        // A data length claiming more than the blob holds.
        let mut long = good.clone();
        long[4..8].copy_from_slice(&(MAX_DATA_BYTES as u32).to_be_bytes());
        assert!(parse_header_blob(&long).is_err());
        // The name entry's offset pointing past the data.
        let mut far = good.clone();
        let name_entry = 8 + 16;
        far[name_entry + 8..name_entry + 12].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
        assert!(parse_header_blob(&far).is_err());
        // A string with no terminating NUL before the data ends.
        let mut open = header(&[
            (TAG_VERSION, Value::Str("1")),
            (TAG_RELEASE, Value::Str("1")),
            (TAG_NAME, Value::Str("unterminated")),
        ]);
        assert!(parse_header_blob(&open).is_ok(), "intact before the cut");
        open.pop();
        let data_len = u32::from_be_bytes(open[4..8].try_into().unwrap()) - 1;
        open[4..8].copy_from_slice(&data_len.to_be_bytes());
        assert!(parse_header_blob(&open).is_err());
        // An epoch entry whose four bytes run off the end.
        let mut short = header(&[
            (TAG_NAME, Value::Str("a")),
            (TAG_VERSION, Value::Str("1")),
            (TAG_RELEASE, Value::Str("1")),
            (TAG_EPOCH, Value::Int(2)),
        ]);
        assert!(parse_header_blob(&short).is_ok(), "intact before the cut");
        short.truncate(short.len() - 2);
        let data_len = u32::from_be_bytes(short[4..8].try_into().unwrap()) - 2;
        short[4..8].copy_from_slice(&data_len.to_be_bytes());
        assert!(parse_header_blob(&short).is_err());
    }

    #[test]
    fn repeated_identity_tags_are_refused() {
        // Thousands of NAME entries over one huge string would make decoding
        // rescan it once per entry.
        let mut tags: Vec<(u32, Value)> = vec![
            (TAG_VERSION, Value::Str("1")),
            (TAG_RELEASE, Value::Str("1")),
        ];
        for _ in 0..3 {
            tags.push((TAG_NAME, Value::Str("again")));
        }
        assert!(parse_header_blob(&header(&tags)).is_err());
    }

    #[test]
    fn identity_strings_longer_than_the_window_are_refused() {
        let long = "x".repeat(MAX_IDENTITY_BYTES + 1);
        let blob = header(&[
            (TAG_NAME, Value::Str(&long)),
            (TAG_VERSION, Value::Str("1")),
            (TAG_RELEASE, Value::Str("1")),
        ]);
        assert!(parse_header_blob(&blob).is_err());
        let fits = "x".repeat(MAX_IDENTITY_BYTES);
        let blob = header(&[
            (TAG_NAME, Value::Str(&fits)),
            (TAG_VERSION, Value::Str("1")),
            (TAG_RELEASE, Value::Str("1")),
        ]);
        assert!(parse_header_blob(&blob).is_ok());
    }

    #[test]
    fn non_utf8_strings_are_errors() {
        let mut blob = header(&[
            (TAG_NAME, Value::Str("ab")),
            (TAG_VERSION, Value::Str("1")),
            (TAG_RELEASE, Value::Str("1")),
        ]);
        assert!(parse_header_blob(&blob).is_ok(), "intact before the change");
        let data_start = 8 + 3 * 16;
        blob[data_start] = 0xff;
        assert!(parse_header_blob(&blob).is_err());
    }
}
