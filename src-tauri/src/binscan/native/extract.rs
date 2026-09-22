//! Bounded in-memory archive extraction.
//!
//! "oxAudit does not extract filesystems or archives" used to be the honest
//! one-line summary of this scanner's biggest gap: a vendor firmware image or
//! a saved container image is one opaque file, and the components inside its
//! squashfs or layer tars are invisible to string signatures. This module is
//! that gap closed — in memory, on a budget, without ever executing or
//! writing what it unpacks.
//!
//! What runs here and what deliberately does not:
//!
//! - **Magic-detected formats**: tar (and therefore anything wrapped around
//!   one — `.tar.gz`, `.tar.xz`, `.tar.zst`, `.tar.bz2`), zip, gzip, xz,
//!   zstd, bzip2, `ar` — which makes `.deb` packages and `.a` static
//!   libraries readable — RPM packages (lead, headers, compressed cpio
//!   payload, hand-parsed), and squashfs v4 through the maintained,
//!   fuzzed `backhand` reader, including filesystems embedded in raw
//!   firmware blobs at erase-block alignment. A saved `docker`/OCI image
//!   is a tar of layer tars, so nesting handles it with no image-specific
//!   code at all.
//! - **In memory, never on disk.** Members are scanned from buffers and
//!   dropped; extraction writes nothing, so an archive cannot drop files
//!   anywhere, and symlinks/devices/special modes are never honored — they
//!   are skipped, not recreated.
//! - **Budgets everywhere.** Depth, member count, per-member bytes, and
//!   total expanded bytes are all capped. A ten-kilobyte gzip that expands
//!   to gigabytes (the classic zip bomb, and a real attack on scanners)
//!   stops at the budget with a reported reason; findings already collected
//!   survive.
//! - **Not all of binwalk.** Squashfs v4 is unpacked through a reader with
//!   its own fuzzing story; a raw firmware blob additionally gets a
//!   bounded, 4 KiB-aligned magic search for embedded squashfs within the
//!   first 256 MiB. CramFS, UBI, and the long tail of vendor filesystems
//!   are still *not* unpacked — each needs its own vetted reader, and
//!   pretending otherwise would be the exact kind of silent gap this
//!   module exists to eliminate. Squashfs v3 (pre-2009) parses or yields
//!   nothing; the blob then scans raw, as before.

use std::io::Read;

use super::filetype::{archive_kind, ArchiveKind};
use super::strings::MAX_FILE_BYTES;

/// How much extraction is allowed to do. Every field is a hard stop whose
/// trip is reported, never silently truncating.
pub struct ExtractBudget {
    /// Levels of container nesting to open. Three covers a saved container
    /// image (image tar → layer tar → file) with a level to spare; deeper
    /// nests in the wild are almost always adversarial.
    pub max_depth: usize,
    /// Distinct members pulled out across the whole scan of one container.
    pub max_entries: usize,
    /// Largest single member kept, matching the per-file read cap.
    pub max_entry_bytes: u64,
    /// Total expanded bytes across every member and level. The decompression
    /// bomb stop.
    pub max_total_bytes: u64,
}

impl Default for ExtractBudget {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_entries: 20_000,
            max_entry_bytes: MAX_FILE_BYTES as u64,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}

/// What one extraction actually did, for the notes a scan reports.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExtractStats {
    /// Members successfully pulled out.
    pub entries: usize,
    /// Members skipped for exceeding the per-entry cap.
    pub skipped_oversized: usize,
    /// Members skipped for being markers rather than content: directories,
    /// symlinks, devices, container whiteouts.
    pub skipped_markers: usize,
    /// Set when a budget stopped extraction early. Members already pulled
    /// out remain valid; absence beyond the stop is not evidence of anything.
    pub stopped: Option<String>,
}

impl ExtractStats {
    /// One user-facing line, or `None` when nothing was extracted at all.
    pub fn note(&self, container: &str) -> Option<String> {
        if self.entries == 0 && self.stopped.is_none() {
            return None;
        }
        let mut note = format!(
            "{}: extracted {} member(s) in memory",
            container, self.entries
        );
        if self.skipped_oversized > 0 {
            note.push_str(&format!(
                ", skipped {} over the per-member cap",
                self.skipped_oversized
            ));
        }
        if self.skipped_markers > 0 {
            note.push_str(&format!(
                ", skipped {} markers (directories, links, whiteouts)",
                self.skipped_markers
            ));
        }
        if let Some(reason) = &self.stopped {
            note.push_str(&format!(", stopped early: {reason}"));
        }
        Some(note)
    }
}

/// One extracted member: its path inside the container (POSIX-style, `/`
/// separated, no leading `/`) and its bytes.
pub struct ExtractedMember {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// The outcome of opening one container.
pub struct Extracted {
    pub members: Vec<ExtractedMember>,
    pub stats: ExtractStats,
}

/// Open `bytes` (classified as an archive) and pull out every scannable
/// member, up to the budget. Malformed input yields an empty result rather
/// than an error: an unreadable archive still scans as an opaque blob, which
/// is what the caller falls back to.
pub fn extract(name: &str, bytes: &[u8], budget: &ExtractBudget) -> Extracted {
    let mut out = Extracted {
        members: Vec::new(),
        stats: ExtractStats::default(),
    };
    let mut total = 0_u64;
    extract_into(name, bytes, 0, budget, &mut total, &mut out);
    out
}

fn extract_into(
    name: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extracted,
) {
    if depth >= budget.max_depth {
        // Only report the stop when there was something left to open.
        if archive_kind(bytes).is_some() {
            out.stats
                .stopped
                .get_or_insert_with(|| format!("nesting deeper than {}", budget.max_depth));
        }
        return;
    }
    // A decompression wrapper resolves to one member whose name is the
    // compressed name minus its extension; the payload then re-dispatches,
    // because a `.tar.gz` is a gzip around a tar. Every wrapper level counts
    // against the depth budget — a chain of gzip-around-gzip is adversarial
    // input, not a format to honor.
    match archive_kind(bytes) {
        Some(ArchiveKind::Gzip) => {
            if let Some(plain) = decompress(&mut flate2::read::GzDecoder::new(bytes), budget) {
                let plain_name = strip_archive_suffix(name);
                extract_into(&plain_name, &plain, depth + 1, budget, total, out);
            }
        }
        Some(ArchiveKind::Bzip2) => {
            if let Some(plain) = decompress(&mut bzip2::read::BzDecoder::new(bytes), budget) {
                let plain_name = strip_archive_suffix(name);
                extract_into(&plain_name, &plain, depth + 1, budget, total, out);
            }
        }
        Some(ArchiveKind::Xz) => {
            if let Some(plain) = decompress(&mut liblzma::read::XzDecoder::new(bytes), budget) {
                let plain_name = strip_archive_suffix(name);
                extract_into(&plain_name, &plain, depth + 1, budget, total, out);
            }
        }
        Some(ArchiveKind::Zstd) => {
            if let Ok(mut decoder) = zstd::stream::read::Decoder::new(bytes) {
                if let Some(plain) = decompress(&mut decoder, budget) {
                    let plain_name = strip_archive_suffix(name);
                    extract_into(&plain_name, &plain, depth + 1, budget, total, out);
                }
            }
        }
        Some(ArchiveKind::Tar) => extract_tar(name, bytes, depth, budget, total, out),
        Some(ArchiveKind::Zip) => extract_zip(name, bytes, depth, budget, total, out),
        Some(ArchiveKind::Ar) => extract_ar(name, bytes, depth, budget, total, out),
        Some(ArchiveKind::Rpm) => extract_rpm(name, bytes, depth, budget, total, out),
        Some(ArchiveKind::Squashfs) => {
            // backhand is the maintained, fuzzed reader for this format;
            // hand-rolling one was explicitly rejected when this module was
            // written. v4 images parse; v3 (pre-2009) and malformed images
            // yield nothing and the caller scans the blob raw.
            let cursor = std::io::Cursor::new(bytes);
            if let Ok(filesystem) = backhand::FilesystemReader::from_reader(cursor) {
                drain_squashfs(name, &filesystem, budget, total, out);
            }
        }
        None => {}
    }
}

/// Pull every file out of an opened squashfs. Non-file nodes (directories,
/// symlinks, devices) are counted as markers, as in every other container.
fn drain_squashfs(
    container: &str,
    filesystem: &backhand::FilesystemReader<'_>,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extracted,
) {
    for node in filesystem.files() {
        let backhand::InnerNode::File(file) = &node.inner else {
            out.stats.skipped_markers += 1;
            continue;
        };
        if budget_stop(budget, total, out) {
            return;
        }
        let raw = node.fullpath.to_string_lossy().into_owned();
        let Some(member) = member_path(&raw) else {
            out.stats.skipped_markers += 1;
            continue;
        };
        let mut reader = filesystem.file(file).reader();
        read_member(container, &member, &mut reader, 0, budget, total, out);
    }
}

/// How far into an opaque firmware blob the embedded-squashfs search reads.
const EMBEDDED_SCAN_WINDOW: usize = 256 * 1024 * 1024;
/// How many embedded filesystems one blob may contribute.
const MAX_EMBEDDED: usize = 4;
/// Embedded filesystems sit at partition/erase-block boundaries; this is the
/// alignment the magic search assumes.
const EMBEDDED_ALIGN: usize = 4096;

/// Parse an RPM by hand. The `rpm` crate hard-depends on a second native
/// lzma that conflicts with the one this scanner already links, and RPM is
/// structurally small: a 96-byte lead, two big-endian headers whose only
/// use here is being skipped, and a cpio payload compressed with one of the
/// codecs this module already carries. Red Hat's default payload compression
/// (xz) decompresses through the same `liblzma` the extractor links for
/// `.tar.xz`.
fn extract_rpm(
    container: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extracted,
) {
    let Some(payload) = rpm_payload(bytes) else {
        return;
    };
    // The payload's own magic says which codec; an unrecognized magic means
    // uncompressed cpio, which is what very old packages carry.
    let plain = match archive_kind(&payload[..payload.len().min(512)]) {
        Some(ArchiveKind::Gzip) => decompress(&mut flate2::read::GzDecoder::new(payload), budget),
        Some(ArchiveKind::Bzip2) => decompress(&mut bzip2::read::BzDecoder::new(payload), budget),
        Some(ArchiveKind::Xz) => decompress(&mut liblzma::read::XzDecoder::new(payload), budget),
        Some(ArchiveKind::Zstd) => {
            let Ok(mut decoder) = zstd::stream::read::Decoder::new(payload) else {
                return;
            };
            decompress(&mut decoder, budget)
        }
        _ => Some(payload.to_vec()),
    };
    let Some(cpio) = plain else {
        return;
    };
    extract_cpio(container, &cpio, depth, budget, total, out);
}

/// Skip the lead and both headers, returning the payload slice. A header is
/// a big-endian magic, an index count, a data size, the index, the data, and
/// padding to an 8-byte boundary.
fn rpm_payload(bytes: &[u8]) -> Option<&[u8]> {
    const LEAD: usize = 96;
    const HEADER_FIXED: usize = 16;
    const HEADER_MAGIC: [u8; 4] = [0x8e, 0xad, 0xe8, 0x01];
    let mut offset = LEAD;
    for _ in 0..2 {
        let fixed = bytes.get(offset..offset + HEADER_FIXED)?;
        if fixed[0..4] != HEADER_MAGIC {
            return None;
        }
        let entries = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]) as usize;
        let data = u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]) as usize;
        let header = HEADER_FIXED
            .checked_add(entries.checked_mul(16)?)?
            .checked_add(data)?;
        offset = offset
            .checked_add(header)?
            .checked_add((8 - header % 8) % 8)?;
    }
    bytes.get(offset..)
}

/// One parsed cpio entry: enough to locate content and advance.
struct CpioEntry {
    name: String,
    mode: u32,
    size: usize,
    data_start: usize,
    next_offset: usize,
}

/// Parse the `newc`-format entry at `offset`, or `None` at end/breakage.
fn cpio_entry_at(bytes: &[u8], offset: usize) -> Option<CpioEntry> {
    const ENTRY_FIXED: usize = 110;
    let fixed = bytes.get(offset..offset + ENTRY_FIXED)?;
    if &fixed[0..6] != b"070701" && &fixed[0..6] != b"070702" {
        return None;
    }
    let field = |index: usize| -> Option<u32> {
        let start = 6 + index * 8;
        let text = std::str::from_utf8(fixed.get(start..start + 8)?).ok()?;
        u32::from_str_radix(text, 16).ok()
    };
    let mode = field(1)?;
    let size = field(6)? as usize;
    let name_size = field(11)? as usize;
    let name_start = offset.checked_add(ENTRY_FIXED)?;
    let name_bytes = bytes.get(name_start..name_start.checked_add(name_size)?)?;
    let name =
        String::from_utf8_lossy(&name_bytes[..name_size.saturating_sub(1).min(name_bytes.len())])
            .into_owned();
    let data_start = name_start
        .checked_add(name_size)?
        .checked_add((4 - (ENTRY_FIXED + name_size) % 4) % 4)?;
    let data_end = data_start.checked_add(size)?;
    Some(CpioEntry {
        name,
        mode,
        size,
        data_start,
        next_offset: data_end.checked_add((4 - size % 4) % 4)?,
    })
}

/// Walk a `newc`-format cpio stream (the only payload format RPM uses).
fn extract_cpio(
    container: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extracted,
) {
    let mut offset = 0_usize;
    while let Some(entry) = cpio_entry_at(bytes, offset) {
        if entry.name == "TRAILER!!!" {
            return;
        }
        // Only regular files carry scannable content.
        if entry.mode & 0o170000 == 0o100000 && entry.size > 0 {
            if budget_stop(budget, total, out) {
                return;
            }
            if let Some(member) = member_path(&entry.name) {
                let data = bytes
                    .get(entry.data_start..entry.data_start + entry.size)
                    .unwrap_or(&[]);
                read_member_bytes(container, &member, data, depth, budget, total, out);
            } else {
                out.stats.skipped_markers += 1;
            }
        } else {
            out.stats.skipped_markers += 1;
        }
        offset = entry.next_offset;
    }
}

/// Look for squashfs embedded in a raw firmware blob — the vendor `.bin`
/// shape of header-plus-kernel-plus-filesystem.
///
/// This is deliberately the smallest useful slice of what binwalk does: one
/// magic, one alignment, one format, behind the same budgets as everything
/// else. A magic hit that fails to parse is skipped, not fatal; a blob with
/// no embedded filesystem returns nothing and the caller scans it raw.
pub fn extract_embedded_squashfs(name: &str, bytes: &[u8], budget: &ExtractBudget) -> Extracted {
    let mut out = Extracted {
        members: Vec::new(),
        stats: ExtractStats::default(),
    };
    let mut total = 0_u64;
    let scan_end = bytes.len().min(EMBEDDED_SCAN_WINDOW);
    let mut found = 0_usize;
    let mut offset = 0_usize;
    while offset + 4 <= scan_end && found < MAX_EMBEDDED {
        let magic = &bytes[offset..offset + 4];
        if magic == b"hsqs" || magic == b"sqsh" {
            let cursor = std::io::Cursor::new(&bytes[offset..]);
            if let Ok(filesystem) = backhand::FilesystemReader::from_reader(cursor) {
                found += 1;
                drain_squashfs(
                    &format!("{name}!sqfs@0x{offset:x}"),
                    &filesystem,
                    budget,
                    &mut total,
                    &mut out,
                );
            }
        }
        offset += EMBEDDED_ALIGN;
    }
    out
}

/// Decompress a single stream up to `max_entry_bytes + 1`, so an oversized
/// result is detected rather than read to exhaustion. `None` on malformed
/// input or an oversized payload.
fn decompress(reader: &mut dyn Read, budget: &ExtractBudget) -> Option<Vec<u8>> {
    let mut plain = Vec::new();
    let mut limited = reader.take(budget.max_entry_bytes + 1);
    // A decompression error after some output is still useful output, but
    // distinguishing the two invites half-files; treat both as unusable,
    // because a truncated member can misreport versions.
    limited.read_to_end(&mut plain).ok()?;
    if plain.len() as u64 > budget.max_entry_bytes {
        return None;
    }
    Some(plain)
}

fn extract_tar(
    container: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extracted,
) {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = tar::Archive::new(cursor);
    let Ok(entries) = archive.entries() else {
        return;
    };
    for entry in entries {
        let Ok(mut entry) = entry else {
            continue;
        };
        let header = entry.header();
        let entry_type = header.entry_type();
        if !entry_type.is_file() {
            out.stats.skipped_markers += 1;
            continue;
        }
        if budget_stop(budget, total, out) {
            return;
        }
        let Ok(path) = entry.path() else {
            continue;
        };
        let member = match member_path(&path.to_string_lossy()) {
            Some(member) => member,
            None => {
                out.stats.skipped_markers += 1;
                continue;
            }
        };
        read_member(container, &member, &mut entry, depth, budget, total, out);
    }
}

fn extract_zip(
    container: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extracted,
) {
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
        return;
    };
    for index in 0..archive.len() {
        let Ok(mut file) = archive.by_index(index) else {
            continue;
        };
        if file.is_dir() {
            out.stats.skipped_markers += 1;
            continue;
        }
        if budget_stop(budget, total, out) {
            return;
        }
        let member = match member_path(file.name()) {
            Some(member) => member,
            None => {
                out.stats.skipped_markers += 1;
                continue;
            }
        };
        read_member(container, &member, &mut file, depth, budget, total, out);
    }
}

/// Parse an `ar` archive by hand: the format is a global magic plus 60-byte
/// ASCII headers — small enough that hand-rolling beats a dependency, and it
/// keeps `.deb` and macOS `.a` support free of new supply chain.
///
/// GNU long names (`/N` referring into a `//` table) and BSD embedded names
/// (`#1/len`) are both handled, because `.deb` packages use the GNU form and
/// macOS static libraries use the BSD form.
fn extract_ar(
    container: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extracted,
) {
    const HEADER: usize = 60;
    if bytes.len() < 8 + HEADER {
        return;
    }
    let mut offset = 8; // "!<arch>\n"
    let mut long_names: Vec<u8> = Vec::new();
    while offset + HEADER <= bytes.len() {
        let header = &bytes[offset..offset + HEADER];
        let field = |range: std::ops::Range<usize>| {
            header[range]
                .iter()
                .map(|&b| b as char)
                .collect::<String>()
                .trim()
                .to_string()
        };
        let Ok(size) = field(48..58).parse::<usize>() else {
            return;
        };
        let raw_name = field(0..16);
        let mut name_len = 0_usize;
        let name = if let Some(embedded) = raw_name.strip_prefix("#1/") {
            // BSD: the real name follows the header, padded to a multiple
            // of four inside the declared size.
            let Ok(embedded) = embedded.parse::<usize>() else {
                return;
            };
            name_len = embedded;
            let start = offset + HEADER;
            let end = (start + embedded).min(bytes.len());
            String::from_utf8_lossy(&bytes[start..end])
                .trim_end_matches('\0')
                .to_string()
        } else if raw_name == "//" {
            // GNU: the long-name table.
            let start = offset + HEADER;
            let end = (start + size).min(bytes.len());
            long_names = bytes[start..end].to_vec();
            offset = next_ar_offset(offset, HEADER, size);
            continue;
        } else if raw_name == "/" || raw_name == "debian-binary" {
            offset = next_ar_offset(offset, HEADER, size);
            continue;
        } else if let Some(name) = raw_name
            .strip_suffix('/')
            .and_then(|stem| stem.strip_prefix('/'))
            .and_then(|reference| reference.parse::<usize>().ok())
            .and_then(|index| name_from_long_table(&long_names, index))
        {
            // GNU: `/N` names the Nth entry of the long-name table.
            name
        } else {
            raw_name.trim_end_matches('/').to_string()
        };
        let body = offset + HEADER + name_len;
        let end = body
            .saturating_add(size.saturating_sub(name_len))
            .min(bytes.len());
        if end > body {
            let member_name = name;
            if let Some(member) = member_path(&member_name) {
                read_member_bytes(
                    container,
                    &member,
                    &bytes[body..end],
                    depth,
                    budget,
                    total,
                    out,
                );
            } else {
                out.stats.skipped_markers += 1;
            }
        }
        offset = next_ar_offset(offset, HEADER, size);
    }
}

/// `ar` members start on two-byte boundaries.
fn next_ar_offset(offset: usize, header: usize, size: usize) -> usize {
    offset + header + size + (size & 1)
}

fn name_from_long_table(table: &[u8], index: usize) -> Option<String> {
    let start = table.get(index..)?;
    let end = start.iter().position(|&b| b == b'\n' || b == b'\0')?;
    Some(
        String::from_utf8_lossy(&start[..end])
            .trim_end_matches('/')
            .to_string(),
    )
}

/// Read one member through the shared budget path, then recurse: the member
/// may itself be a container (a layer tar inside an image tar).
fn read_member(
    container: &str,
    member: &str,
    reader: &mut dyn Read,
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extracted,
) {
    if out.members.len() >= budget.max_entries {
        out.stats
            .stopped
            .get_or_insert_with(|| format!("more than {} members", budget.max_entries));
        return;
    }
    let mut bytes = Vec::new();
    let mut limited = reader.take(budget.max_entry_bytes + 1);
    if limited.read_to_end(&mut bytes).is_err() {
        // An unreadable member is skipped; the container's other members
        // still count.
        return;
    }
    if bytes.len() as u64 > budget.max_entry_bytes {
        out.stats.skipped_oversized += 1;
        return;
    }
    read_member_bytes(container, member, &bytes, depth, budget, total, out);
}

/// Budget accounting plus push-or-recurse for one member's bytes.
fn read_member_bytes(
    container: &str,
    member: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extracted,
) {
    let length = bytes.len() as u64;
    if *total + length > budget.max_total_bytes {
        out.stats
            .stopped
            .get_or_insert_with(|| format!("expanded past {} bytes", budget.max_total_bytes));
        return;
    }
    *total += length;
    let leaf = !bytes.is_empty() && archive_kind(&bytes[..bytes.len().min(512)]).is_none();
    if leaf {
        out.stats.entries += 1;
        out.members.push(ExtractedMember {
            path: format!("{container}!/{member}"),
            bytes: bytes.to_vec(),
        });
    } else {
        // A nested container expands in place; its own members carry the
        // combined path. An empty member is dropped — nothing to scan.
        if !bytes.is_empty() {
            extract_into(
                &format!("{container}!/{member}"),
                bytes,
                depth + 1,
                budget,
                total,
                out,
            );
        }
    }
}

/// Stop before reading the next member once a budget is exhausted. Called at
/// iteration boundaries where there is nothing half-read to discard.
fn budget_stop(budget: &ExtractBudget, total: &mut u64, out: &mut Extracted) -> bool {
    if *total >= budget.max_total_bytes {
        out.stats
            .stopped
            .get_or_insert_with(|| format!("expanded past {} bytes", budget.max_total_bytes));
        return true;
    }
    if out.members.len() >= budget.max_entries {
        out.stats
            .stopped
            .get_or_insert_with(|| format!("more than {} members", budget.max_entries));
        return true;
    }
    false
}

/// Normalize a member path: no leading `/`, no `.` or `..` components, no
/// empty components. Paths are display-only (nothing is written to disk), but
/// a clean form keeps virtual paths readable and unambiguous.
fn member_path(raw: &str) -> Option<String> {
    let mut parts = Vec::new();
    for component in raw.split(['/', '\\']) {
        match component {
            "" | "." => continue,
            ".." => return None,
            component => parts.push(component),
        }
    }
    // Container-layer whiteouts (`AUFS`-style `.wh.` markers) describe
    // deletions, not content.
    if let Some(last) = parts.last() {
        if last.starts_with(".wh.") || *last == ".wh" {
            return None;
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

/// `rootfs.tar.gz` → `rootfs.tar`; `payload.xz` → `payload`. The name is
/// display-only — it exists so a decompressed single file has a sensible
/// virtual path rather than its compressed one.
fn strip_archive_suffix(name: &str) -> String {
    for pair in [
        (".tar.gz", ".tar"),
        (".tgz", ".tar"),
        (".tar.xz", ".tar"),
        (".txz", ".tar"),
        (".tar.zst", ".tar"),
        (".tar.bz2", ".tar"),
        (".tbz2", ".tar"),
        (".gz", ""),
        (".xz", ""),
        (".zst", ""),
        (".bz2", ""),
    ] {
        if let Some(stripped) = name.strip_suffix(pair.0) {
            return format!("{stripped}{}", pair.1);
        }
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A binary member carrying the banner a real busybox has — the same
    /// fixture shape the end-to-end scan tests use.
    fn busybox() -> Vec<u8> {
        let mut bytes = vec![0u8, 0, 0, 0];
        bytes.extend_from_slice(b"BusyBox is a multi-call binary\0BusyBox v1.38.0 (2026-05-13)\0");
        bytes
    }

    fn tar_with(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, name, bytes.as_slice())
                .expect("append tar member");
        }
        builder.into_inner().expect("tar bytes")
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    fn zip_with(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in members {
            writer
                .start_file(name.to_string(), zip::write::SimpleFileOptions::default())
                .expect("start zip member");
            std::io::Write::write_all(&mut writer, bytes).expect("zip write");
        }
        writer.finish().expect("zip finish").into_inner()
    }

    fn budget() -> ExtractBudget {
        ExtractBudget::default()
    }

    fn paths(extracted: &Extracted) -> Vec<&str> {
        extracted.members.iter().map(|m| m.path.as_str()).collect()
    }

    #[test]
    fn a_tar_members_are_extracted_with_virtual_paths() {
        let tar = tar_with(&[
            ("bin/busybox", busybox()),
            ("README.txt", b"just text\n".to_vec()),
        ]);
        let extracted = extract("fw.tar", &tar, &budget());
        assert_eq!(
            paths(&extracted),
            vec!["fw.tar!/bin/busybox", "fw.tar!/README.txt"]
        );
        assert_eq!(extracted.stats.entries, 2);
        assert_eq!(extracted.stats.stopped, None);
        // The member bytes round-trip.
        assert_eq!(extracted.members[0].bytes, busybox());
    }

    #[test]
    fn a_compressed_tar_finds_its_members() {
        let tar = tar_with(&[("bin/busybox", busybox())]);
        let gz = gzip(&tar);
        let extracted = extract("fw.tar.gz", &gz, &budget());
        assert_eq!(paths(&extracted), vec!["fw.tar!/bin/busybox"]);
        assert_eq!(extracted.stats.entries, 1);
    }

    #[test]
    fn an_xz_wrapped_tar_finds_its_members() {
        let tar = tar_with(&[("usr/sbin/dnsmasq", busybox())]);
        let mut encoder = liblzma::write::XzEncoder::new(Vec::new(), 6);
        std::io::Write::write_all(&mut encoder, &tar).expect("xz write");
        let xz = encoder.finish().expect("xz finish");
        let extracted = extract("rootfs.tar.xz", &xz, &budget());
        assert_eq!(paths(&extracted), vec!["rootfs.tar!/usr/sbin/dnsmasq"]);
    }

    #[test]
    fn a_zstd_wrapped_tar_finds_its_members() {
        let tar = tar_with(&[("bin/sh", busybox())]);
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).expect("zstd encoder");
        std::io::Write::write_all(&mut encoder, &tar).expect("zstd write");
        let zst = encoder.finish().expect("zstd finish");
        let extracted = extract("rootfs.tar.zst", &zst, &budget());
        assert_eq!(paths(&extracted), vec!["rootfs.tar!/bin/sh"]);
    }

    #[test]
    fn a_bzip2_wrapped_tar_finds_its_members() {
        let tar = tar_with(&[("bin/gzip", busybox())]);
        let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar).expect("bz2 write");
        let bz2 = encoder.finish().expect("bz2 finish");
        let extracted = extract("rootfs.tar.bz2", &bz2, &budget());
        assert_eq!(paths(&extracted), vec!["rootfs.tar!/bin/gzip"]);
    }

    #[test]
    fn a_saved_container_image_is_tar_all_the_way_down() {
        // A docker save / OCI image is a tar whose members include layer tars.
        // No image-specific code should be needed to read it.
        let layer = tar_with(&[
            ("bin/busybox", busybox()),
            ("etc/ssl/openssl.cnf", b"config\n\0".to_vec()),
        ]);
        let image = tar_with(&[
            ("manifest.json", b"{\"Layers\":[\"layer.tar\"]}\n".to_vec()),
            ("layer.tar", layer),
        ]);
        let extracted = extract("image.tar", &image, &budget());
        assert_eq!(
            paths(&extracted),
            vec![
                "image.tar!/manifest.json",
                "image.tar!/layer.tar!/bin/busybox",
                "image.tar!/layer.tar!/etc/ssl/openssl.cnf",
            ]
        );
    }

    #[test]
    fn a_zip_members_are_extracted() {
        let zip = zip_with(&[("opt/tool/busybox", busybox())]);
        let extracted = extract("dist.zip", &zip, &budget());
        assert_eq!(paths(&extracted), vec!["dist.zip!/opt/tool/busybox"]);
    }

    #[test]
    fn a_deb_is_an_ar_around_a_compressed_tar() {
        let data_tar = tar_with(&[("usr/lib/libz.so.1", busybox())]);
        let gz = gzip(&data_tar);
        // A .deb: ar members debian-binary, control.tar.gz, data.tar.gz.
        let mut deb = b"!<arch>\n".to_vec();
        let mut push = |name: &str, bytes: &[u8]| {
            let header = format!(
                "{name:<16}{0:<12}{0:<6}{0:<6}{0:<8}{1:<10}`\n",
                0,
                bytes.len()
            );
            deb.extend_from_slice(header.as_bytes());
            deb.extend_from_slice(bytes);
            if bytes.len() % 2 == 1 {
                deb.push(b'\n');
            }
        };
        push("debian-binary", b"2.0\n");
        push("data.tar.gz", &gz);
        let extracted = extract("pkg.deb", &deb, &budget());
        assert_eq!(
            paths(&extracted),
            vec!["pkg.deb!/data.tar!/usr/lib/libz.so.1"]
        );
    }

    #[test]
    fn directories_symlinks_and_whiteouts_are_not_content() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_cksum();
        builder
            .append_data(&mut header, "bin/sh", std::io::empty())
            .expect("symlink member");
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "bin/", std::io::empty())
            .expect("directory member");
        let tar = {
            let mut header = tar::Header::new_gnu();
            header.set_size(busybox().len() as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, "bin/.wh.realfile", busybox().as_slice())
                .expect("whiteout member");
            builder.into_inner().expect("tar bytes")
        };
        let extracted = extract("layer.tar", &tar, &budget());
        // The whiteout marker is a deletion record, not content — even though
        // it is a regular file carrying a recognizable binary.
        assert_eq!(paths(&extracted), Vec::<&str>::new());
        assert_eq!(extracted.stats.skipped_markers, 3);
    }

    #[test]
    fn nesting_deeper_than_the_budget_stops_with_a_reason() {
        // Three containers deep (outer → inner → inner → file) opens fully.
        let leaf = tar_with(&[("bin/busybox", busybox())]);
        let second = tar_with(&[("inner.tar", leaf)]);
        let first = tar_with(&[
            ("docs.txt", b"notes\n".to_vec()),
            ("inner.tar", second.clone()),
        ]);
        let extracted = extract("outer.tar", &first, &budget());
        assert_eq!(
            paths(&extracted),
            vec![
                "outer.tar!/docs.txt",
                "outer.tar!/inner.tar!/inner.tar!/bin/busybox",
            ]
        );
        assert_eq!(extracted.stats.stopped, None);

        // Four deep stops before the innermost container and says so; the
        // members already pulled out survive the stop.
        let third = tar_with(&[("inner.tar", second)]);
        let first = tar_with(&[("docs.txt", b"notes\n".to_vec()), ("inner.tar", third)]);
        let extracted = extract("outer.tar", &first, &budget());
        assert_eq!(paths(&extracted), vec!["outer.tar!/docs.txt"]);
        assert_eq!(
            extracted.stats.stopped.as_deref(),
            Some("nesting deeper than 3")
        );
    }

    #[test]
    fn an_expansion_bomb_stops_at_the_total_byte_budget() {
        // A small gzip that expands far past the budget: the classic attack
        // on scanners. Whatever fit is kept; the stop is reported.
        let tar = tar_with(&[
            ("a/one", vec![7u8; 4096]),
            ("b/two", vec![7u8; 4096]),
            ("c/three", vec![7u8; 4096]),
        ]);
        let gz = gzip(&tar);
        let mut small = budget();
        small.max_total_bytes = 5000;
        let extracted = extract("bomb.tar.gz", &gz, &small);
        assert!(!extracted.members.is_empty(), "what fit is kept");
        assert!(
            extracted
                .stats
                .stopped
                .as_deref()
                .is_some_and(|reason| reason.contains("expanded past")),
            "stop reason: {:?}",
            extracted.stats.stopped
        );
    }

    #[test]
    fn an_oversized_member_is_skipped_not_fatal() {
        let tar = tar_with(&[("huge.bin", vec![1u8; 512]), ("bin/busybox", busybox())]);
        let mut small = budget();
        small.max_entry_bytes = 256;
        let extracted = extract("fw.tar", &tar, &small);
        assert_eq!(paths(&extracted), vec!["fw.tar!/bin/busybox"]);
        assert_eq!(extracted.stats.skipped_oversized, 1);
    }

    #[test]
    fn the_member_count_budget_stops_extraction() {
        let members: Vec<(String, Vec<u8>)> = (0..6)
            .map(|index| (format!("m{index}"), busybox()))
            .collect();
        let refs: Vec<(&str, Vec<u8>)> = members
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.clone()))
            .collect();
        let tar = tar_with(&refs);
        let mut small = budget();
        small.max_entries = 3;
        let extracted = extract("many.tar", &tar, &small);
        assert_eq!(extracted.members.len(), 3);
        assert_eq!(
            extracted.stats.stopped.as_deref(),
            Some("more than 3 members")
        );
    }

    #[test]
    fn malformed_archives_yield_nothing_and_no_crash() {
        let garbage = [0x1fu8, 0x8b, 0x08, 0x00, 0xff, 0xff, 0xff];
        let extracted = extract("broken.gz", &garbage, &budget());
        assert_eq!(paths(&extracted), Vec::<&str>::new());
        assert_eq!(extracted.stats.entries, 0);

        let mut not_tar = vec![0u8; 600];
        not_tar[257..262].copy_from_slice(b"ustar");
        let extracted = extract("truncated.tar", &not_tar, &budget());
        assert!(paths(&extracted).is_empty());
    }

    #[test]
    fn member_paths_reject_traversal_and_absolute_forms() {
        assert_eq!(member_path("./bin/busybox").as_deref(), Some("bin/busybox"));
        assert_eq!(member_path("/etc/passwd").as_deref(), Some("etc/passwd"));
        assert_eq!(member_path("../../escape"), None);
        assert_eq!(member_path("ok/../escape"), None);
        assert_eq!(member_path(""), None);
        assert_eq!(member_path("./"), None);
    }

    #[test]
    fn the_note_names_the_container_and_its_limits() {
        let mut stats = ExtractStats {
            entries: 12,
            skipped_oversized: 1,
            skipped_markers: 4,
            stopped: Some("nesting deeper than 3".into()),
        };
        let note = stats.note("fw.tar").expect("note");
        assert!(note.contains("fw.tar"), "{note}");
        assert!(note.contains("12 member(s)"), "{note}");
        assert!(note.contains("1 over the per-member cap"), "{note}");
        assert!(note.contains("4 markers"), "{note}");
        assert!(note.contains("stopped early"), "{note}");

        stats = ExtractStats::default();
        assert!(stats.note("empty.zip").is_none());
    }
}

#[cfg(test)]
mod squashfs_tests {
    use super::*;

    fn busybox() -> Vec<u8> {
        let mut bytes = vec![0u8, 0, 0, 0];
        bytes.extend_from_slice(b"BusyBox is a multi-call binary\0BusyBox v1.38.0 (2026-05-13)\0");
        bytes
    }

    /// Build a real gzip-compressed squashfs v4 image in memory, so the
    /// reader path is exercised exactly as on-disk firmware would hit it.
    fn squashfs_with(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut writer = backhand::FilesystemWriter::default();
        writer.set_compressor(
            backhand::FilesystemCompressor::new(backhand::v4::compressor::Compressor::Gzip, None)
                .expect("gzip compressor"),
        );
        let header = backhand::NodeHeader {
            permissions: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        };
        for (path, bytes) in members {
            // The writer stores absolute paths and requires every parent
            // directory to exist as a node, exactly as the on-disk format
            // does.
            let absolute = std::path::PathBuf::from("/").join(path);
            writer
                .push_dir_all(absolute.parent().expect("parent"), header)
                .expect("push dir");
            writer
                .push_file(bytes.as_slice(), &absolute, header)
                .expect("push squashfs member");
        }
        let mut image = Vec::new();
        writer
            .write(&mut std::io::Cursor::new(&mut image))
            .expect("write squashfs");
        image
    }

    fn paths(extracted: &Extracted) -> Vec<&str> {
        extracted.members.iter().map(|m| m.path.as_str()).collect()
    }

    #[test]
    fn a_squashfs_filesystem_is_extracted() {
        let image = squashfs_with(&[
            ("bin/busybox", busybox()),
            ("etc/config/firewall", b"defaults\n\0".to_vec()),
        ]);
        assert_eq!(
            super::super::filetype::archive_kind(&image),
            Some(super::super::filetype::ArchiveKind::Squashfs)
        );
        let extracted = extract("rootfs.squashfs", &image, &ExtractBudget::default());
        assert_eq!(
            paths(&extracted),
            vec![
                "rootfs.squashfs!/bin/busybox",
                "rootfs.squashfs!/etc/config/firewall",
            ]
        );
        assert_eq!(extracted.members[0].bytes, busybox());
    }

    #[test]
    fn an_embedded_squashfs_is_found_at_an_erasure_boundary() {
        // The vendor `.bin` shape: junk header/kernel first, filesystem at a
        // page-aligned offset. Junk carries no magic so only the real hit
        // parses.
        let image = squashfs_with(&[("bin/busybox", busybox())]);
        let mut blob = vec![0x5au8; EMBEDDED_ALIGN * 2];
        blob.extend_from_slice(&image);
        let extracted = extract_embedded_squashfs("fw.bin", &blob, &ExtractBudget::default());
        assert_eq!(
            paths(&extracted),
            vec![format!("fw.bin!sqfs@0x2000!/bin/busybox")]
        );
    }

    #[test]
    fn a_blob_with_no_embedded_filesystem_yields_nothing() {
        let blob = vec![0x5au8; EMBEDDED_ALIGN * 3];
        let extracted = extract_embedded_squashfs("plain.bin", &blob, &ExtractBudget::default());
        assert_eq!(paths(&extracted), Vec::<&str>::new());
    }

    #[test]
    fn a_stray_magic_that_does_not_parse_is_skipped() {
        let mut blob = vec![0x5au8; EMBEDDED_ALIGN];
        blob.extend_from_slice(b"hsqs");
        blob.extend_from_slice(&[0x11u8; EMBEDDED_ALIGN]);
        let extracted = extract_embedded_squashfs("liar.bin", &blob, &ExtractBudget::default());
        assert_eq!(paths(&extracted), Vec::<&str>::new());
    }

    #[test]
    fn squashfs_budgets_stop_extraction_with_a_reason() {
        let members: Vec<(String, Vec<u8>)> = (0..5)
            .map(|index| (format!("bin/tool{index}"), busybox()))
            .collect();
        let refs: Vec<(&str, Vec<u8>)> = members
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.clone()))
            .collect();
        let image = squashfs_with(&refs);
        let small = ExtractBudget {
            max_entries: 2,
            ..ExtractBudget::default()
        };
        let extracted = extract("rootfs.squashfs", &image, &small);
        assert_eq!(extracted.members.len(), 2);
        assert_eq!(
            extracted.stats.stopped.as_deref(),
            Some("more than 2 members")
        );
    }

    #[test]
    fn an_rpm_package_finds_the_files_in_its_payload() {
        // A minimal but structurally real RPM: lead, signature and main
        // headers (empty indexes), and an xz-compressed cpio payload —
        // Red Hat's default compression, exercised through the same
        // liblzma the extractor links for .tar.xz.
        let mut cpio = Vec::new();
        let mut push_entry = |name: &str, mode: u32, data: &[u8]| {
            let name_field = format!("{name}\0").into_bytes();
            let header = format!(
                "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
                1, mode, 0, 0, 1, 0, data.len(), 0, 0, 0, 0, name_field.len(), 0
            );
            cpio.extend_from_slice(header.as_bytes());
            cpio.extend_from_slice(&name_field);
            while cpio.len() % 4 != 0 {
                cpio.push(0);
            }
            cpio.extend_from_slice(data);
            while cpio.len() % 4 != 0 {
                cpio.push(0);
            }
        };
        push_entry("./usr/lib/libcrypto.so.3", 0o100755, &busybox());
        push_entry("TRAILER!!!", 0, b"");
        let mut encoder = liblzma::write::XzEncoder::new(Vec::new(), 6);
        std::io::Write::write_all(&mut encoder, &cpio).expect("xz write");
        let payload = encoder.finish().expect("xz finish");

        let mut rpm = vec![0xedu8, 0xab, 0xee, 0xdb];
        rpm.extend_from_slice(&[0; 92]); // rest of the 96-byte lead
        for _ in 0..2 {
            let mut header = [0u8; 16];
            header[0..4].copy_from_slice(&[0x8e, 0xad, 0xe8, 0x01]);
            // Zero index entries, zero data bytes, already 8-aligned.
            rpm.extend_from_slice(&header);
        }
        rpm.extend_from_slice(&payload);

        let extracted = extract("tool.rpm", &rpm, &ExtractBudget::default());
        assert_eq!(paths(&extracted), vec!["tool.rpm!/usr/lib/libcrypto.so.3"]);
    }

    #[test]
    fn an_rpm_whose_headers_do_not_parse_yields_nothing() {
        let mut rpm = vec![0xedu8, 0xab, 0xee, 0xdb];
        rpm.extend_from_slice(&[0x41; 400]);
        let extracted = extract("broken.rpm", &rpm, &ExtractBudget::default());
        assert_eq!(paths(&extracted), Vec::<&str>::new());
    }

    #[test]
    fn malformed_squashfs_yields_nothing_and_no_crash() {
        let garbage = [b'h', b's', b'q', b's', 0xff, 0xff, 0xff, 0xff];
        let extracted = extract("broken.squashfs", &garbage, &ExtractBudget::default());
        assert_eq!(paths(&extracted), Vec::<&str>::new());
    }
}
