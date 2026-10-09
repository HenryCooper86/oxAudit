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
//!   payload, hand-parsed), plain zlib CramFS, and squashfs v4 through the maintained,
//!   fuzzed `backhand` reader, including filesystems embedded in raw
//!   firmware blobs at unaligned offsets. A saved `docker`/OCI image
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
//!   bounded, unaligned sliding magic search for embedded squashfs within
//!   the first 256 MiB, with a parse-attempt cap against magic sprays.
//!   UBI/UBIFS and the long tail of vendor filesystems
//!   are still *not* unpacked — each needs its own vetted reader, and
//!   pretending otherwise would be the exact kind of silent gap this
//!   module exists to eliminate. Squashfs v3 (pre-2009) parses or yields
//!   nothing; the blob then scans raw, as before.

use std::borrow::Cow;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::filetype::{archive_kind, ArchiveKind};
use crate::DEFAULT_MAX_MEMBER_BYTES;

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
    /// Total expanded bytes across every member and level. Streamed layer tars
    /// also cap actual decoded bytes, including framing and skipped content.
    pub max_total_bytes: u64,
}

impl Default for ExtractBudget {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_entries: 20_000,
            max_entry_bytes: DEFAULT_MAX_MEMBER_BYTES,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}

/// What one extraction actually did, for the notes a scan reports.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExtractStats {
    /// Members successfully pulled out.
    pub entries: usize,
    /// Peak simultaneous member/wrapper Vec capacities during extraction.
    /// Excludes input, codec/page/table allocations and buffers retained by a visitor.
    pub peak_retained_bytes: u64,
    /// Members skipped for exceeding the per-entry cap.
    pub skipped_oversized: usize,
    /// Members or compression streams skipped because their bytes could not be read or decoded.
    pub skipped_unreadable: usize,
    /// Members skipped for being markers rather than content: directories,
    /// symlinks, devices, container whiteouts.
    pub skipped_markers: usize,
    /// Set when a budget stopped extraction early. Members already pulled
    /// out remain valid; absence beyond the stop is not evidence of anything.
    pub stopped: Option<String>,
}

impl ExtractStats {
    /// One user-facing line, or `None` when neither extraction nor skipped content needs reporting.
    pub fn note(&self, container: &str) -> Option<String> {
        if self.entries == 0
            && self.skipped_oversized == 0
            && self.skipped_unreadable == 0
            && self.stopped.is_none()
        {
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
        if self.skipped_unreadable > 0 {
            note.push_str(&format!(
                ", skipped {} unreadable member(s) or stream(s)",
                self.skipped_unreadable
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
    /// Container levels from this extraction root to the leaf.
    pub depth: usize,
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
    let mut members = Vec::new();
    let stats = extract_visit(name, bytes, budget, &mut |member| {
        members.push(member);
        true
    });
    Extracted { members, stats }
}

/// Visit each leaf as it is decoded, without retaining previously visited
/// members. Nested containers retain their ancestors and the current member.
/// Return false to stop; accepted findings can be kept by the caller while
/// `stopped` records that later members were not examined. Keeping member
/// buffers in the visitor defeats this API's retention benefit.
pub fn extract_visit(
    name: &str,
    bytes: &[u8],
    budget: &ExtractBudget,
    visitor: &mut dyn FnMut(ExtractedMember) -> bool,
) -> ExtractStats {
    let mut out = Extraction::new(visitor);
    let mut total = 0_u64;
    extract_into(name, bytes, 0, budget, &mut total, &mut out);
    out.stats
}

/// Cancellable streaming extraction.
pub fn extract_visit_cancellable(
    name: &str,
    bytes: &[u8],
    budget: &ExtractBudget,
    cancel: &AtomicBool,
    visitor: &mut dyn FnMut(ExtractedMember) -> bool,
) -> ExtractStats {
    let mut out = Extraction::new(visitor);
    out.cancel = Some(cancel);
    let mut total = 0_u64;
    extract_into(name, bytes, 0, budget, &mut total, &mut out);
    out.stats
}

/// Visit files in an OCI layer tar, optionally wrapped by a detected codec.
/// Tar and codec output are read incrementally; skipped members and tar
/// framing count toward the streamed-layer byte limit too. Random-access
/// formats should use [`extract_visit_cancellable`] instead.
pub fn extract_layer_visit(
    name: &str,
    reader: &mut dyn Read,
    kind: ArchiveKind,
    budget: &ExtractBudget,
    cancel: &AtomicBool,
    visitor: &mut dyn FnMut(ExtractedMember) -> bool,
) -> ExtractStats {
    let mut out = Extraction::new(visitor);
    out.cancel = Some(cancel);
    // Bound and cancel reads made by codecs, including while tar skips a
    // member whose content exceeded the per-member cap.
    let mut input = CancelReader { reader, cancel };
    // Keep the same decompressed member identity as the collecting API.
    let plain_name = if kind == ArchiveKind::Tar {
        name.to_owned()
    } else {
        strip_archive_suffix(name)
    };
    let name = plain_name.as_str();
    match kind {
        ArchiveKind::Tar => drain_layer(name, &mut input, 0, budget, &mut out),
        ArchiveKind::Gzip => drain_layer(
            name,
            &mut flate2::read::GzDecoder::new(input),
            1,
            budget,
            &mut out,
        ),
        ArchiveKind::Bzip2 => drain_layer(
            name,
            &mut bzip2::read::BzDecoder::new(input),
            1,
            budget,
            &mut out,
        ),
        ArchiveKind::Xz => drain_layer(
            name,
            &mut liblzma::read::XzDecoder::new(input),
            1,
            budget,
            &mut out,
        ),
        ArchiveKind::Zstd => match zstd::stream::read::Decoder::new(input) {
            Ok(mut decoder) => drain_layer(name, &mut decoder, 1, budget, &mut out),
            Err(_) => out.stats.skipped_unreadable += 1,
        },
        _ => {
            out.stats.stopped = Some("unsupported streamed layer format".into());
        }
    }
    if cancel.load(Ordering::Relaxed) {
        out.stats
            .stopped
            .get_or_insert_with(|| "scan cancelled".into());
    }
    out.stats
}

struct CancelReader<'a> {
    reader: &'a mut dyn Read,
    cancel: &'a AtomicBool,
}

impl Read for CancelReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("scan cancelled"));
        }
        let len = bytes.len().min(64 * 1024);
        self.reader.read(&mut bytes[..len])
    }
}

struct LayerReader<'a> {
    reader: &'a mut dyn Read,
    remaining: u64,
    exhausted: bool,
}

impl Read for LayerReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            if !self.exhausted {
                let mut probe = [0; 1];
                self.exhausted = self.reader.read(&mut probe)? > 0;
            }
            return Ok(0);
        }
        let len = bytes
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let read = self.reader.read(&mut bytes[..len])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn drain_layer(
    name: &str,
    reader: &mut dyn Read,
    depth: usize,
    budget: &ExtractBudget,
    out: &mut Extraction<'_>,
) {
    if depth >= budget.max_depth {
        out.stats.stopped = Some(format!("nesting deeper than {}", budget.max_depth));
        return;
    }
    let mut reader = LayerReader {
        reader,
        remaining: budget.max_total_bytes,
        exhausted: false,
    };
    let mut total = 0;
    extract_tar_reader(name, &mut reader, depth, budget, &mut total, out);
    if reader.exhausted {
        out.stats.stopped.get_or_insert_with(|| {
            format!(
                "streamed layer expanded past {} bytes (including framing and skipped content)",
                budget.max_total_bytes
            )
        });
    }
}

struct Extraction<'a> {
    stats: ExtractStats,
    visitor: &'a mut dyn FnMut(ExtractedMember) -> bool,
    retained_bytes: u64,
    visitor_stopped: bool,
    cancel: Option<&'a AtomicBool>,
}

impl<'a> Extraction<'a> {
    fn new(visitor: &'a mut dyn FnMut(ExtractedMember) -> bool) -> Self {
        Self {
            stats: ExtractStats::default(),
            visitor,
            retained_bytes: 0,
            visitor_stopped: false,
            cancel: None,
        }
    }

    fn observe_buffer(&mut self, bytes: usize) {
        self.stats.peak_retained_bytes = self
            .stats
            .peak_retained_bytes
            .max(self.retained_bytes + bytes as u64);
    }

    fn retain(&mut self, bytes: usize) {
        self.observe_buffer(bytes);
        self.retained_bytes += bytes as u64;
    }

    fn release(&mut self, bytes: usize) {
        self.retained_bytes -= bytes as u64;
    }
}

fn extract_into(
    name: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extraction<'_>,
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
    if budget_stop(budget, total, out) {
        return;
    }
    // A decompression wrapper resolves to one member whose name is the
    // compressed name minus its extension; the payload then re-dispatches,
    // because a `.tar.gz` is a gzip around a tar. Every wrapper level counts
    // against the depth budget — a chain of gzip-around-gzip is adversarial
    // input, not a format to honor.
    match archive_kind(bytes) {
        Some(ArchiveKind::Gzip) => {
            if let Some(plain) = decompress(&mut flate2::read::GzDecoder::new(bytes), budget, out) {
                dispatch_decompressed(name, plain, depth, budget, total, out);
            }
        }
        Some(ArchiveKind::Bzip2) => {
            if let Some(plain) = decompress(&mut bzip2::read::BzDecoder::new(bytes), budget, out) {
                dispatch_decompressed(name, plain, depth, budget, total, out);
            }
        }
        Some(ArchiveKind::Xz) => {
            if let Some(plain) = decompress(&mut liblzma::read::XzDecoder::new(bytes), budget, out)
            {
                dispatch_decompressed(name, plain, depth, budget, total, out);
            }
        }
        Some(ArchiveKind::Zstd) => {
            if let Ok(mut decoder) = zstd::stream::read::Decoder::new(bytes) {
                if let Some(plain) = decompress(&mut decoder, budget, out) {
                    dispatch_decompressed(name, plain, depth, budget, total, out);
                }
            }
        }
        Some(ArchiveKind::Tar) => extract_tar(name, bytes, depth, budget, total, out),
        Some(ArchiveKind::Zip) => extract_zip(name, bytes, depth, budget, total, out),
        Some(ArchiveKind::Ar) => extract_ar(name, bytes, depth, budget, total, out),
        Some(ArchiveKind::Rpm) => extract_rpm(name, bytes, depth, budget, total, out),
        Some(ArchiveKind::Cramfs) => extract_cramfs(name, bytes, depth, budget, total, out),
        Some(ArchiveKind::Squashfs) => {
            // backhand is the maintained, fuzzed reader for this format;
            // hand-rolling one was explicitly rejected when this module was
            // written. v4 images parse; everything else yields nothing and
            // the caller scans the blob raw.
            //
            // v3 was tried and deliberately not shipped: the plain-zlib v3
            // kinds could not be verified against any obtainable image, and
            // the v3 images that actually dominate old firmware — OpenWrt
            // Kamikaze/8.09-era vendor builds — are LZMA-patched hybrids
            // with mixed-endian headers that backhand rejects under every
            // kind (measured against 8.09.2's openwrt-atheros-root.squashfs:
            // all four kinds fail). The vendor-LZMA kinds that might read
            // them need a C++ 7zip-era dependency that does not build
            // cleanly. Those blobs still scan raw, as before.
            let cursor = std::io::Cursor::new(bytes);
            if let Ok(filesystem) = backhand::FilesystemReader::from_reader(cursor) {
                drain_squashfs(name, &filesystem, depth, budget, total, out);
            }
        }
        None => {}
    }
}

/// A decompressed payload is either another container — a `.tar.gz` is a
/// gzip around a tar — or a leaf file in its own right, like a gzip'd raw
/// firmware image. Dropping the second case would silently un-scan every
/// single-file compression wrapper.
fn dispatch_decompressed(
    name: &str,
    plain: Vec<u8>,
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extraction<'_>,
) {
    if archive_kind(&plain[..plain.len().min(512)]).is_some() {
        let plain_name = strip_archive_suffix(name);
        let retained = plain.capacity();
        out.retain(retained);
        extract_into(&plain_name, &plain, depth + 1, budget, total, out);
        out.release(retained);
    } else {
        let member_name = strip_archive_suffix(name);
        read_member_bytes(name, &member_name, plain.into(), depth, budget, total, out);
    }
}

/// Pull every file out of an opened squashfs. Non-file nodes (directories,
/// symlinks, devices) are counted as markers, as in every other container.
fn drain_squashfs(
    container: &str,
    filesystem: &backhand::FilesystemReader<'_>,
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extraction<'_>,
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
        read_member(container, &member, &mut reader, depth, budget, total, out);
    }
}

/// Read a CramFS image: the read-only compressed filesystem some vendor
/// firmware ships instead of squashfs. The layout follows the kernel reader
/// (`fs/cramfs/inode.c`): a 76-byte superblock whose root inode starts the
/// directory tree; directory data as contiguous 12-byte inodes each followed
/// by their 4-byte-padded name; file data behind a block-pointer table where
/// **each pointer names the end of its block** and the first block starts
/// immediately after the table.
///
/// Deliberately refused, each with the blob falling back to a raw scan: the
/// shifted-root-offset flag (old padded images), the wrong-signature flag,
/// and direct block pointers (a legacy addressing variant). Everything
/// modern `mkfs.cramfs` writes is the plain zlib form handled here.
fn extract_cramfs(
    container: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extraction<'_>,
) {
    const SUPERBLOCK: usize = 76;
    const FLAG_SHIFTED_ROOT: u32 = 0x0000_0400;
    const FLAG_WRONG_SIGNATURE: u32 = 0x0000_0200;
    if bytes.len() < SUPERBLOCK {
        return;
    }
    let field = |offset: usize| {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    };
    let flags = field(8);
    if flags & (FLAG_SHIFTED_ROOT | FLAG_WRONG_SIGNATURE) != 0 {
        return;
    }
    if &bytes[16..32] != b"Compressed ROMFS" {
        return;
    }
    // The root inode is embedded in the superblock at offset 64; its data
    // pointer names where the root directory's records live.
    let Some(root) = cramfs_inode_at(bytes, 64) else {
        return;
    };
    walk_cramfs_dir(
        &mut CramfsWalk {
            bytes,
            container,
            budget,
            total,
            out,
        },
        root.offset as usize,
        root.size as usize,
        "",
        depth,
    );
}

/// One parsed CramFS inode: 12 bytes, three little-endian words whose
/// bitfields the format packs as mode:16 uid:16, size:24 gid:8, and
/// namelen:6 offset:26.
struct CramfsInode {
    mode: u32,
    size: u32,
    namelen: u32,
    offset: u32,
}

fn cramfs_inode_at(bytes: &[u8], offset: usize) -> Option<CramfsInode> {
    let word = |index: usize| {
        let start = offset.checked_add(index * 4)?;
        let raw = bytes.get(start..start + 4)?;
        Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    };
    let first = word(0)?;
    let second = word(1)?;
    let third = word(2)?;
    Some(CramfsInode {
        mode: first & 0xffff,
        size: second & 0xff_ffff,
        namelen: third & 0x3f,
        offset: (third >> 6) * 4,
    })
}

/// Walk one directory's data region: contiguous inode+name records. Regular
/// files become members; directories recurse under the same depth budget as
/// container nesting; everything else counts as a marker.
struct CramfsWalk<'a, 'visitor> {
    bytes: &'a [u8],
    container: &'a str,
    budget: &'a ExtractBudget,
    total: &'a mut u64,
    out: &'a mut Extraction<'visitor>,
}

fn walk_cramfs_dir(
    walk: &mut CramfsWalk<'_, '_>,
    offset: usize,
    size: usize,
    prefix: &str,
    depth: usize,
) {
    let bytes = walk.bytes;
    let Some(end) = offset.checked_add(size) else {
        return;
    };
    if end > bytes.len() || offset > end {
        return;
    }
    let mut cursor = offset;
    while cursor + 12 <= end {
        if budget_stop(walk.budget, walk.total, walk.out) {
            return;
        }
        let Some(node) = cramfs_inode_at(bytes, cursor) else {
            return;
        };
        let name_len = node.namelen as usize * 4;
        let Some(record) = bytes.get(cursor + 12..cursor + 12 + name_len) else {
            return;
        };
        let raw_name = String::from_utf8_lossy(record);
        let name = raw_name.split('\0').next().unwrap_or_default();
        cursor += 12 + name_len;
        if name.is_empty() {
            walk.out.stats.skipped_markers += 1;
            continue;
        }
        match node.mode & 0xf000 {
            0x4000 => {
                if depth < walk.budget.max_depth {
                    walk_cramfs_dir(
                        walk,
                        node.offset as usize,
                        node.size as usize,
                        &format!("{prefix}{name}/"),
                        depth + 1,
                    );
                } else {
                    walk.out.stats.stopped.get_or_insert_with(|| {
                        format!("nesting deeper than {}", walk.budget.max_depth)
                    });
                }
            }
            0x8000 if node.size > 0 => {
                let full = format!("{prefix}{name}");
                let Some(member) = member_path(&full) else {
                    walk.out.stats.skipped_markers += 1;
                    continue;
                };
                if u64::from(node.size) > walk.budget.max_entry_bytes {
                    walk.out.stats.skipped_oversized += 1;
                    continue;
                }
                if u64::from(node.size) > walk.budget.max_total_bytes.saturating_sub(*walk.total) {
                    *walk.total = walk.budget.max_total_bytes;
                    budget_stop(walk.budget, walk.total, walk.out);
                    return;
                }
                walk.out.observe_buffer(node.size as usize);
                if let Some(content) = cramfs_file_bytes(walk.bytes, &node, walk.budget) {
                    read_member_bytes(
                        walk.container,
                        &member,
                        content.into(),
                        depth,
                        walk.budget,
                        walk.total,
                        walk.out,
                    );
                } else {
                    walk.out.stats.skipped_unreadable += 1;
                }
            }
            _ => walk.out.stats.skipped_markers += 1,
        }
    }
}

/// Assemble one file's content from its block-pointer table. The table has
/// exactly one pointer per block, each naming its block's END (one-past);
/// block zero starts immediately after the table, later blocks where the
/// previous pointer said. Blocks are zlib streams unless the uncompressed
/// flag is set. Each block expands to at most one 4 KiB page; a zero-length
/// block is a hole. Short pages are zero-filled, as in Linux's CramFS reader
/// (fs/cramfs/inode.c, cramfs_read_folio). Corrupt zlib is never raw content.
fn cramfs_file_bytes(bytes: &[u8], node: &CramfsInode, budget: &ExtractBudget) -> Option<Vec<u8>> {
    const PAGE: u32 = 4096;
    const FLAG_UNCOMPRESSED: u32 = 0x8000_0000;
    const FLAG_DIRECT: u32 = 0x4000_0000;
    if u64::from(node.size) > budget.max_entry_bytes {
        return None;
    }
    let pointer = |entry: usize| -> Option<u32> {
        let raw = bytes.get(entry..entry + 4)?;
        Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    };
    let blocks = node.size.div_ceil(PAGE) as usize;
    let table = node.offset as usize;
    let mut content: Vec<u8> = Vec::with_capacity(node.size as usize);
    let mut previous_end: Option<usize> = None;
    for index in 0..blocks {
        let entry = table.checked_add(index * 4)?;
        let value = pointer(entry)?;
        if value & FLAG_DIRECT != 0 {
            // Legacy direct addressing; the caller marks the file skipped
            // rather than guessing its layout.
            return None;
        }
        let end = (value & !(FLAG_UNCOMPRESSED | FLAG_DIRECT)) as usize;
        let start = previous_end.replace(end).unwrap_or(table + blocks * 4);
        if end < start || end > bytes.len() {
            return None;
        }
        let block = &bytes[start..end];
        let expected = (node.size as usize - index * PAGE as usize).min(PAGE as usize);
        let page_end = content.len() + expected;
        if block.is_empty() {
            content.resize(page_end, 0);
        } else if value & FLAG_UNCOMPRESSED != 0 {
            if block.len() > PAGE as usize {
                return None;
            }
            content.extend_from_slice(&block[..block.len().min(expected)]);
            content.resize(page_end, 0);
        } else {
            if block.len() > 2 * PAGE as usize {
                return None;
            }
            let mut plain = Vec::new();
            let mut limited = flate2::read::ZlibDecoder::new(block).take(u64::from(PAGE) + 1);
            if limited.read_to_end(&mut plain).is_err() || plain.len() > PAGE as usize {
                return None;
            }
            content.extend_from_slice(&plain[..plain.len().min(expected)]);
            content.resize(page_end, 0);
        }
    }
    Some(content)
}

/// How far into an opaque firmware blob the embedded-squashfs search reads.
const EMBEDDED_SCAN_WINDOW: usize = 256 * 1024 * 1024;
/// How many embedded filesystems one blob may contribute.
const MAX_EMBEDDED: usize = 4;
/// How many magic hits will be handed to the parser before the search gives
/// up. A blob can spray the four magic bytes anywhere; the parser is the
/// expensive part, so it is the part that gets bounded.
const MAX_PARSE_ATTEMPTS: usize = 64;

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
    out: &mut Extraction<'_>,
) {
    let Some(payload) = rpm_payload(bytes) else {
        return;
    };
    // The payload's own magic says which codec; an unrecognized magic means
    // uncompressed cpio, which is what very old packages carry.
    let plain = match archive_kind(&payload[..payload.len().min(512)]) {
        Some(ArchiveKind::Gzip) => {
            decompress(&mut flate2::read::GzDecoder::new(payload), budget, out)
        }
        Some(ArchiveKind::Bzip2) => {
            decompress(&mut bzip2::read::BzDecoder::new(payload), budget, out)
        }
        Some(ArchiveKind::Xz) => {
            decompress(&mut liblzma::read::XzDecoder::new(payload), budget, out)
        }
        Some(ArchiveKind::Zstd) => {
            let Ok(mut decoder) = zstd::stream::read::Decoder::new(payload) else {
                return;
            };
            decompress(&mut decoder, budget, out)
        }
        _ => Some(payload.to_vec()),
    };
    let Some(cpio) = plain else {
        return;
    };
    let retained = cpio.capacity();
    out.retain(retained);
    extract_cpio(container, &cpio, depth, budget, total, out);
    out.release(retained);
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
    out: &mut Extraction<'_>,
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
                read_member_bytes(container, &member, data.into(), depth, budget, total, out);
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
/// The search slides over every byte of the window (real images put their
/// filesystem at offsets no alignment rule predicts — the reference Archer C7
/// image's sits at `0x1f8718`), but keeps two hard bounds so a hostile blob
/// cannot turn the search into a cost attack: the window itself, and a cap on
/// parse attempts after which the blob gives up and is reported. A magic hit
/// that fails to parse is skipped, not fatal; a blob with no embedded
/// filesystem returns nothing and the caller scans it raw.
pub fn extract_embedded_squashfs(name: &str, bytes: &[u8], budget: &ExtractBudget) -> Extracted {
    let mut members = Vec::new();
    let stats = extract_embedded_squashfs_visit(name, bytes, budget, &mut |member| {
        members.push(member);
        true
    });
    Extracted { members, stats }
}

/// Embedded-filesystem equivalent of [`extract_visit`].
pub fn extract_embedded_squashfs_visit(
    name: &str,
    bytes: &[u8],
    budget: &ExtractBudget,
    visitor: &mut dyn FnMut(ExtractedMember) -> bool,
) -> ExtractStats {
    extract_embedded_squashfs_visit_with_cancel(name, bytes, budget, None, visitor)
}

/// Embedded extraction with cancellation checked between reads and members.
pub fn extract_embedded_squashfs_visit_cancellable(
    name: &str,
    bytes: &[u8],
    budget: &ExtractBudget,
    cancel: &AtomicBool,
    visitor: &mut dyn FnMut(ExtractedMember) -> bool,
) -> ExtractStats {
    extract_embedded_squashfs_visit_with_cancel(name, bytes, budget, Some(cancel), visitor)
}

fn extract_embedded_squashfs_visit_with_cancel(
    name: &str,
    bytes: &[u8],
    budget: &ExtractBudget,
    cancel: Option<&AtomicBool>,
    visitor: &mut dyn FnMut(ExtractedMember) -> bool,
) -> ExtractStats {
    let mut out = Extraction::new(visitor);
    out.cancel = cancel;
    let mut total = 0_u64;
    let scan_end = bytes.len().min(EMBEDDED_SCAN_WINDOW);
    let mut found = 0_usize;
    let mut attempts = 0_usize;
    let mut offset = 0_usize;
    while offset + 4 <= scan_end && found < MAX_EMBEDDED {
        if budget_stop(budget, &mut total, &mut out) {
            break;
        }
        let Some(next) = memchr::memchr2(b'h', b's', &bytes[offset..scan_end - 3]) else {
            break;
        };
        let hit = offset + next;
        let magic = &bytes[hit..hit + 4];
        if magic == b"hsqs" || magic == b"sqsh" {
            attempts += 1;
            if attempts > MAX_PARSE_ATTEMPTS {
                out.stats.stopped.get_or_insert_with(|| {
                    format!(
                        "gave up on the magic search after {MAX_PARSE_ATTEMPTS} unparsable hits"
                    )
                });
                break;
            }
            let cursor = std::io::Cursor::new(&bytes[hit..]);
            if let Ok(filesystem) = backhand::FilesystemReader::from_reader(cursor) {
                found += 1;
                if budget.max_depth == 0 {
                    out.stats
                        .stopped
                        .get_or_insert_with(|| "nesting deeper than 0".into());
                    break;
                }
                drain_squashfs(
                    &format!("{name}!sqfs@0x{hit:x}"),
                    &filesystem,
                    0,
                    budget,
                    &mut total,
                    &mut out,
                );
            }
        }
        offset = hit + 1;
    }
    out.stats
}

/// Decompress a single stream up to `max_entry_bytes + 1`, so an oversized
/// result is detected rather than read to exhaustion. `None` on malformed
/// input or an oversized payload.
fn decompress(
    reader: &mut dyn Read,
    budget: &ExtractBudget,
    out: &mut Extraction<'_>,
) -> Option<Vec<u8>> {
    let plain = match read_bounded(reader, budget.max_entry_bytes.saturating_add(1), out) {
        Ok(plain) => plain,
        Err(_) => {
            out.stats.skipped_unreadable += 1;
            return None;
        }
    };
    if plain.len() as u64 > budget.max_entry_bytes {
        out.stats.skipped_oversized += 1;
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
    out: &mut Extraction<'_>,
) {
    extract_tar_reader(
        container,
        &mut std::io::Cursor::new(bytes),
        depth,
        budget,
        total,
        out,
    );
}

fn extract_tar_reader(
    container: &str,
    reader: &mut dyn Read,
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extraction<'_>,
) {
    let mut archive = tar::Archive::new(reader);
    let Ok(entries) = archive.entries() else {
        out.stats.skipped_unreadable += 1;
        return;
    };
    for entry in entries {
        let Ok(mut entry) = entry else {
            out.stats.skipped_unreadable += 1;
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
        if entry.size() > budget.max_entry_bytes {
            out.stats.skipped_oversized += 1;
            continue;
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
        let expected = entry.size();
        read_member_sized(
            container,
            &member,
            &mut entry,
            depth,
            budget,
            total,
            out,
            Some(expected),
        );
    }
}

fn extract_zip(
    container: &str,
    bytes: &[u8],
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extraction<'_>,
) {
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
        return;
    };
    for index in 0..archive.len() {
        let Ok(mut file) = archive.by_index(index) else {
            out.stats.skipped_unreadable += 1;
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
        let expected = file.size();
        read_member_sized(
            container,
            &member,
            &mut file,
            depth,
            budget,
            total,
            out,
            Some(expected),
        );
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
    out: &mut Extraction<'_>,
) {
    const HEADER: usize = 60;
    if bytes.len() < 8 + HEADER {
        return;
    }
    let mut offset = 8; // "!<arch>\n"
    let mut long_names: &[u8] = &[];
    while offset + HEADER <= bytes.len() {
        if budget_stop(budget, total, out) {
            return;
        }
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
            long_names = &bytes[start..end];
            offset = next_ar_offset(offset, HEADER, size);
            continue;
        } else if raw_name == "/" || raw_name == "debian-binary" {
            offset = next_ar_offset(offset, HEADER, size);
            continue;
        } else if let Some(name) = raw_name
            .strip_suffix('/')
            .and_then(|stem| stem.strip_prefix('/'))
            .and_then(|reference| reference.parse::<usize>().ok())
            .and_then(|index| name_from_long_table(long_names, index))
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
                    (&bytes[body..end]).into(),
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
    out: &mut Extraction<'_>,
) {
    read_member_sized(container, member, reader, depth, budget, total, out, None);
}

#[allow(clippy::too_many_arguments)]
fn read_member_sized(
    container: &str,
    member: &str,
    reader: &mut dyn Read,
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extraction<'_>,
    expected: Option<u64>,
) {
    if budget_stop(budget, total, out) {
        return;
    }
    let remaining = budget.max_total_bytes.saturating_sub(*total);
    let limit = budget.max_entry_bytes.min(remaining).saturating_add(1);
    let bytes = match read_bounded(reader, limit, out) {
        Ok(bytes) => bytes,
        Err(_) => {
            out.stats.skipped_unreadable += 1;
            return;
        }
    };
    if expected.is_some_and(|size| (bytes.len() as u64) < size)
        && bytes.len() as u64 <= budget.max_entry_bytes.min(remaining)
    {
        out.stats.skipped_unreadable += 1;
        return;
    }
    read_member_bytes(container, member, bytes.into(), depth, budget, total, out);
}

/// Grow geometrically, but never beyond the requested cap, including the
/// probe byte. `read_to_end` can double a nearly full capped buffer.
fn read_bounded(
    reader: &mut dyn Read,
    limit: u64,
    out: &mut Extraction<'_>,
) -> std::io::Result<Vec<u8>> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut bytes = Vec::new();
    let mut chunk = [0; 64 * 1024];
    while bytes.len() < limit {
        if out.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            out.stats
                .stopped
                .get_or_insert_with(|| "scan cancelled".into());
            return Err(std::io::Error::other("scan cancelled"));
        }
        let remaining = (limit - bytes.len()).min(chunk.len());
        let read = match reader.read(&mut chunk[..remaining]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if read == 0 {
            break;
        }
        let needed = bytes.len() + read;
        if needed > bytes.capacity() {
            let capacity = needed.max(bytes.capacity().saturating_mul(2)).min(limit);
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .map_err(std::io::Error::other)?;
        }
        out.observe_buffer(bytes.capacity());
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

/// Budget accounting plus push-or-recurse for one member's bytes.
fn read_member_bytes(
    container: &str,
    member: &str,
    bytes: Cow<'_, [u8]>,
    depth: usize,
    budget: &ExtractBudget,
    total: &mut u64,
    out: &mut Extraction<'_>,
) {
    if budget_stop(budget, total, out) {
        return;
    }
    let length = bytes.len() as u64;
    if length > budget.max_entry_bytes {
        out.stats.skipped_oversized += 1;
        return;
    }
    if length > budget.max_total_bytes.saturating_sub(*total) {
        *total = budget.max_total_bytes;
        out.stats
            .stopped
            .get_or_insert_with(|| format!("expanded past {} bytes", budget.max_total_bytes));
        return;
    }
    *total += length;
    let leaf = !bytes.is_empty() && archive_kind(&bytes[..bytes.len().min(512)]).is_none();
    let retained = match &bytes {
        Cow::Owned(buffer) => buffer.capacity(),
        Cow::Borrowed(_) if leaf => bytes.len(),
        Cow::Borrowed(_) => 0,
    };
    out.retain(retained);
    if leaf {
        out.stats.entries += 1;
        if !(out.visitor)(ExtractedMember {
            path: format!("{container}!/{member}"),
            bytes: bytes.into_owned(),
            depth: depth + 1,
        }) {
            out.visitor_stopped = true;
            out.stats
                .stopped
                .get_or_insert_with(|| "member visitor stopped".into());
        }
    } else {
        // A nested container expands in place; its own members carry the
        // combined path. An empty member is dropped — nothing to scan.
        if !bytes.is_empty() {
            extract_into(
                &format!("{container}!/{member}"),
                &bytes,
                depth + 1,
                budget,
                total,
                out,
            );
        }
    }
    out.release(retained);
}

/// Stop before reading the next member once a budget is exhausted. Called at
/// iteration boundaries where there is nothing half-read to discard.
fn budget_stop(budget: &ExtractBudget, total: &mut u64, out: &mut Extraction<'_>) -> bool {
    if out.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        out.stats
            .stopped
            .get_or_insert_with(|| "scan cancelled".into());
        return true;
    }
    if out.visitor_stopped {
        return true;
    }
    if *total >= budget.max_total_bytes {
        out.stats
            .stopped
            .get_or_insert_with(|| format!("expanded past {} bytes", budget.max_total_bytes));
        return true;
    }
    if out.stats.entries >= budget.max_entries {
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

    #[test]
    fn streamed_compressed_layer_paths_match_the_collecting_api() {
        let tar = tar_with(&[("bin/busybox", busybox())]);
        let bytes = gzip(&tar);
        let name = "image!layer-0000.tar.gz";
        let expected = extract(name, &bytes, &ExtractBudget::default());
        let mut streamed_paths = Vec::new();
        extract_layer_visit(
            name,
            &mut bytes.as_slice(),
            ArchiveKind::Gzip,
            &ExtractBudget::default(),
            &AtomicBool::new(false),
            &mut |member| {
                streamed_paths.push(member.path);
                true
            },
        );
        assert_eq!(streamed_paths, paths(&expected));
        assert_eq!(streamed_paths, ["image!layer-0000.tar!/bin/busybox"]);
    }

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

    fn ar_with(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = b"!<arch>\n".to_vec();
        for (name, body) in members {
            let header = format!(
                "{name:<16}{0:<12}{0:<6}{0:<6}{0:<8}{1:<10}`\n",
                0,
                body.len()
            );
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend_from_slice(body);
            if body.len() % 2 == 1 {
                bytes.push(b'\n');
            }
        }
        bytes
    }

    fn budget() -> ExtractBudget {
        ExtractBudget::default()
    }

    fn paths(extracted: &Extracted) -> Vec<&str> {
        extracted.members.iter().map(|m| m.path.as_str()).collect()
    }

    #[test]
    fn discarded_oversized_zip_members_still_count_their_peak_buffer_capacity() {
        let archive = zip_with(&[("oversized", vec![7; 1024])]);
        let limited = ExtractBudget {
            max_entry_bytes: 512,
            ..budget()
        };
        let stats = extract_visit("firmware.zip", &archive, &limited, &mut |_| true);
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.skipped_oversized, 1);
        assert_eq!(stats.peak_retained_bytes, 513);
    }

    #[test]
    fn a_streamed_total_stop_never_accepts_a_partial_member() {
        let archive = tar_with(&[("first", busybox()), ("second", busybox())]);
        let limited = ExtractBudget {
            max_entry_bytes: 1024,
            max_total_bytes: 1544,
            ..budget()
        };
        let mut paths = Vec::new();
        let stats = extract_layer_visit(
            "layer",
            &mut archive.as_slice(),
            ArchiveKind::Tar,
            &limited,
            &AtomicBool::new(false),
            &mut |member| {
                paths.push(member.path);
                true
            },
        );
        assert_eq!(paths, vec!["layer!/first"]);
        assert_eq!(stats.entries, 1);
        assert!(stats.skipped_unreadable > 0);
        assert!(stats.stopped.is_some());
    }

    #[test]
    fn streamed_layer_total_stop_keeps_earlier_evidence_and_bounds_skipped_bytes() {
        let archive = tar_with(&[("bin/busybox", busybox()), ("huge.bin", vec![7; 32 * 1024])]);
        let limited = ExtractBudget {
            max_entry_bytes: 1024,
            max_total_bytes: 4096,
            ..budget()
        };
        let mut reader = std::io::Cursor::new(archive);
        let mut paths = Vec::new();
        let stats = extract_layer_visit(
            "layer",
            &mut reader,
            ArchiveKind::Tar,
            &limited,
            &AtomicBool::new(false),
            &mut |member| {
                paths.push(member.path);
                true
            },
        );
        assert_eq!(paths, vec!["layer!/bin/busybox"]);
        assert!(stats.stopped.as_deref().unwrap().contains("4096"));
        assert!(
            reader.position() <= 4097,
            "skipping an oversized member must stop at the layer budget plus one probe"
        );
    }

    #[test]
    fn streamed_layer_scans_after_an_oversized_member_without_buffering_the_layer() {
        let archive = tar_with(&[("huge.bin", vec![7; 32 * 1024]), ("bin/busybox", busybox())]);
        let limited = ExtractBudget {
            max_entry_bytes: 1024,
            max_total_bytes: 64 * 1024,
            ..budget()
        };
        for (kind, bytes) in [
            (ArchiveKind::Tar, archive.clone()),
            (ArchiveKind::Gzip, gzip(&archive)),
        ] {
            let mut paths = Vec::new();
            let stats = extract_layer_visit(
                "layer",
                &mut bytes.as_slice(),
                kind,
                &limited,
                &AtomicBool::new(false),
                &mut |member| {
                    paths.push(member.path);
                    true
                },
            );
            assert_eq!(paths, vec!["layer!/bin/busybox"]);
            assert_eq!(stats.skipped_oversized, 1);
            assert!(
                stats.peak_retained_bytes <= 1025,
                "compressed tar staging must not retain the whole layer: {stats:?}"
            );
        }
    }

    #[test]
    fn cancellation_between_members_keeps_accepted_work_and_stops_decoding() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let cancel = AtomicBool::new(false);
        let archive = tar_with(&[("first", busybox()), ("second", vec![7; 128])]);
        let mut accepted = Vec::new();
        let stats =
            extract_visit_cancellable("fw.tar", &archive, &budget(), &cancel, &mut |member| {
                accepted.push(member.path);
                cancel.store(true, Ordering::Relaxed);
                true
            });
        assert_eq!(accepted, vec!["fw.tar!/first"]);
        assert_eq!(stats.entries, 1);
        assert!(stats.stopped.as_deref().unwrap().contains("cancelled"));
    }

    #[test]
    fn streaming_many_members_releases_buffers_before_reading_the_next() {
        let members: Vec<(String, Vec<u8>)> = (0..12)
            .map(|index| (format!("bin/payload-{index}"), vec![7; 64 * 1024]))
            .collect();
        let borrowed: Vec<(&str, Vec<u8>)> = members
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.clone()))
            .collect();
        let archive = tar_with(&borrowed);
        let mut accepted = 0;
        let stats = extract_visit("many.tar", &archive, &budget(), &mut |member| {
            assert_eq!(member.bytes.len(), 64 * 1024);
            accepted += 1;
            true
        });
        assert_eq!(accepted, 12);
        assert_eq!(stats.entries, 12);
        assert!(
            stats.peak_retained_bytes <= 64 * 1024 + 1,
            "the extractor must retain one leaf, not all 12: {stats:?}"
        );
    }

    #[test]
    fn a_streaming_stop_preserves_already_accepted_members_and_reports_coverage() {
        let archive = tar_with(&[("first", busybox()), ("second", vec![7; 128])]);
        let mut accepted = Vec::new();
        let stats = extract_visit("firmware.tar", &archive, &budget(), &mut |member| {
            accepted.push(member.path);
            false
        });
        assert_eq!(accepted, vec!["firmware.tar!/first"]);
        assert_eq!(stats.entries, 1);
        assert!(
            stats.stopped.is_some(),
            "a visitor stop is incomplete coverage"
        );
    }

    #[test]
    fn a_nested_stream_keeps_only_ancestors_and_the_current_leaf() {
        let inner = tar_with(&[("bin/busybox", busybox()), ("bin/other", vec![7; 128])]);
        let outer = tar_with(&[("layer.tar", inner.clone()), ("bin/last", vec![7; 128])]);
        let mut paths = Vec::new();
        let stats = extract_visit("image.tar", &outer, &budget(), &mut |member| {
            paths.push(member.path);
            true
        });
        assert_eq!(
            paths,
            vec![
                "image.tar!/layer.tar!/bin/busybox",
                "image.tar!/layer.tar!/bin/other",
                "image.tar!/bin/last"
            ]
        );
        assert!(stats.peak_retained_bytes <= inner.len() as u64 + 129);
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
    fn ar_members_obey_the_per_member_cap() {
        let archive = ar_with(&[("huge.o", vec![1; 512]), ("busybox.o", busybox())]);
        let small = ExtractBudget {
            max_entry_bytes: 256,
            ..budget()
        };
        let extracted = extract("lib.a", &archive, &small);
        assert_eq!(paths(&extracted), vec!["lib.a!/busybox.o"]);
        assert_eq!(extracted.stats.skipped_oversized, 1);
    }

    #[test]
    fn ar_members_obey_the_member_count_cap() {
        let archive = ar_with(&[("one.o", busybox()), ("two.o", busybox())]);
        let small = ExtractBudget {
            max_entries: 1,
            ..budget()
        };
        let extracted = extract("lib.a", &archive, &small);
        assert_eq!(paths(&extracted), vec!["lib.a!/one.o"]);
        assert_eq!(
            extracted.stats.stopped.as_deref(),
            Some("more than 1 members")
        );
    }

    #[test]
    fn an_oversized_compression_wrapper_reports_the_skip() {
        let compressed = gzip(&vec![7; 512]);
        let small = ExtractBudget {
            max_entry_bytes: 256,
            ..budget()
        };
        let extracted = extract("firmware.gz", &compressed, &small);
        assert!(extracted.members.is_empty());
        assert_eq!(extracted.stats.skipped_oversized, 1);
        assert!(extracted
            .stats
            .note("firmware.gz")
            .unwrap()
            .contains("per-member cap"));
    }

    #[test]
    fn a_member_read_stops_at_the_remaining_total_budget() {
        let mut reader = std::io::Cursor::new(vec![7; 4096]);
        let small = ExtractBudget {
            max_entry_bytes: 1024,
            max_total_bytes: 32,
            ..budget()
        };
        let mut members = Vec::new();
        let mut visitor = |member| {
            members.push(member);
            true
        };
        let mut out = Extraction::new(&mut visitor);
        let mut total = 0;
        read_member(
            "fw.tar",
            "huge.bin",
            &mut reader,
            0,
            &small,
            &mut total,
            &mut out,
        );
        assert_eq!(
            reader.position(),
            33,
            "only the budget and one probe byte are read"
        );
        assert_eq!(out.stats.entries, 0);
        assert_eq!(out.stats.stopped.as_deref(), Some("expanded past 32 bytes"));
    }

    #[test]
    fn a_single_oversized_member_still_has_a_coverage_note() {
        let archive = tar_with(&[("huge.bin", vec![7; 512])]);
        let small = ExtractBudget {
            max_entry_bytes: 256,
            ..budget()
        };
        let extracted = extract("fw.tar", &archive, &small);
        assert!(extracted.members.is_empty());
        assert!(extracted
            .stats
            .note("fw.tar")
            .unwrap()
            .contains("skipped 1"));
    }

    #[test]
    fn a_corrupt_zip_member_reports_incomplete_extraction() {
        // Stored bytes make the CRC corruption independent of the compressor.
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in [
            ("broken.bin", b"corrupt-me".to_vec()),
            ("busybox", busybox()),
        ] {
            writer
                .start_file(
                    name,
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored),
                )
                .unwrap();
            std::io::Write::write_all(&mut writer, &bytes).unwrap();
        }
        let mut archive = writer.finish().unwrap().into_inner();
        let offset = archive
            .windows(10)
            .position(|bytes| bytes == b"corrupt-me")
            .unwrap();
        archive[offset] ^= 1;
        let extracted = extract("fw.zip", &archive, &budget());
        assert_eq!(paths(&extracted), vec!["fw.zip!/busybox"]);
        assert!(extracted
            .stats
            .note("fw.zip")
            .unwrap()
            .contains("unreadable"));
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

    /// Corruption at every byte boundary must terminate without panicking —
    /// the extractor reads untrusted firmware, and a crash is an availability
    /// bug an attacker controls. Fixed seeds keep failures reproducible.
    #[test]
    fn every_truncation_and_single_byte_flip_terminates() {
        let tar = tar_with(&[
            ("bin/busybox", busybox()),
            ("etc/note", b"text\0\0\n".to_vec()),
        ]);
        let zip = zip_with(&[("bin/busybox", busybox())]);
        let mut deb = b"!<arch>\n".to_vec();
        let member = tar_with(&[("usr/lib/libz.so", busybox())]);
        let gz = gzip(&member);
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "data.tar.gz",
            0,
            0,
            0,
            0,
            gz.len()
        );
        deb.extend_from_slice(header.as_bytes());
        deb.extend_from_slice(&gz);
        let mut rpm = vec![0xedu8, 0xab, 0xee, 0xdb];
        rpm.extend_from_slice(&[0; 92]);
        for _ in 0..2 {
            let mut header = [0u8; 16];
            header[0..4].copy_from_slice(&[0x8e, 0xad, 0xe8, 0x01]);
            rpm.extend_from_slice(&header);
        }
        rpm.extend_from_slice(&gzip(&tar));

        let budget = ExtractBudget::default();
        for (name, corpus) in [("t", tar), ("z", zip), ("d", deb), ("r", rpm)] {
            for cut in [
                0usize,
                1,
                4,
                7,
                60,
                61,
                96,
                111,
                200,
                corpus.len().saturating_sub(1),
            ] {
                let truncated = &corpus[..cut.min(corpus.len())];
                let _ = extract(name, truncated, &budget);
            }
            // Deterministic single-byte flips across representative positions.
            let mut flipped = corpus.clone();
            let mut state = 0x2545F4914F6CDD1Du64;
            for position in (0..flipped.len()).step_by(7) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                flipped[position] = (state & 0xff) as u8;
            }
            let _ = extract(name, &flipped, &budget);
            let mut sparse = corpus.clone();
            for position in (0..sparse.len()).step_by(13) {
                sparse[position] ^= 0xff;
            }
            let _ = extract(name, &sparse, &budget);
        }
    }

    #[test]
    fn a_self_referential_gzip_chain_cannot_loop() {
        // gzip whose payload is (claimed to be) itself is impossible to
        // build for real, but a deep chain of decompression wrappers is not;
        // the depth budget must stop it. Two levels is enough to prove the
        // counter increments through wrappers.
        let plain = busybox();
        let once = gzip(&plain);
        let twice = gzip(&once);
        let extracted = extract("chain.gz.gz", &twice, &ExtractBudget::default());
        // busybox bytes decompressed out of the wrappers as a single member.
        assert_eq!(extracted.stats.entries, 1);
        assert_eq!(extracted.members[0].bytes, busybox());
    }

    #[test]
    fn the_note_names_the_container_and_its_limits() {
        let mut stats = ExtractStats {
            entries: 12,
            peak_retained_bytes: 0,
            skipped_oversized: 1,
            skipped_unreadable: 0,
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
            crate::filetype::archive_kind(&image),
            Some(crate::filetype::ArchiveKind::Squashfs)
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
        let mut blob = vec![0x5au8; 8192];
        blob.extend_from_slice(&image);
        let extracted = extract_embedded_squashfs("fw.bin", &blob, &ExtractBudget::default());
        assert_eq!(
            paths(&extracted),
            vec![format!("fw.bin!sqfs@0x2000!/bin/busybox")]
        );
    }

    #[test]
    fn an_embedded_squashfs_is_found_at_an_unaligned_offset() {
        // The Archer C7 reference image's filesystem sits at 0x1f8718 — no
        // alignment rule predicts it, which is why the search slides instead
        // of stepping. The junk header is binary (NUL-bearing), not printable.
        let image = squashfs_with(&[("bin/busybox", busybox())]);
        let mut blob = vec![0x00u8; 0x1f8718];
        blob.extend_from_slice(&image);
        let extracted = extract_embedded_squashfs("fw.bin", &blob, &ExtractBudget::default());
        assert_eq!(
            paths(&extracted),
            vec![format!("fw.bin!sqfs@0x1f8718!/bin/busybox")]
        );
    }

    #[test]
    fn a_magic_spray_gives_up_after_a_bounded_number_of_parse_attempts() {
        // A blob can repeat the magic bytes to make the parser do work on
        // every hit. The attempt cap stops the search with a stated reason;
        // the test completing at all is the termination proof.
        let mut blob = Vec::new();
        for _ in 0..4096 {
            blob.extend_from_slice(b"hsqs");
        }
        let extracted = extract_embedded_squashfs("spray.bin", &blob, &ExtractBudget::default());
        assert_eq!(paths(&extracted), Vec::<&str>::new());
        assert!(
            extracted
                .stats
                .stopped
                .as_deref()
                .is_some_and(|reason| reason.contains("gave up")),
            "stop reason: {:?}",
            extracted.stats.stopped
        );
    }

    #[test]
    fn the_search_covers_both_magic_spellings() {
        // "sqsh" is the big-endian superblock spelling; the sliding search
        // watches both first bytes, and backhand decides endianness on parse.
        let image = squashfs_with(&[("bin/tool", busybox())]);
        let mut blob = vec![0u8, 0, 0, 0, 0, 0, 0];
        blob.extend_from_slice(&image);
        let extracted = extract_embedded_squashfs("be.bin", &blob, &ExtractBudget::default());
        assert_eq!(
            paths(&extracted),
            vec![format!("be.bin!sqfs@0x7!/bin/tool")]
        );
    }

    #[test]
    fn a_blob_with_no_embedded_filesystem_yields_nothing() {
        let blob = vec![0x5au8; 12288];
        let extracted = extract_embedded_squashfs("plain.bin", &blob, &ExtractBudget::default());
        assert_eq!(paths(&extracted), Vec::<&str>::new());
    }

    #[test]
    fn a_stray_magic_that_does_not_parse_is_skipped() {
        let mut blob = vec![0x5au8; 4096];
        blob.extend_from_slice(b"hsqs");
        blob.extend_from_slice(&[0x11u8; 4096]);
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
    fn nested_squashfs_keeps_the_container_depth() {
        let leaf = squashfs_with(&[("bin/busybox", busybox())]);
        let inner = squashfs_with(&[("inner.sqfs", leaf)]);
        let outer = squashfs_with(&[("inner.sqfs", inner)]);
        let small = ExtractBudget {
            max_depth: 2,
            ..ExtractBudget::default()
        };
        let extracted = extract("outer.sqfs", &outer, &small);
        assert!(
            extracted.members.is_empty(),
            "the third filesystem must stay unopened"
        );
        assert_eq!(
            extracted.stats.stopped.as_deref(),
            Some("nesting deeper than 2")
        );
    }

    #[test]
    fn an_embedded_squashfs_obeys_a_zero_depth_budget() {
        let image = squashfs_with(&[("bin/busybox", busybox())]);
        let mut blob = vec![0; 7];
        blob.extend_from_slice(&image);
        let small = ExtractBudget {
            max_depth: 0,
            ..ExtractBudget::default()
        };
        let extracted = extract_embedded_squashfs("fw.bin", &blob, &small);
        assert!(extracted.members.is_empty());
        assert_eq!(
            extracted.stats.stopped.as_deref(),
            Some("nesting deeper than 0")
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

#[cfg(test)]
mod cramfs_tests {
    use super::*;

    /// The genuine output of mkfs.cramfs from util-linux 2.40 (alpine:3.20),
    /// built over a two-file tree: bin/busybox carrying a recognizable
    /// banner, and etc/app.conf. Four kilobytes, the format's page floor.
    fn real_image() -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rootfs.cramfs");
        std::fs::read(path).expect("committed fixture")
    }

    fn block_table(size: u32, blocks: &[(u32, Vec<u8>)]) -> (Vec<u8>, CramfsInode) {
        let mut bytes = vec![0; blocks.len() * 4];
        for (index, (flags, block)) in blocks.iter().enumerate() {
            bytes.extend_from_slice(block);
            let pointer = bytes.len() as u32 | flags;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&pointer.to_le_bytes());
        }
        (
            bytes,
            CramfsInode {
                mode: 0o100755,
                size,
                namelen: 0,
                offset: 0,
            },
        )
    }

    fn zlib(bytes: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn cramfs_rejects_a_block_that_expands_past_one_page() {
        let (bytes, node) = block_table(4096, &[(0, zlib(&vec![7; 8192]))]);
        assert!(cramfs_file_bytes(&bytes, &node, &ExtractBudget::default()).is_none());
    }

    #[test]
    fn cramfs_rejects_corrupt_compressed_data_instead_of_treating_it_as_raw() {
        let (bytes, node) = block_table(8, &[(0, b"not zlib".to_vec())]);
        assert!(cramfs_file_bytes(&bytes, &node, &ExtractBudget::default()).is_none());
    }

    #[test]
    fn cramfs_rejects_an_uncompressed_block_larger_than_one_page() {
        let (bytes, node) = block_table(4096, &[(0x8000_0000, vec![7; 8192])]);
        assert!(cramfs_file_bytes(&bytes, &node, &ExtractBudget::default()).is_none());
    }

    #[test]
    fn cramfs_holes_preserve_the_offsets_of_later_content() {
        let (bytes, node) = block_table(4099, &[(0, Vec::new()), (0, zlib(b"end"))]);
        let content = cramfs_file_bytes(&bytes, &node, &ExtractBudget::default()).unwrap();
        assert_eq!(content.len(), 4099);
        assert!(content[..4096].iter().all(|byte| *byte == 0));
        assert_eq!(&content[4096..], b"end");
    }

    #[test]
    fn a_real_mkfs_cramfs_image_yields_its_files() {
        let image = real_image();
        assert_eq!(
            crate::filetype::archive_kind(&image),
            Some(crate::filetype::ArchiveKind::Cramfs)
        );
        let extracted = extract("rootfs.cramfs", &image, &ExtractBudget::default());
        assert_eq!(
            extracted
                .members
                .iter()
                .map(|m| m.path.as_str())
                .collect::<Vec<_>>(),
            vec!["rootfs.cramfs!/bin/busybox", "rootfs.cramfs!/etc/app.conf",]
        );
        let busybox = &extracted.members[0];
        assert!(busybox.bytes.starts_with(b"#!/bin/sh"));
        assert!(busybox
            .bytes
            .windows(b"BusyBox v1.36.1".len())
            .any(|w| w == b"BusyBox v1.36.1"));
        assert_eq!(extracted.members[1].bytes, b"config\x00\x00\n");
        assert_eq!(extracted.stats.stopped, None);
    }

    #[test]
    fn cramfs_budgets_stop_with_a_reason() {
        let image = real_image();
        let small = ExtractBudget {
            max_entries: 1,
            ..ExtractBudget::default()
        };
        let extracted = extract("rootfs.cramfs", &image, &small);
        assert_eq!(extracted.members.len(), 1);
        assert_eq!(
            extracted.stats.stopped.as_deref(),
            Some("more than 1 members")
        );
    }

    #[test]
    fn cramfs_files_obey_the_per_member_cap() {
        let image = real_image();
        let small = ExtractBudget {
            max_entry_bytes: 9,
            ..ExtractBudget::default()
        };
        let extracted = extract("rootfs.cramfs", &image, &small);
        assert_eq!(extracted.members.len(), 1);
        assert_eq!(extracted.members[0].path, "rootfs.cramfs!/etc/app.conf");
        assert_eq!(extracted.members[0].bytes, b"config\x00\x00\n");
        assert_eq!(extracted.stats.skipped_oversized, 1);
    }

    #[test]
    fn a_malformed_cramfs_yields_nothing_and_no_crash() {
        let mut image = real_image();
        // Corrupt the root inode's offset so the walk lands out of range.
        image[72..76].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let extracted = extract("broken.cramfs", &image, &ExtractBudget::default());
        assert!(extracted.members.is_empty());

        // Wrong signature: refuse rather than parse.
        let mut image = real_image();
        image[16] = b'X';
        let extracted = extract("liar.cramfs", &image, &ExtractBudget::default());
        assert!(extracted.members.is_empty());
    }
}
