//! Byte-pattern matching over raw binary content.
//!
//! String signatures can only find a component that says its own name. A
//! library built without its version string — zstd, sqlite3, pcre2, liblzma —
//! is invisible to them, and those are exactly the libraries a vendor firmware
//! image is full of.
//!
//! The technique here is the one [VulHunt](https://github.com/vulhunt-re/vulhunt)
//! uses for UEFI firmware: match *code* rather than text, with a pattern whose
//! unknown bytes are wildcards. Its `BMatch` masks at nibble granularity, which
//! is what lets a pattern pin an opcode while leaving an operand free. That
//! model is adopted here; the code is ours, and VulHunt's own compatibility
//! layers are MIT/Apache in any case.
//!
//! What makes this worth more than a second string matcher is *capture*. Many
//! libraries expose their version as a numeric constant compiled into a
//! function — zstd's `ZSTD_versionNumber` is one instruction returning 10507
//! for 1.5.7 — so a pattern that pins the instruction and captures the operand
//! reads a version out of a binary that never spells one out.

use serde::Deserialize;

/// One byte of a pattern: a value and the mask of bits that must match.
///
/// Nibble granularity is the point. `5.` matches any byte whose high nibble is
/// 5, which pins an instruction class while leaving the register or operand
/// free — the difference between a pattern that survives a recompile and one
/// that matches exactly one build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskedByte {
    value: u8,
    mask: u8,
}

impl MaskedByte {
    pub const fn exact(value: u8) -> Self {
        Self { value, mask: 0xff }
    }

    pub const fn any() -> Self {
        Self { value: 0, mask: 0 }
    }

    #[inline]
    pub fn matches(self, byte: u8) -> bool {
        byte & self.mask == self.value
    }

    pub fn is_wildcard(self) -> bool {
        self.mask == 0
    }
}

#[derive(Debug, PartialEq)]
pub enum PatternError {
    Empty,
    OddNibbles(String),
    BadCharacter(char),
    NoAnchor,
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternError::Empty => write!(f, "pattern is empty"),
            PatternError::OddNibbles(token) => {
                write!(f, "token {token:?} is not a whole byte")
            }
            PatternError::BadCharacter(c) => write!(f, "unexpected character {c:?}"),
            PatternError::NoAnchor => write!(
                f,
                "pattern is all wildcards, which would match at every offset"
            ),
        }
    }
}

/// A parsed byte pattern.
#[derive(Debug, Clone, PartialEq)]
pub struct BytePattern {
    bytes: Vec<MaskedByte>,
    /// Offset of the first fully-known byte, when there is one. It is only a
    /// scanning shortcut: a pattern made entirely of nibble-masked bytes is
    /// perfectly legitimate — `5.` pins an opcode class — and simply has no
    /// single byte value to search for.
    anchor: Option<usize>,
}

impl BytePattern {
    /// Parse a pattern such as `"60 21 .. 52 c0 03 5f d6"`.
    ///
    /// Whitespace between bytes is optional. `.` is a wildcard nibble, so `..`
    /// is any byte and `5.` is any byte in `0x50..=0x5f`.
    pub fn parse(raw: &str) -> Result<Self, PatternError> {
        let mut bytes = Vec::new();
        let mut nibbles: Vec<Option<u8>> = Vec::new();
        let mut token = String::new();

        let flush = |nibbles: &mut Vec<Option<u8>>,
                     bytes: &mut Vec<MaskedByte>,
                     token: &mut String|
         -> Result<(), PatternError> {
            if nibbles.is_empty() {
                return Ok(());
            }
            if nibbles.len() & 1 == 1 {
                return Err(PatternError::OddNibbles(token.clone()));
            }
            for pair in nibbles.chunks(2) {
                let (high, low) = (pair[0], pair[1]);
                let mut value = 0u8;
                let mut mask = 0u8;
                if let Some(high) = high {
                    value |= high << 4;
                    mask |= 0xf0;
                }
                if let Some(low) = low {
                    value |= low;
                    mask |= 0x0f;
                }
                bytes.push(MaskedByte { value, mask });
            }
            nibbles.clear();
            token.clear();
            Ok(())
        };

        for character in raw.chars() {
            match character {
                ' ' | '\t' | '\n' | '\r' | '_' => {
                    flush(&mut nibbles, &mut bytes, &mut token)?;
                }
                '.' | '?' => {
                    nibbles.push(None);
                    token.push(character);
                }
                _ if character.is_ascii_hexdigit() => {
                    nibbles.push(Some(
                        character.to_digit(16).expect("checked to be a hex digit") as u8,
                    ));
                    token.push(character);
                }
                other => return Err(PatternError::BadCharacter(other)),
            }
        }
        flush(&mut nibbles, &mut bytes, &mut token)?;

        if bytes.is_empty() {
            return Err(PatternError::Empty);
        }
        // A pattern of nothing but wildcards matches at every offset in the
        // file, which is never what anyone meant and is expensive to discover
        // at scan time. Constraining *any* bits is enough to be meaningful.
        if bytes.iter().all(|byte| byte.is_wildcard()) {
            return Err(PatternError::NoAnchor);
        }
        let anchor = bytes.iter().position(|byte| byte.mask == 0xff);

        Ok(Self { bytes, anchor })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn matches_at(&self, haystack: &[u8], offset: usize) -> bool {
        let Some(window) = haystack.get(offset..offset + self.bytes.len()) else {
            return false;
        };
        self.bytes
            .iter()
            .zip(window)
            .all(|(pattern, &byte)| pattern.matches(byte))
    }

    /// Every offset in `haystack` where this pattern matches.
    ///
    /// Scanning is anchored on the first fully-known byte via `memchr`, so a
    /// pattern that begins with wildcards does not cost a full comparison at
    /// every offset of a multi-megabyte image.
    pub fn find_all(&self, haystack: &[u8]) -> Vec<usize> {
        let mut found = Vec::new();
        if haystack.len() < self.bytes.len() {
            return found;
        }
        let last_start = haystack.len() - self.bytes.len();

        let Some(anchor) = self.anchor else {
            // No single byte value to search for; compare at every offset.
            for start in 0..=last_start {
                if self.matches_at(haystack, start) {
                    found.push(start);
                }
            }
            return found;
        };

        let anchor_value = self.bytes[anchor].value;
        let mut cursor = anchor;
        while cursor < haystack.len() {
            let Some(hit) = memchr(anchor_value, &haystack[cursor..]) else {
                break;
            };
            let absolute = cursor + hit;
            // Where the pattern would have to start for its anchor to land here.
            if absolute >= anchor {
                let start = absolute - anchor;
                if start <= last_start && self.matches_at(haystack, start) {
                    found.push(start);
                }
            }
            cursor = absolute + 1;
        }
        found
    }

    /// The bytes a match covers, for capture extraction.
    pub fn slice_at<'a>(&self, haystack: &'a [u8], offset: usize) -> Option<&'a [u8]> {
        haystack.get(offset..offset + self.bytes.len())
    }
}

/// Minimal byte search. `memchr` is not a dependency here and the loop is
/// short enough that the compiler vectorizes it.
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&byte| byte == needle)
}

/// How to read a number out of the bytes a pattern matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    U16Le,
    U16Be,
    U32Le,
    U32Be,
    /// AArch64 `movz w<d>, #imm16`: the operand is bits 5..21 of a 32-bit
    /// little-endian instruction word, so it cannot be read as a plain integer.
    #[serde(rename = "arm64-movz-imm16")]
    Arm64MovzImm16,
    /// AArch64 `movz w0, #lo16` followed by `movk w0, #hi16, lsl #16` — how a
    /// constant too large for one instruction is loaded. Both words are
    /// validated, including the shift and destination register, before the
    /// halves are recombined.
    #[serde(rename = "arm64-movz-movk-imm32")]
    Arm64MovzMovkImm32,
    /// ARM (A32) `movw r0, #imm16`: the immediate is split across the
    /// instruction word — imm4 in bits 19:16, imm12 in bits 11:0 — so it
    /// cannot be read as a plain integer. The destination register is pinned
    /// to r0 by the pattern itself.
    #[serde(rename = "arm-movw-imm16")]
    ArmMovwImm16,
    /// MIPS16e2 `EXTEND; li v0, imm16`: four bytes big-endian, an EXTEND
    /// word around a LI word. The combined immediate is a bit permutation,
    /// not an integer read: the EXTEND word's low five bits land above the
    /// LI immediate and its upper six below it. The EXTEND opcode itself is
    /// validated here because the pattern's first byte only pins four of
    /// its five bits.
    #[serde(rename = "mips16-extend-li-imm16")]
    Mips16ExtendLiImm16,
}

/// Decode an AArch64 wide-immediate move, returning `(imm16, hw)`.
///
/// `top9` distinguishes the variants: MOVZ is `010100101`, MOVK is
/// `011100101`. `Rd` must be `w0`, since these patterns describe a function
/// returning a constant.
fn decode_wide_move(word: u32, top9: u32) -> Option<(u32, u32)> {
    if (word >> 23) & 0x1ff != top9 {
        return None;
    }
    if word & 0x1f != 0 {
        return None;
    }
    Some(((word >> 5) & 0xffff, (word >> 21) & 0x3))
}

const MOVZ_TOP9: u32 = 0b0_1010_0101;
const MOVK_TOP9: u32 = 0b0_1110_0101;

impl Encoding {
    /// Read the number from `window`, which is the pattern's captured span.
    pub fn read(self, window: &[u8]) -> Option<u64> {
        match self {
            Encoding::U16Le => window
                .get(..2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]) as u64),
            Encoding::U16Be => window
                .get(..2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]) as u64),
            Encoding::U32Le => window
                .get(..4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64),
            Encoding::U32Be => window
                .get(..4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64),
            Encoding::Arm64MovzImm16 => {
                let bytes = window.get(..4)?;
                let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let (imm, shift) = decode_wide_move(word, MOVZ_TOP9)?;
                // A shifted MOVZ loads the value into a different half of the
                // register; reading it as the whole number would be wrong.
                (shift == 0).then_some(imm as u64)
            }
            Encoding::ArmMovwImm16 => {
                let bytes = window.get(..4)?;
                let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                // The pattern pins the opcode; what is read here is only the
                // split immediate: imm4 in bits 19:16 over imm12 in 11:0.
                Some((u64::from((word >> 16) & 0xf) << 12) | u64::from(word & 0xfff))
            }
            Encoding::Mips16ExtendLiImm16 => {
                let bytes = window.get(..4)?;
                let extend = u16::from_be_bytes([bytes[0], bytes[1]]);
                let li = u16::from_be_bytes([bytes[2], bytes[3]]);
                // EXTEND: opcode 11110 in bits 15:11; the remaining eleven
                // bits are the upper part of the combined immediate.
                if extend >> 11 != 0b11110 {
                    return None;
                }
                let fields = extend & 0x7ff;
                // Measured against four real accessors (zstd 1.4.5, 1.4.9,
                // 1.5.2, 1.5.7 for mips_24kc): bits 4:0 land above the LI
                // immediate, bits 10:5 below it.
                let upper = ((fields & 0x1f) << 6) | ((fields >> 5) & 0x3f);
                Some((u64::from(upper) << 5) | u64::from(li & 0x1f))
            }
            Encoding::Arm64MovzMovkImm32 => {
                let bytes = window.get(..8)?;
                let low_word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let high_word = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                let (low, low_shift) = decode_wide_move(low_word, MOVZ_TOP9)?;
                let (high, high_shift) = decode_wide_move(high_word, MOVK_TOP9)?;
                if low_shift != 0 || high_shift != 1 {
                    return None;
                }
                Some(((high as u64) << 16) | low as u64)
            }
        }
    }
}

/// How a captured number becomes a version string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionFormula {
    /// `major * 10000 + minor * 100 + patch` — zstd's ZSTD_VERSION_NUMBER.
    #[serde(rename = "decimal-10000")]
    Decimal10000,
    /// `major * 1000000 + minor * 1000 + patch` — sqlite3's
    /// SQLITE_VERSION_NUMBER. A separate scheme, not a scaled version of the
    /// one above, which is why one formula cannot serve both.
    #[serde(rename = "decimal-1000000")]
    Decimal1000000,
    /// `major * 1000 + minor * 100 + patch * 10` — zlib's ZLIB_VERNUM, as hex
    /// nibbles: 0x1310 is 1.3.1.
    NibbleHex,
    /// `(major << 16) | (minor << 8) | patch` — curl's LIBCURL_VERSION_NUM.
    Packed8,
    /// `major * 10000000 + minor * 10000 + patch * 10 + stability` —
    /// liblzma's LZMA_VERSION_NUMBER, where the last digit is 0 alpha,
    /// 1 beta, 2 stable. The stability digit is dropped rather than rendered.
    #[serde(rename = "decimal-10000000-stability")]
    Decimal10000000Stability,
    /// `(major << 24) | (minor << 16) | (patch << 8)` — Mbed TLS's
    /// MBEDTLS_VERSION_NUMBER, which keeps a spare low byte.
    #[serde(rename = "packed8-hi")]
    Packed8Hi,
    /// `(major << 8) | minor` — for libraries that expose the two through
    /// separate accessors and have no combined constant at all.
    #[serde(rename = "major-minor")]
    MajorMinor,
}

impl VersionFormula {
    pub fn render(self, value: u64) -> Option<String> {
        match self {
            VersionFormula::Decimal10000 => {
                let major = value / 10000;
                let minor = (value % 10000) / 100;
                let patch = value % 100;
                (major > 0 && major < 100).then(|| format!("{major}.{minor}.{patch}"))
            }
            VersionFormula::Decimal1000000 => {
                let major = value / 1_000_000;
                let minor = (value % 1_000_000) / 1000;
                let patch = value % 1000;
                (major > 0 && major < 100).then(|| format!("{major}.{minor}.{patch}"))
            }
            VersionFormula::NibbleHex => {
                let major = (value >> 12) & 0xf;
                let minor = (value >> 8) & 0xf;
                let patch = (value >> 4) & 0xf;
                (major > 0).then(|| format!("{major}.{minor}.{patch}"))
            }
            VersionFormula::Decimal10000000Stability => {
                let major = value / 10_000_000;
                let minor = (value % 10_000_000) / 10_000;
                let patch = (value % 10_000) / 10;
                let stability = value % 10;
                (major > 0 && major < 100 && stability <= 2)
                    .then(|| format!("{major}.{minor}.{patch}"))
            }
            VersionFormula::Packed8Hi => {
                let major = (value >> 24) & 0xff;
                let minor = (value >> 16) & 0xff;
                let patch = (value >> 8) & 0xff;
                (major > 0 && major < 100).then(|| format!("{major}.{minor}.{patch}"))
            }
            VersionFormula::MajorMinor => {
                let major = (value >> 8) & 0xff;
                let minor = value & 0xff;
                (major > 0 && major < 100).then(|| format!("{major}.{minor}"))
            }
            VersionFormula::Packed8 => {
                let major = (value >> 16) & 0xff;
                let minor = (value >> 8) & 0xff;
                let patch = value & 0xff;
                (major > 0).then(|| format!("{major}.{minor}.{patch}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_hex_pattern_parses_and_matches_exactly() {
        let pattern = BytePattern::parse("60 21 85 52").expect("parses");
        assert_eq!(pattern.len(), 4);
        assert_eq!(
            pattern.find_all(&[0x00, 0x60, 0x21, 0x85, 0x52, 0xff]),
            vec![1]
        );
        assert!(pattern.find_all(&[0x60, 0x21, 0x85, 0x53]).is_empty());
    }

    #[test]
    fn whitespace_is_optional() {
        assert_eq!(
            BytePattern::parse("602185 52").expect("parses"),
            BytePattern::parse("60 21 85 52").expect("parses")
        );
    }

    #[test]
    fn a_full_byte_wildcard_matches_anything_in_that_position() {
        let pattern = BytePattern::parse(".. .. .. 52 c0 03 5f d6").expect("parses");
        let haystack = [0x60, 0x21, 0x85, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
        assert_eq!(pattern.find_all(&haystack), vec![0]);
    }

    #[test]
    fn a_nibble_wildcard_pins_half_a_byte() {
        // The whole point of masking at nibble granularity: pin the opcode,
        // leave the register free, so one pattern survives a recompile.
        let pattern = BytePattern::parse("5.").expect("parses");
        assert_eq!(pattern.find_all(&[0x4f, 0x50, 0x5f, 0x60]), vec![1, 2]);

        let high_free = BytePattern::parse(".2").expect("parses");
        assert_eq!(high_free.find_all(&[0x02, 0x12, 0x13, 0xf2]), vec![0, 1, 3]);
    }

    #[test]
    fn a_question_mark_is_accepted_as_a_wildcard_too() {
        assert_eq!(
            BytePattern::parse("?? 52").expect("parses"),
            BytePattern::parse(".. 52").expect("parses")
        );
    }

    #[test]
    fn a_pattern_of_only_wildcards_is_refused() {
        // It matches at every offset of every file, which is never intended
        // and is expensive to find out at scan time.
        assert_eq!(BytePattern::parse(".. .. .."), Err(PatternError::NoAnchor));
        assert_eq!(BytePattern::parse(""), Err(PatternError::Empty));
    }

    #[test]
    fn a_pattern_with_no_fully_known_byte_is_still_valid() {
        // `5. 2.` constrains real bits and is exactly the kind of pattern
        // nibble masking exists for. Rejecting it — or failing to scan it
        // because there is no byte value to search for — would throw away the
        // feature being ported.
        let pattern = BytePattern::parse("5. 2.").expect("parses");
        assert_eq!(pattern.find_all(&[0x00, 0x52, 0x2b, 0x00]), vec![1]);
        assert!(pattern.find_all(&[0x42, 0x2b]).is_empty());
    }

    #[test]
    fn half_a_byte_is_refused_rather_than_padded() {
        // Silently reading "5" as 0x05 or 0x50 would make a pattern mean
        // something its author did not write.
        assert!(matches!(
            BytePattern::parse("60 5"),
            Err(PatternError::OddNibbles(_))
        ));
        assert_eq!(
            BytePattern::parse("60 zz"),
            Err(PatternError::BadCharacter('z'))
        );
    }

    #[test]
    fn a_pattern_beginning_with_wildcards_still_finds_its_match() {
        // Scanning anchors on the first known byte; getting the offset
        // arithmetic wrong here silently loses every such match.
        let pattern = BytePattern::parse(".. .. ff ee").expect("parses");
        let haystack = [0x00, 0x11, 0x22, 0x33, 0xff, 0xee];
        assert_eq!(pattern.find_all(&haystack), vec![2]);
    }

    #[test]
    fn a_match_running_past_the_end_of_the_buffer_is_not_reported() {
        let pattern = BytePattern::parse("ff ee dd").expect("parses");
        assert!(pattern.find_all(&[0x00, 0xff, 0xee]).is_empty());
    }

    #[test]
    fn every_occurrence_is_found_not_just_the_first() {
        // Firmware routinely carries two builds of one library; stopping at
        // the first match hides the older one.
        let pattern = BytePattern::parse("ab cd").expect("parses");
        assert_eq!(
            pattern.find_all(&[0xab, 0xcd, 0x00, 0xab, 0xcd]),
            vec![0, 3]
        );
    }

    #[test]
    fn overlapping_matches_are_all_reported() {
        let pattern = BytePattern::parse("aa aa").expect("parses");
        assert_eq!(pattern.find_all(&[0xaa, 0xaa, 0xaa]), vec![0, 1]);
    }

    #[test]
    fn an_arm64_movz_operand_is_decoded_from_the_instruction_word() {
        // `movz w0, #0x290b` encoded little-endian, taken from a real
        // libzstd.1.5.7.dylib at _ZSTD_versionNumber.
        let instruction = [0x60, 0x21, 0x85, 0x52];
        assert_eq!(
            Encoding::Arm64MovzImm16.read(&instruction),
            Some(10507),
            "the operand is bits 5..21, not a plain little-endian integer"
        );
    }

    #[test]
    fn an_arm_movw_immediate_is_recombined_from_its_split_fields() {
        // `movw r0, #0x2906` — the instruction word 0xE3020906 stored
        // little-endian, taken from OpenWrt 23.05.5's libzstd 1.5.2 for
        // arm_cortex-a7 at ZSTD_versionNumber. The immediate is imm4 in
        // bits 19:16 over imm12 in bits 11:0, not a plain integer read.
        let instruction = [0x06, 0x09, 0x02, 0xe3];
        assert_eq!(Encoding::ArmMovwImm16.read(&instruction), Some(10_502));
    }

    #[test]
    fn an_arm64_movz_movk_pair_recombines_into_one_constant() {
        // Taken verbatim from Homebrew's liblzma.5.dylib at
        // _lzma_version_number: movz w0,#0x2920 / movk w0,#0x2fc,lsl #16 / ret.
        let bytes = [0x00, 0x24, 0x85, 0x52, 0x80, 0x5f, 0xa0, 0x72];
        assert_eq!(Encoding::Arm64MovzMovkImm32.read(&bytes), Some(50_080_032));

        // And from libsqlite3.3.53.3.dylib at _sqlite3_libversion_number.
        let sqlite = [0x60, 0xb9, 0x92, 0x52, 0xc0, 0x05, 0xa0, 0x72];
        assert_eq!(Encoding::Arm64MovzMovkImm32.read(&sqlite), Some(3_053_003));
    }

    #[test]
    fn a_movz_movk_pair_with_the_wrong_shift_is_refused() {
        // `movk ..., lsl #32` puts the half somewhere else entirely; combining
        // it as the high 16 bits would invent a number.
        let mut bytes = [0x00, 0x24, 0x85, 0x52, 0x80, 0x5f, 0xa0, 0x72];
        bytes[6] = 0xc0; // hw = 2, i.e. lsl #32
        assert_eq!(Encoding::Arm64MovzMovkImm32.read(&bytes), None);
    }

    #[test]
    fn a_movz_movk_pair_targeting_another_register_is_refused() {
        // These patterns describe a function returning a constant in w0. A
        // pair building a value in w3 is unrelated code.
        let mut bytes = [0x00, 0x24, 0x85, 0x52, 0x80, 0x5f, 0xa0, 0x72];
        bytes[0] |= 3; // Rd = w3
        assert_eq!(Encoding::Arm64MovzMovkImm32.read(&bytes), None);
    }

    #[test]
    fn a_movz_not_followed_by_a_movk_is_refused() {
        // movz then `ret` is a different, valid shape — but it is a 16-bit
        // constant, and reading the ret as a high half would be nonsense.
        let bytes = [0x60, 0x21, 0x85, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
        assert_eq!(Encoding::Arm64MovzMovkImm32.read(&bytes), None);
    }

    #[test]
    fn a_word_that_is_not_a_movz_decodes_to_nothing() {
        // Reading the operand bits out of some other instruction would invent
        // a version number from unrelated code.
        assert_eq!(
            Encoding::Arm64MovzImm16.read(&[0xc0, 0x03, 0x5f, 0xd6]),
            None
        );
        assert_eq!(Encoding::Arm64MovzImm16.read(&[0x00, 0x00]), None);
    }

    #[test]
    fn plain_integer_encodings_read_both_ways_round() {
        assert_eq!(Encoding::U16Le.read(&[0x0b, 0x29]), Some(0x290b));
        assert_eq!(Encoding::U16Be.read(&[0x29, 0x0b]), Some(0x290b));
        assert_eq!(
            Encoding::U32Le.read(&[0x0b, 0x29, 0x00, 0x00]),
            Some(0x290b)
        );
        assert_eq!(
            Encoding::U32Be.read(&[0x00, 0x00, 0x29, 0x0b]),
            Some(0x290b)
        );
        assert_eq!(Encoding::U32Le.read(&[0x01]), None);
    }

    #[test]
    fn the_zstd_constant_renders_as_its_release() {
        // 1 * 10000 + 5 * 100 + 7 — the value libzstd.1.5.7 actually returns.
        assert_eq!(
            VersionFormula::Decimal10000.render(10507).as_deref(),
            Some("1.5.7")
        );
        // sqlite encodes 3.46.1 as 3046001, a different scheme entirely. The
        // wrong formula must decline rather than produce "304.60.1".
        assert_eq!(VersionFormula::Decimal10000.render(3_046_001), None);
        assert_eq!(
            VersionFormula::Decimal1000000.render(3_046_001).as_deref(),
            Some("3.46.1")
        );
    }

    #[test]
    fn a_nonsensical_constant_does_not_become_a_version() {
        // Byte patterns match code, and code contains numbers that are not
        // versions. Refusing implausible ones is what keeps this from
        // manufacturing findings.
        assert_eq!(VersionFormula::Decimal10000.render(0), None);
        assert_eq!(VersionFormula::Decimal10000.render(9_999_999), None);
        assert_eq!(VersionFormula::NibbleHex.render(0x0310), None);
        assert_eq!(VersionFormula::Packed8.render(0), None);
    }

    #[test]
    fn the_lzma_constant_renders_without_its_stability_digit() {
        // LZMA_VERSION_NUMBER ends in 0 alpha, 1 beta, 2 stable. 50080032 is
        // 5.8.3 stable; the trailing 2 is not part of the version.
        assert_eq!(
            VersionFormula::Decimal10000000Stability
                .render(50_080_032)
                .as_deref(),
            Some("5.8.3")
        );
        assert_eq!(
            VersionFormula::Decimal10000000Stability
                .render(50_080_012)
                .as_deref(),
            Some("5.8.1")
        );
        // 3..=9 is not a stability level, so this is some other number.
        assert_eq!(
            VersionFormula::Decimal10000000Stability.render(50_080_037),
            None
        );
    }

    #[test]
    fn the_sqlite_constant_renders_as_its_release() {
        assert_eq!(
            VersionFormula::Decimal1000000.render(3_046_001).as_deref(),
            Some("3.46.1")
        );
        assert_eq!(
            VersionFormula::Decimal1000000.render(3_053_003).as_deref(),
            Some("3.53.3")
        );
    }

    #[test]
    fn the_mbedtls_constant_renders_without_its_spare_byte() {
        // MBEDTLS_VERSION_NUMBER is 0xMMmmpp00; the trailing byte is reserved,
        // not part of the version.
        assert_eq!(
            VersionFormula::Packed8Hi.render(0x0306_0500).as_deref(),
            Some("3.6.5")
        );
        assert_eq!(VersionFormula::Packed8Hi.render(0), None);
    }

    #[test]
    fn a_major_minor_pair_renders_as_two_components() {
        // nettle has no combined constant — major and minor come from two
        // separate one-instruction accessors.
        assert_eq!(
            VersionFormula::MajorMinor.render(0x030a).as_deref(),
            Some("3.10")
        );
        assert_eq!(VersionFormula::MajorMinor.render(0x0008), None, "no major");
    }

    #[test]
    fn the_zlib_and_curl_constants_render_as_their_releases() {
        assert_eq!(
            VersionFormula::NibbleHex.render(0x1310).as_deref(),
            Some("1.3.1")
        );
        assert_eq!(
            VersionFormula::Packed8.render(0x080e01).as_deref(),
            Some("8.14.1")
        );
    }
}
