//! Berkeley DB hash databases, read far enough to list their values.
//!
//! rpm kept its package database in a Berkeley DB hash file
//! (`/var/lib/rpm/Packages`) until the move to SQLite, so RHEL 7 and 8, Rocky
//! and Alma 8, and Amazon Linux 2 images still carry one. Each value is one
//! package header. Only what reading values needs is implemented:
//!
//! - page 0 is the hash metadata page: magic `0x00061561` at byte 12 (whose
//!   byte order is the file's), page size at 20, last page number at 32;
//! - hash pages (type 2 or 13) hold an index of item offsets after a 26-byte
//!   header, keys and values alternating;
//! - a value is either inline (`H_KEYDATA`, type 1) or a pointer to a chain of
//!   overflow pages (`H_OFFPAGE`, type 3, type 7 pages), each holding
//!   `hf_offset` bytes of data after its header and naming the next page.
//!
//! The file is untrusted image content: every offset is checked, overflow
//! chains are bounded and loop-checked, and values are capped.

/// Largest single value, matching the rpm header data cap.
pub const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;

/// One stored key and its value.
pub type Entry = (Vec<u8>, Vec<u8>);

/// Every value in the database, in page order.
pub fn values(bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    Ok(entries(bytes)?
        .into_iter()
        .map(|(_, value)| value)
        .collect())
}

/// Every key and value in the database, in page order. Keys stored off-page
/// (which rpm never writes) come back empty.
pub fn entries(bytes: &[u8]) -> Result<Vec<Entry>, &'static str> {
    entries_and_skipped(bytes).map(|(entries, _)| entries)
}

/// [`entries`], plus how many values were of a kind this reader does not
/// decode (duplicate sets, `H_DUPLICATE`/`H_OFFDUP`), so callers can say so.
pub fn entries_and_skipped(bytes: &[u8]) -> Result<(Vec<Entry>, usize), &'static str> {
    const HASH_MAGIC: u32 = 0x0006_1561;
    const PAGE_HEADER: usize = 26;
    const P_HASH_UNSORTED: u8 = 2;
    const P_OVERFLOW: u8 = 7;
    const P_HASHMETA: u8 = 8;
    const P_HASH: u8 = 13;
    const H_KEYDATA: u8 = 1;
    const H_OFFPAGE: u8 = 3;

    let magic = bytes.get(12..16).ok_or("not a Berkeley DB file")?;
    let big_endian = if u32::from_le_bytes(magic.try_into().unwrap()) == HASH_MAGIC {
        false
    } else if u32::from_be_bytes(magic.try_into().unwrap()) == HASH_MAGIC {
        true
    } else {
        return Err("not a Berkeley DB hash database");
    };
    let u16_at = |page: &[u8], at: usize| -> Option<u16> {
        let raw: [u8; 2] = page.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if big_endian {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        })
    };
    let u32_at = |page: &[u8], at: usize| -> Option<u32> {
        let raw: [u8; 4] = page.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        })
    };

    let page_size = u32_at(bytes, 20).ok_or("truncated metadata page")? as usize;
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err("Berkeley DB page size is out of range");
    }
    if bytes.get(24) != Some(&0) {
        return Err("encrypted Berkeley DB databases are not read");
    }
    if bytes.get(25) != Some(&P_HASHMETA) {
        return Err("Berkeley DB metadata page has the wrong type");
    }
    let page_count = bytes.len() / page_size;
    let last_page = u32_at(bytes, 32).ok_or("truncated metadata page")? as usize;
    if last_page >= page_count {
        return Err("Berkeley DB claims more pages than the file holds");
    }
    let page = |number: usize| -> Option<&[u8]> {
        let start = number.checked_mul(page_size)?;
        bytes.get(start..start.checked_add(page_size)?)
    };

    // Every overflow page belongs to one chain. Refusing reuse stops loops
    // and keeps a crafted file from multiplying one chain into many values.
    let mut claimed = vec![false; page_count];
    let mut values = Vec::new();
    let mut skipped = 0usize;
    for number in 1..=last_page {
        let hash_page = page(number).ok_or("Berkeley DB page is out of range")?;
        if !matches!(hash_page[25], P_HASH | P_HASH_UNSORTED) {
            continue;
        }
        let entries = u16_at(hash_page, 20).ok_or("truncated hash page")? as usize;
        // Items are laid down from the page end, so their offsets strictly
        // descend and sit between the index and the page end. Checking that
        // once bounds every inline item to its own span: the bytes copied
        // out of a page can never exceed the page.
        let mut offsets = Vec::with_capacity(entries);
        for index in 0..entries {
            let at = u16_at(hash_page, PAGE_HEADER + index * 2)
                .ok_or("hash page index is truncated")? as usize;
            let above = offsets.last().copied().unwrap_or(page_size);
            if at < PAGE_HEADER + entries * 2 || at >= above {
                return Err("hash page items are out of order or outside their page");
            }
            offsets.push(at);
        }
        let offset = |index: usize| -> Result<usize, &'static str> {
            offsets
                .get(index)
                .copied()
                .ok_or("hash page index is truncated")
        };
        // Keys and values alternate; values are the odd items. Items grow
        // down from the page end, so an inline item runs up to the start of
        // the item before it (or the page end, for the first).
        let inline = |index: usize| -> Result<Option<Vec<u8>>, &'static str> {
            let at = offset(index)?;
            if hash_page[at] != H_KEYDATA {
                return Ok(None);
            }
            let end = if index == 0 {
                page_size
            } else {
                offset(index - 1)?
            };
            if end <= at {
                return Err("hash page items overlap");
            }
            Ok(Some(hash_page[at + 1..end].to_vec()))
        };
        for value_index in (1..entries).step_by(2) {
            let key = inline(value_index - 1)?.unwrap_or_default();
            let at = offset(value_index)?;
            match hash_page[at] {
                H_KEYDATA => {
                    let value = inline(value_index)?.unwrap_or_default();
                    values.push((key, value));
                }
                H_OFFPAGE => {
                    let mut next =
                        u32_at(hash_page, at + 4).ok_or("off-page item is truncated")? as usize;
                    let total =
                        u32_at(hash_page, at + 8).ok_or("off-page item is truncated")? as usize;
                    if total > MAX_VALUE_BYTES {
                        return Err("Berkeley DB value is larger than the cap");
                    }
                    let mut value = Vec::with_capacity(total);
                    while next != 0 {
                        if next >= page_count || claimed[next] {
                            return Err("Berkeley DB overflow chain loops or leaves the file");
                        }
                        claimed[next] = true;
                        let overflow = page(next).ok_or("Berkeley DB page is out of range")?;
                        if overflow[25] != P_OVERFLOW {
                            return Err("Berkeley DB overflow chain reaches a non-overflow page");
                        }
                        let used = u16_at(overflow, 22).ok_or("truncated overflow page")? as usize;
                        let data = overflow
                            .get(PAGE_HEADER..PAGE_HEADER + used)
                            .ok_or("Berkeley DB overflow page claims more data than it holds")?;
                        if value.len() + data.len() > total {
                            return Err("Berkeley DB overflow chain is longer than its value");
                        }
                        value.extend_from_slice(data);
                        next = u32_at(overflow, 16).ok_or("truncated overflow page")? as usize;
                    }
                    if value.len() != total {
                        return Err("Berkeley DB overflow chain is shorter than its value");
                    }
                    values.push((key, value));
                }
                _ => skipped += 1,
            }
        }
    }
    Ok((values, skipped))
}

/// Encode values as a little-endian hash database with off-page values.
/// Test support for the image scanner, which builds rpm `Packages` files to
/// exercise reading them.
#[doc(hidden)]
pub fn encode_for_tests(values: &[Vec<u8>]) -> Vec<u8> {
    // As rpm writes it: key 0 holds the next header instance number.
    let mut entries = vec![(0u32, (values.len() as u32 + 1).to_le_bytes().to_vec(), true)];
    entries.extend(
        values
            .iter()
            .enumerate()
            .map(|(index, value)| (index as u32 + 1, value.clone(), false)),
    );
    Writer::new(4096, false).build(&entries)
}

const HEADER: usize = 26;

/// A hash database holding `values`: a metadata page, one hash page of
/// key/value items, and overflow chains for the values marked off-page.
struct Writer {
    page_size: usize,
    big_endian: bool,
    pages: Vec<Vec<u8>>,
}

impl Writer {
    fn new(page_size: usize, big_endian: bool) -> Self {
        Self {
            page_size,
            big_endian,
            pages: vec![vec![0; page_size]],
        }
    }
    fn u16(&self, page: &mut [u8], at: usize, value: u16) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        page[at..at + 2].copy_from_slice(&bytes);
    }
    fn u32(&self, page: &mut [u8], at: usize, value: u32) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        page[at..at + 4].copy_from_slice(&bytes);
    }
    /// Write `data` as an overflow chain; returns its first page number.
    fn overflow(&mut self, data: &[u8]) -> u32 {
        let room = self.page_size - HEADER;
        let first = self.pages.len() as u32;
        let chunks: Vec<&[u8]> = data.chunks(room).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let mut page = vec![0; self.page_size];
            let number = self.pages.len() as u32;
            self.u32(&mut page, 8, number);
            let next = if i + 1 < chunks.len() { number + 1 } else { 0 };
            self.u32(&mut page, 16, next);
            self.u16(&mut page, 22, chunk.len() as u16);
            page[25] = 7;
            page[HEADER..HEADER + chunk.len()].copy_from_slice(chunk);
            self.pages.push(page);
        }
        first
    }
    /// Build the file. `inline` values are stored on the hash page.
    fn build(mut self, values: &[(u32, Vec<u8>, bool)]) -> Vec<u8> {
        // Overflow chains first, so their page numbers are known.
        let mut items: Vec<Vec<u8>> = Vec::new();
        for (number, value, inline) in values {
            let mut key = vec![1u8];
            let mut scratch = vec![0u8; 4];
            self.u32(&mut scratch, 0, *number);
            key.extend_from_slice(&scratch);
            items.push(key);
            if *inline {
                let mut item = vec![1u8];
                item.extend_from_slice(value);
                items.push(item);
            } else {
                let first = self.overflow(value);
                let mut item = vec![3u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                let mut scratch = vec![0u8; 12];
                self.u32(&mut scratch, 4, first);
                self.u32(&mut scratch, 8, value.len() as u32);
                item[4..].copy_from_slice(&scratch[4..]);
                items.push(item);
            }
        }
        let hash_number = self.pages.len() as u32;
        let mut page = vec![0; self.page_size];
        self.u32(&mut page, 8, hash_number);
        self.u16(&mut page, 20, items.len() as u16);
        page[25] = 13;
        // Items grow down from the end of the page.
        let mut end = self.page_size;
        for (i, item) in items.iter().enumerate() {
            let start = end - item.len();
            page[start..end].copy_from_slice(item);
            self.u16(&mut page, HEADER + i * 2, start as u16);
            end = start;
        }
        self.u16(&mut page, 22, end as u16);
        self.pages.push(page);

        let last = self.pages.len() as u32 - 1;
        let mut meta = std::mem::take(&mut self.pages[0]);
        self.u32(&mut meta, 12, 0x0006_1561);
        self.u32(&mut meta, 16, 9);
        self.u32(&mut meta, 20, self.page_size as u32);
        meta[25] = 8;
        self.u32(&mut meta, 32, last);
        self.pages[0] = meta;
        self.pages.concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_like(size: usize, seed: u8) -> Vec<u8> {
        (0..size)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn reads_values_across_overflow_chains() {
        let big = header_like(3000, 1); // six 512-byte pages
        let small = header_like(400, 2); // one page
        let file =
            Writer::new(512, false).build(&[(1, big.clone(), false), (2, small.clone(), false)]);
        assert_eq!(values(&file), Ok(vec![big, small]));
    }

    #[test]
    fn inline_values_are_read_too() {
        let tiny = header_like(40, 3);
        let big = header_like(1200, 4);
        let file =
            Writer::new(512, false).build(&[(1, tiny.clone(), true), (2, big.clone(), false)]);
        assert_eq!(values(&file), Ok(vec![tiny, big]));
    }

    #[test]
    fn big_and_little_endian_files_both_read() {
        let value = header_like(2000, 5);
        for big_endian in [false, true] {
            let file = Writer::new(1024, big_endian).build(&[(1, value.clone(), false)]);
            assert_eq!(
                values(&file),
                Ok(vec![value.clone()]),
                "big endian: {big_endian}"
            );
        }
    }

    #[test]
    fn foreign_files_are_refused() {
        assert!(values(b"").is_err());
        assert!(values(&[0u8; 4096]).is_err());
        // A btree database (magic 0x053162) is not a hash database.
        let mut btree = Writer::new(512, false).build(&[(1, header_like(10, 6), true)]);
        btree[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        assert!(values(&btree).is_err());
        // A page size that is not a power of two between 512 and 65536.
        let mut odd = Writer::new(512, false).build(&[(1, header_like(10, 7), true)]);
        odd[20..24].copy_from_slice(&1000u32.to_le_bytes());
        assert!(values(&odd).is_err());
    }

    #[test]
    fn items_must_strictly_descend_inside_their_page() {
        // Every key pointing at one low offset and every value at one high
        // offset would let each key copy the same span again: a few MB of
        // file becoming gigabytes of keys.
        let mut file = Writer::new(512, false).build(&[(1, header_like(8, 9), true)]);
        assert!(values(&file).is_ok(), "intact before the damage");
        let page = file.len() - 512;
        let pairs = 50usize;
        let writer = Writer::new(512, false);
        let low = HEADER + pairs * 4;
        let high = 512 - 12;
        let mut hash = vec![0u8; 512];
        writer.u16(&mut hash, 20, (pairs * 2) as u16);
        writer.u16(&mut hash, 22, low as u16);
        hash[25] = 13;
        hash[low] = 1; // H_KEYDATA
        hash[high] = 3; // H_OFFPAGE, page 0, length 0
        for pair in 0..pairs {
            writer.u16(&mut hash, HEADER + pair * 4, low as u16);
            writer.u16(&mut hash, HEADER + pair * 4 + 2, high as u16);
        }
        file[page..].copy_from_slice(&hash);
        assert!(values(&file).is_err());
    }

    #[test]
    fn duplicate_value_items_are_counted_not_dropped() {
        // H_DUPLICATE (2) and H_OFFDUP (4) values are not read; they must be
        // counted so the caller can say so, not silently vanish.
        let mut file = Writer::new(512, false).build(&[
            (1, header_like(20, 11), true),
            (2, header_like(20, 12), true),
        ]);
        let page = file.len() - 512;
        let offsets: Vec<usize> = (0..4)
            .map(|i| {
                u16::from_le_bytes([file[page + HEADER + i * 2], file[page + HEADER + i * 2 + 1]])
                    as usize
            })
            .collect();
        file[page + offsets[3]] = 2; // the second value becomes H_DUPLICATE
        let (entries, skipped) = entries_and_skipped(&file).expect("readable");
        assert_eq!(entries.len(), 1);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn looping_or_out_of_range_chains_stop_with_an_error() {
        let value = header_like(3000, 8);
        let good = Writer::new(512, false).build(&[(1, value, false)]);
        assert!(values(&good).is_ok(), "intact before the damage");
        // Page 1 is the first overflow page; point its successor back at itself.
        let mut looping = good.clone();
        looping[512 + 16..512 + 20].copy_from_slice(&1u32.to_le_bytes());
        assert!(values(&looping).is_err());
        // Point it past the end of the file.
        let mut beyond = good.clone();
        beyond[512 + 16..512 + 20].copy_from_slice(&9999u32.to_le_bytes());
        assert!(values(&beyond).is_err());
        // An overflow page claiming more data than a page holds.
        let mut overfull = good.clone();
        overfull[512 + 22..512 + 24].copy_from_slice(&600u16.to_le_bytes());
        assert!(values(&overfull).is_err());
        // A last page number beyond the file.
        let mut short = good.clone();
        short[32..36].copy_from_slice(&500u32.to_le_bytes());
        assert!(values(&short).is_err());
        // A hash page index pointing outside its page.
        let hash_page = good.len() - 512;
        let mut wild = good.clone();
        wild[hash_page + HEADER + 2..hash_page + HEADER + 4]
            .copy_from_slice(&0xfff0u16.to_le_bytes());
        assert!(values(&wild).is_err());
    }
}
