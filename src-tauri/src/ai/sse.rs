//! Minimal SSE decoder for OpenAI-compatible streaming, modeled on
//! y-agent's `sse.rs`: incremental byte buffering with multi-byte UTF-8
//! safety (events end only at ASCII line boundaries) and `data:` line
//! extraction. LF, CRLF, and CR line endings may cross network chunks.

pub struct SseDecoder {
    buf: Vec<u8>,
    at_start: bool,
}

impl Default for SseDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SseDecoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(8192),
            at_start: true,
        }
    }

    /// Append raw bytes from the network.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > 16 * 1024 * 1024 {
            // pathological server; drop the head to bound memory
            let keep = self.buf.len() - 1024 * 1024;
            self.buf.drain(..keep);
        }
    }

    /// Extract the next complete SSE event's payload: the joined content of
    /// its `data:` lines (already trimmed of the `data:` prefix), or `None`
    /// when no complete event is buffered yet.
    pub fn next_data(&mut self) -> Option<String> {
        loop {
            let (end, consumed) = find_boundary(&self.buf)?;
            let event = String::from_utf8_lossy(&self.buf[..end]);
            let text = if self.at_start {
                self.at_start = false;
                event.strip_prefix('\u{feff}').unwrap_or(&event)
            } else {
                &event
            };
            let mut data = String::new();
            let mut has_data = false;
            for line in text.split(['\r', '\n']) {
                let value = match line.strip_prefix("data:") {
                    Some(rest) => rest.strip_prefix(' ').unwrap_or(rest),
                    None if line == "data" => "",
                    _ => continue, // comments and other fields do not carry chat data
                };
                if has_data {
                    data.push('\n');
                }
                data.push_str(value);
                has_data = true;
            }
            self.buf.drain(..consumed);
            if has_data {
                return Some(data);
            }
        }
    }
}

/// Locate a blank line, treating CRLF as one line ending even across pushes.
/// Returns the event's end and the number of bytes to consume.
fn find_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    let mut line_start = 0;
    let mut i = 0;
    while i < buf.len() {
        if !matches!(buf[i], b'\r' | b'\n') {
            i += 1;
            continue;
        }
        let next = i + if buf[i] == b'\r' && buf.get(i + 1) == Some(&b'\n') {
            2
        } else {
            1
        };
        if i == line_start {
            return Some((line_start, next));
        }
        line_start = next;
        i = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_single_event() {
        let mut d = SseDecoder::new();
        d.push(b"data: {\"a\":1}\n\n");
        assert_eq!(d.next_data().as_deref(), Some("{\"a\":1}"));
        assert!(d.next_data().is_none());
    }

    #[test]
    fn partial_chunk_waits() {
        let mut d = SseDecoder::new();
        d.push(b"data: hel");
        assert!(d.next_data().is_none());
        d.push(b"lo\n\n");
        assert_eq!(d.next_data().as_deref(), Some("hello"));
    }

    #[test]
    fn crlf_boundary() {
        let mut d = SseDecoder::new();
        d.push(b"data: x\r\n\r\n");
        assert_eq!(d.next_data().as_deref(), Some("x"));
    }

    #[test]
    fn multiple_events_and_done() {
        let mut d = SseDecoder::new();
        d.push(b"data: one\n\ndata: [DONE]\n\n");
        assert_eq!(d.next_data().as_deref(), Some("one"));
        assert_eq!(d.next_data().as_deref(), Some("[DONE]"));
        assert!(d.next_data().is_none());
    }

    #[test]
    fn joined_data_lines() {
        let mut d = SseDecoder::new();
        d.push(b"data: a\ndata: b\n\n");
        assert_eq!(d.next_data().as_deref(), Some("a\nb"));
    }

    #[test]
    fn multibyte_split_across_chunks() {
        // '€' is 3 bytes (e2 82 ac); split mid-sequence across pushes.
        let mut d = SseDecoder::new();
        d.push(b"data: \xe2");
        assert!(d.next_data().is_none());
        d.push(b"\x82\xac\n\n");
        assert_eq!(d.next_data().as_deref(), Some("€"));
    }

    #[test]
    fn done_flag() {
        let mut d = SseDecoder::new();
        d.push(b"data: [DONE]\n\n");
        assert_eq!(d.next_data().as_deref(), Some("[DONE]"));
    }

    #[test]
    fn line_endings_and_utf8_survive_every_chunk_split() {
        for ending in ["\n", "\r\n", "\r", "\r\n\n", "\n\r\n"] {
            let wire = format!(
                ": heartbeat{ending}{ending}data: €{ending}{ending}data: [DONE]{ending}{ending}"
            );
            for split in 0..=wire.len() {
                let mut decoder = SseDecoder::new();
                let mut events = Vec::new();
                for chunk in [&wire.as_bytes()[..split], &wire.as_bytes()[split..]] {
                    decoder.push(chunk);
                    while let Some(data) = decoder.next_data() {
                        events.push(data);
                    }
                }
                assert_eq!(events, ["€", "[DONE]"], "ending {ending:?}, split {split}");
            }
        }
    }

    #[test]
    fn data_fields_preserve_whitespace_and_empty_lines() {
        let mut decoder = SseDecoder::new();
        decoder.push(b"data:  indented\rdata:\tvalue\rdata\rdata: end\r\r");
        assert_eq!(
            decoder.next_data().as_deref(),
            Some(" indented\n\tvalue\n\nend")
        );
        assert!(decoder.next_data().is_none());
    }

    #[test]
    fn only_a_stream_leading_bom_is_ignored_across_chunks() {
        let wire = "\u{feff}data: first\n\n\u{feff}data: ignored\n\ndata: \u{feff}second\n\n";
        for split in 0..=wire.len() {
            let mut decoder = SseDecoder::new();
            let mut events = Vec::new();
            for chunk in [&wire.as_bytes()[..split], &wire.as_bytes()[split..]] {
                decoder.push(chunk);
                while let Some(data) = decoder.next_data() {
                    events.push(data);
                }
            }
            assert_eq!(events, ["first", "\u{feff}second"], "split {split}");
        }
    }
}
