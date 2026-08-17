//! Minimal SSE decoder for OpenAI-compatible streaming, modeled on
//! y-agent's `sse.rs`: incremental byte buffering with multi-byte UTF-8
//! safety (we only cut events at `\n\n` / `\r\n\r\n` ASCII boundaries, so a
//! split multibyte character can never be truncated) and `data:` line
//! extraction. Malformed events are skipped without killing the stream.

pub struct SseDecoder {
    buf: Vec<u8>,
}

impl Default for SseDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SseDecoder {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(8192) }
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
            let end = find_boundary(&self.buf)?;
            let chunk: Vec<u8> = self.buf[..end].to_vec();
            let consumed = end + 2; // \n\n
            self.buf.drain(..consumed.min(self.buf.len()));

            let text = String::from_utf8_lossy(&chunk);
            let mut data_lines: Vec<String> = Vec::new();
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("data:") {
                    data_lines.push(rest.trim_start().to_string());
                }
                // `event:`, `id:`, `retry:`, comments — ignored for chat streams
            }
            if data_lines.is_empty() {
                continue; // an event with no data (e.g. a comment) — keep reading
            }
            return Some(data_lines.join("\n"));
        }
    }
}

/// Find the first `\n\n` or `\r\n\r\n` boundary; returns its start index.
fn find_boundary(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        if buf[i] == b'\r' && i + 3 < buf.len() && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n'
        {
            return Some(i);
        }
        i += 1;
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
}
