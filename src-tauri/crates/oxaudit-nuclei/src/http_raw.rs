//! Parsing of `raw:` HTTP requests, after interpolation.

/// A raw request split into its parts. Header and body bytes are kept as
/// written; the host builds the wire form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RawRequest {
    pub method: String,
    /// Request URI as written; empty for the "blank URI" form
    /// (`GET HTTP/1.1`), which means the target itself.
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// `@Host:` override.
    pub host_override: Option<String>,
    /// `@timeout:` in milliseconds.
    pub timeout_ms: Option<u64>,
    /// `@tls-sni:` override.
    pub tls_sni: Option<String>,
}

fn parse_duration_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let (num, unit) = s.split_at(split);
    let value: f64 = num.parse().ok()?;
    let scale = match unit.trim() {
        "ms" => 1.0,
        "s" => 1000.0,
        "m" => 60_000.0,
        "h" => 3_600_000.0,
        _ => return None,
    };
    let ms = value * scale;
    (ms.is_finite() && (0.0..=3_600_000.0).contains(&ms)).then_some(ms as u64)
}

pub(crate) fn parse_raw(input: &[u8]) -> Result<RawRequest, String> {
    let mut req = RawRequest::default();
    let mut pos = 0usize;
    // Returns the next line (without terminator) and advances `pos`.
    let next_line = |pos: &mut usize| -> Option<&[u8]> {
        if *pos >= input.len() {
            return None;
        }
        let rest = &input[*pos..];
        let (line, used) = match rest.iter().position(|b| *b == b'\n') {
            Some(i) => (&rest[..i], i + 1),
            None => (rest, rest.len()),
        };
        *pos += used;
        Some(line.strip_suffix(b"\r").unwrap_or(line))
    };

    // Annotations and the request line.
    let request_line = loop {
        let Some(line) = next_line(&mut pos) else {
            return Err("no request line".into());
        };
        let text = String::from_utf8_lossy(line);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(annotation) = trimmed.strip_prefix('@') {
            let (name, value) = annotation
                .split_once(':')
                .ok_or_else(|| format!("annotation without a value: @{annotation}"))?;
            let value = value.trim().to_string();
            match name.trim().to_ascii_lowercase().as_str() {
                "host" => req.host_override = Some(value),
                "tls-sni" => req.tls_sni = Some(value),
                "timeout" => {
                    req.timeout_ms = Some(
                        parse_duration_ms(&value)
                            .ok_or_else(|| format!("invalid @timeout `{value}`"))?,
                    );
                }
                other => return Err(format!("unsupported annotation @{other}")),
            }
            continue;
        }
        break trimmed.to_string();
    };

    let tokens: Vec<&str> = request_line.split_whitespace().collect();
    match tokens.as_slice() {
        [method, version] if version.starts_with("HTTP/") => {
            req.method = (*method).to_string();
        }
        [method, uri] => {
            req.method = (*method).to_string();
            req.uri = (*uri).to_string();
        }
        [method, uri, version] if version.starts_with("HTTP/") => {
            req.method = (*method).to_string();
            req.uri = (*uri).to_string();
        }
        _ => return Err(format!("malformed request line `{request_line}`")),
    }
    if req.method.is_empty() || !req.method.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(format!("invalid method `{}`", req.method));
    }
    req.method.make_ascii_uppercase();

    // Headers until the first blank line.
    let mut saw_blank = false;
    while let Some(line) = next_line(&mut pos) {
        if line.is_empty() {
            saw_blank = true;
            break;
        }
        let text = String::from_utf8_lossy(line).into_owned();
        if text.starts_with([' ', '\t']) {
            return Err("folded header lines are not supported".into());
        }
        let (name, value) = text
            .split_once(':')
            .ok_or_else(|| format!("malformed header line `{text}`"))?;
        let name = name.trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(format!("invalid header name `{name}`"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        req.headers
            .push((name.to_string(), value.trim().to_string()));
    }
    if saw_blank {
        let mut body = input.get(pos..).unwrap_or_default().to_vec();
        // The trailing newline of a YAML block scalar is not part of the body.
        if body.ends_with(b"\r\n") {
            body.truncate(body.len() - 2);
        } else if body.ends_with(b"\n") {
            body.truncate(body.len() - 1);
        }
        req.body = body;
    }
    Ok(req)
}
