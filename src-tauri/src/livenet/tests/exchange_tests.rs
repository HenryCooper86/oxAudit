use oxaudit_nuclei::HttpResponseData;

use crate::livenet::exchange::{
    is_credential_param, is_sensitive_header, redact_url, render_bytes, render_http_request,
    render_http_response, truncate_str, SentHttpRequest, EXCERPT_CAP, REDACTED,
};

#[test]
fn sensitive_header_table() {
    for name in [
        "Authorization",
        "authorization",
        "Proxy-Authorization",
        "Cookie",
        "Set-Cookie",
        "X-Api-Key",
        "X-Auth-Token",
        "X-CSRF-Token",
        "x-access-token",
        "Client-Secret",
        "X-Password",
        "X-Api_Key",
        "apikey",
        "X-Vendor-ApiKey",
        "db-passwd",
    ] {
        assert!(is_sensitive_header(name), "{name} must be redacted");
    }
    for name in [
        "Content-Type",
        "User-Agent",
        "Host",
        "Accept",
        "X-Request-Id",
        "Location",
        "Server",
    ] {
        assert!(!is_sensitive_header(name), "{name} must be kept");
    }
}

#[test]
fn request_values_are_redacted() {
    let req = SentHttpRequest {
        method: "POST".into(),
        url: "http://app.test/login".into(),
        headers: vec![
            ("Authorization".into(), "Bearer s3cr3t-bearer".into()),
            ("Cookie".into(), "session=abc123".into()),
            ("X-Custom-Token".into(), "tok-999".into()),
            ("X-Request-Id".into(), "req-1".into()),
        ],
        body: b"user=admin".to_vec(),
    };
    let (text, truncated) = render_http_request(&req);
    assert!(!truncated);
    assert!(text.starts_with("POST http://app.test/login HTTP/1.1\r\n"));
    assert!(text.contains(&format!("Authorization: {REDACTED}")));
    assert!(text.contains(&format!("Cookie: {REDACTED}")));
    assert!(text.contains(&format!("X-Custom-Token: {REDACTED}")));
    assert!(text.contains("X-Request-Id: req-1"));
    for secret in ["s3cr3t-bearer", "abc123", "tok-999"] {
        assert!(!text.contains(secret), "{secret} leaked");
    }
    assert!(text.ends_with("user=admin"));
}

#[test]
fn response_values_are_redacted_and_capped() {
    let resp = HttpResponseData {
        status: 200,
        reason: "OK".into(),
        version: "HTTP/1.1".into(),
        headers: vec![
            ("Set-Cookie".into(), "sid=very-secret; HttpOnly".into()),
            ("Server".into(), "test".into()),
        ],
        body: "x".repeat(10_000).into_bytes(),
        ..HttpResponseData::default()
    };
    let (text, truncated) = render_http_response(&resp, false);
    assert!(truncated);
    assert!(text.len() <= EXCERPT_CAP, "{}", text.len());
    assert!(text.ends_with("[truncated]"));
    assert!(text.contains(&format!("Set-Cookie: {REDACTED}")));
    assert!(!text.contains("very-secret"));
    assert!(text.contains("Server: test"));

    let small = HttpResponseData {
        status: 404,
        body: b"nope".to_vec(),
        ..HttpResponseData::default()
    };
    let (text, truncated) = render_http_response(&small, true);
    assert!(truncated, "the body cap flag carries through");
    assert!(text.ends_with("nope"));
}

#[test]
fn request_excerpt_is_capped() {
    let req = SentHttpRequest {
        method: "GET".into(),
        url: format!("http://app.test/{}", "p".repeat(10_000)),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let (text, truncated) = render_http_request(&req);
    assert!(truncated);
    assert!(text.len() <= EXCERPT_CAP);
}

#[test]
fn binary_bodies_are_a_hex_preview() {
    let bytes: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
    let (text, truncated) = render_bytes(&bytes, 512);
    assert!(text.starts_with("[binary, 5000 bytes]\n"));
    assert!(text.contains("00000000  00 01 02 03"));
    assert!(truncated);
    assert!(text.len() <= 512);
    let (text, truncated) = render_bytes(b"\xff\xfe\x00ok", 512);
    assert!(text.starts_with("[binary, 5 bytes]"));
    assert!(!truncated);
    let (text, _) = render_bytes("plain text\r\nwith lines\t".as_bytes(), 512);
    assert_eq!(text, "plain text\r\nwith lines\t");
}

#[test]
fn truncation_respects_char_boundaries() {
    let (s, cut) = truncate_str("ééé", 3);
    assert_eq!(s, "é");
    assert!(cut);
    let (s, cut) = truncate_str("abc", 3);
    assert_eq!(s, "abc");
    assert!(!cut);
}

#[test]
fn urls_lose_user_info_and_credential_query_values() {
    assert_eq!(
        redact_url(
            "https://alice:pw@h.test:8443/p?q=1&api_key=abc&Token=x&sig=&SESSION_id=s&page=2#access_token=t&x=1",
            false
        ),
        "https://[REDACTED]@h.test:8443/p?q=1&api_key=[REDACTED]&Token=[REDACTED]&sig=&SESSION_id=[REDACTED]&page=2#access_token=[REDACTED]&x=1"
    );
    // Percent-encoded names are decoded before the check.
    assert_eq!(
        redact_url("http://h.test/?client%5Fsecret=abc", false),
        "http://h.test/?client%5Fsecret=[REDACTED]"
    );
    // A credential template: every value goes.
    assert_eq!(
        redact_url("http://h.test/p?a=1&bare&c=", true),
        "http://h.test/p?a=[REDACTED]&[REDACTED]&c="
    );
    // Nothing to redact: unchanged.
    for plain in ["http://h.test/a/b", "h.test:443", "example.com"] {
        assert_eq!(redact_url(plain, false), plain);
    }
    for name in [
        "token",
        "apikey",
        "api_key",
        "X-Signature",
        "pwd",
        "jwt",
        "sid",
        "auth",
        "Bearer",
        "credentials",
        "access_token",
        "client_secret",
        "passwd",
        "key",
    ] {
        assert!(is_credential_param(name), "{name}");
    }
    assert!(!is_credential_param("page"));
}

#[test]
fn stored_request_lines_and_location_headers_are_redacted() {
    let req = SentHttpRequest {
        method: "GET".into(),
        url: "http://bob:hunter2@app.test/cb?code=1&access_token=SECRETVALUE".into(),
        headers: vec![("Referer".into(), "http://app.test/?token=SECRETREF".into())],
        body: Vec::new(),
    };
    let (text, _) = render_http_request(&req);
    assert!(
        text.starts_with(
            "GET http://[REDACTED]@app.test/cb?code=1&access_token=[REDACTED] HTTP/1.1\r\n"
        ),
        "{text}"
    );
    for secret in ["hunter2", "SECRETVALUE", "SECRETREF"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    let resp = HttpResponseData {
        status: 302,
        reason: "Found".into(),
        version: "HTTP/1.1".into(),
        headers: vec![(
            "Location".into(),
            "https://idp.test/next?session=SECRETLOC&step=2".into(),
        )],
        ..HttpResponseData::default()
    };
    let (text, _) = render_http_response(&resp, false);
    assert!(
        text.contains("Location: https://idp.test/next?session=[REDACTED]&step=2"),
        "{text}"
    );
}
