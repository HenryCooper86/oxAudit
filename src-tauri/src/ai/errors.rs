//! Typed LLM errors + classification, modeled on y-agent's `error_classifier.rs`.
//!
//! The retry policy mirrors y-agent's provider attempt contract: only
//! transient pre-output failures (5xx / network / timeout) auto-retry; 429
//! honors its own `Retry-After`; auth/quota/context errors never retry.

use std::fmt;

#[derive(Debug, Clone)]
pub enum LlmError {
    /// 429 — has its own retry-after; honor it once, then surface.
    RateLimited { retry_after_secs: Option<u64> },
    /// 403 with quota/balance signals — permanent until user acts.
    QuotaExhausted,
    /// 401 / 403 auth failure (bad key, unauthorized).
    AuthFailed,
    /// 404 with a model signal, or "model not found".
    ModelNotFound,
    /// 400/422 context-window overflow.
    ContextWindowExceeded,
    /// 5xx.
    ServerError,
    /// Transport failure (DNS, connect, mid-stream read).
    NetworkError(String),
    /// Malformed/unparseable response or 400 without a known signal.
    ParseError(String),
    /// No data within the idle timeout.
    Timeout,
    /// User cancelled the run.
    Cancelled,
}

impl LlmError {
    /// Whether a retry is safe and likely to help.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            LlmError::ServerError | LlmError::NetworkError(_) | LlmError::Timeout
        )
    }

    /// Human-friendly message for the UI.
    pub fn user_message(&self) -> String {
        match self {
            LlmError::RateLimited { retry_after_secs } => match retry_after_secs {
                Some(s) => format!("Rate limited by the AI provider — retry in {s}s."),
                None => "Rate limited by the AI provider — try again in a moment.".into(),
            },
            LlmError::QuotaExhausted => {
                "AI provider quota or balance exhausted — check your account.".into()
            }
            LlmError::AuthFailed => "AI authentication failed — check your API key in Settings.".into(),
            LlmError::ModelNotFound => {
                "Model not found on this endpoint — check the model name in Settings.".into()
            }
            LlmError::ContextWindowExceeded => {
                "Conversation too long for the configured context window — start a new chat, rewind earlier turns, or raise the model context setting.".into()
            }
            LlmError::ServerError => "AI provider returned a server error — try again.".into(),
            LlmError::NetworkError(e) => format!("Network error contacting AI provider: {e}"),
            LlmError::ParseError(e) => format!("Unexpected AI response: {e}"),
            LlmError::Timeout => "AI provider timed out — try again.".into(),
            LlmError::Cancelled => "Chat cancelled.".into(),
        }
    }
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.user_message())
    }
}

impl std::error::Error for LlmError {}

/// Classify an HTTP failure into a typed error using y-agent-style heuristics
/// on status + lower-cased body. `retry_after` comes from the `Retry-After`
/// header when present.
pub fn classify(status: u16, body: &str, retry_after: Option<u64>) -> LlmError {
    let lower = body.to_ascii_lowercase();
    let has = |needle: &str| lower.contains(needle);
    match status {
        429 => LlmError::RateLimited {
            retry_after_secs: retry_after.or_else(|| extract_retry_after_json(&lower)),
        },
        401 | 403 => {
            if has("insufficient_quota") || has("quota") || has("balance") || has("billing") {
                LlmError::QuotaExhausted
            } else {
                LlmError::AuthFailed
            }
        }
        404 => {
            if has("model") {
                LlmError::ModelNotFound
            } else {
                LlmError::ServerError
            }
        }
        400 | 422 => {
            if (has("context") || has("token"))
                && (has("length")
                    || has("maximum")
                    || has("window")
                    || has("exceed")
                    || has("too long"))
            {
                LlmError::ContextWindowExceeded
            } else {
                LlmError::ParseError(snippet(body))
            }
        }
        408 | 409 | 425 => LlmError::ServerError,
        500..=599 => LlmError::ServerError,
        _ => {
            if has("context") && has("length") {
                LlmError::ContextWindowExceeded
            } else if has("model") && (has("not found") || has("does not exist")) {
                LlmError::ModelNotFound
            } else if has("rate limit") || has("too many requests") {
                LlmError::RateLimited {
                    retry_after_secs: extract_retry_after_json(&lower),
                }
            } else {
                LlmError::ParseError(snippet(body))
            }
        }
    }
}

fn snippet(body: &str) -> String {
    let cleaned: String = body.chars().take(300).collect();
    cleaned.replace('\n', " ")
}

fn extract_retry_after_json(lower: &str) -> Option<u64> {
    // {"error": { ..., "retry_after": 7 }} or {"retry_after": 7}
    for marker in ["retry_after", "retry-after"] {
        if let Some(idx) = lower.find(marker) {
            let rest = &lower[idx + marker.len()..];
            if let Some(colon) = rest.find(':') {
                let after = &rest[colon + 1..];
                let num: String = after
                    .chars()
                    .skip_while(|c| !c.is_ascii_digit())
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(n) = num.parse::<u64>() {
                    return Some(n.clamp(0, 120));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_from_429() {
        let e = classify(429, "Too many requests", Some(7));
        assert!(matches!(
            e,
            LlmError::RateLimited {
                retry_after_secs: Some(7)
            }
        ));
    }

    #[test]
    fn auth_from_401() {
        let e = classify(401, "Incorrect API key provided", None);
        assert!(matches!(e, LlmError::AuthFailed));
    }

    #[test]
    fn quota_from_403() {
        let e = classify(403, "You exceeded your current quota", None);
        assert!(matches!(e, LlmError::QuotaExhausted));
    }

    #[test]
    fn context_window_from_400() {
        let e = classify(
            400,
            "This model's maximum context length is 128000 tokens",
            None,
        );
        assert!(matches!(e, LlmError::ContextWindowExceeded));
    }

    #[test]
    fn model_not_found_from_404() {
        let e = classify(404, "The model `gpt-4x` does not exist", None);
        assert!(matches!(e, LlmError::ModelNotFound));
    }

    #[test]
    fn server_5xx_transient() {
        let e = classify(503, "Service Unavailable", None);
        assert!(matches!(e, LlmError::ServerError));
        assert!(e.is_transient());
        assert!(!LlmError::AuthFailed.is_transient());
    }

    #[test]
    fn retry_after_from_body() {
        let e = classify(429, r#"{"error":{"retry_after":12}}"#, None);
        assert!(matches!(
            e,
            LlmError::RateLimited {
                retry_after_secs: Some(12)
            }
        ));
    }
}
