//! Opt-in live secret validation.
//!
//! A leaked credential is an emergency *if the provider still accepts it*.
//! This module answers exactly that question, and only that question, under
//! rules that keep it compatible with oxAudit's local-first promise:
//!
//! - **Opt-in only.** Nothing here runs unless `--validate-secrets` was
//!   passed. A default scan never puts a credential on the wire.
//! - **Fixed provider endpoints.** Each rule validates against its
//!   credential's own provider over TLS — a GitHub token goes to
//!   `api.github.com`, nowhere else. There is no configurable URL, so the
//!   secret cannot be aimed at an attacker's host by a typo or a malicious
//!   setting.
//! - **Status in, status out.** The only thing read from a response is the
//!   HTTP status. Account identities and response bodies are discarded, and
//!   nothing about the credential is logged.
//! - **Honest tri-state.** `Some(true)` means the provider authenticated the
//!   credential — treat it as live and rotate immediately. `Some(false)`
//!   means the provider rejected it — **not** a licence to skip rotation:
//!   the credential may still work against other surfaces, or be re-enabled.
//!   `None` means no validator exists for that rule or the check could not
//!   complete; the finding stays unverified.
//!
//! The raw secret value exists only between the scanner hit and this call —
//! findings themselves carry redacted evidence, so an unvalidated run never
//! retains credential material.

use crate::models::Finding;

/// A credential as the scanner saw it, before redaction. Exists only for the
/// duration of a validating run and never leaves it serialized.
pub struct RawSecret {
    pub finding_id: String,
    pub rule_id: String,
    pub value: String,
}

/// Debug never prints the value: a derived implementation would put credential
/// material into any `{:?}` log line.
impl std::fmt::Debug for RawSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawSecret")
            .field("finding_id", &self.finding_id)
            .field("rule_id", &self.rule_id)
            .field("value", &"[redacted]")
            .finish()
    }
}

/// How many credentials one run will put on the wire. Validation is
/// sequential and this bounds both time and provider rate-limit exposure; a
/// history with more distinct leaks than this is an incident where the first
/// twenty answers already decide the response.
pub const MAX_VALIDATIONS: usize = 20;

struct Provider {
    /// The exact origin the credential is sent to.
    endpoint: &'static str,
    header: &'static str,
}

/// Which provider a rule's credential authenticates against. A rule absent
/// from this map has no validator and stays unverified.
fn provider_for(rule_id: &str) -> Option<Provider> {
    match rule_id {
        "github-token" | "github-fine-grained-token" => Some(Provider {
            endpoint: "https://api.github.com/user",
            header: "Authorization",
        }),
        _ => None,
    }
}

/// Validate one credential against its provider.
///
/// `None` for every outcome that is not a clear authentication verdict,
/// including transport failures and provider trouble (429/5xx): an unknown
/// answer must never be mistaken for a safe one.
async fn validate_one(
    value: &str,
    http: &reqwest::Client,
    endpoint: &str,
    header_name: &str,
) -> Option<bool> {
    let response = http
        .get(endpoint)
        .header(header_name, format!("Bearer {value}"))
        .send()
        .await
        .ok()?;
    match response.status().as_u16() {
        // 403 is a valid token without permission for this endpoint — only
        // an authenticated request can be told "forbidden".
        200 | 403 => Some(true),
        401 => Some(false),
        _ => None,
    }
}

/// What one validating run concluded, for the summary line.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ValidationSummary {
    pub checked: usize,
    pub live: usize,
    pub rejected: usize,
    pub skipped_no_validator: usize,
    pub skipped_limit: usize,
    pub skipped_not_kept: usize,
}

impl ValidationSummary {
    pub fn describe(&self) -> String {
        format!(
            "validated {} secret(s) against their providers: {} live, {} rejected, {} unchecked (no validator or provider unreachable)",
            self.checked, self.live, self.rejected,
            self.skipped_no_validator + self.skipped_limit + self.skipped_not_kept
        )
    }
}

/// Validate the secrets behind `findings` and set each finding's `verified`.
///
/// Findings whose id no longer appears in the list (dropped by revision
/// dedupe) are not validated — the kept finding for the same credential
/// carries the verdict. Raw values are consumed here and not returned.
pub async fn validate_raw_secrets(
    findings: &mut [Finding],
    raw: Vec<RawSecret>,
    http: &reqwest::Client,
) -> ValidationSummary {
    validate_with_endpoints(findings, raw, http, &std::collections::HashMap::new()).await
}

/// The same run with per-rule endpoint overrides. Production passes an empty
/// map — the provider map above is then the only source of URLs, which is the
/// security property. Tests use this to point a rule at a local server.
async fn validate_with_endpoints(
    findings: &mut [Finding],
    raw: Vec<RawSecret>,
    http: &reqwest::Client,
    overrides: &std::collections::HashMap<String, String>,
) -> ValidationSummary {
    let mut summary = ValidationSummary::default();
    let mut by_id = std::collections::HashMap::new();
    for (index, finding) in findings.iter().enumerate() {
        by_id.insert(finding.id.clone(), index);
    }
    for secret in raw {
        let Some(&index) = by_id.get(&secret.finding_id) else {
            summary.skipped_not_kept += 1;
            continue;
        };
        if summary.checked >= MAX_VALIDATIONS {
            summary.skipped_limit += 1;
            continue;
        }
        let Some(provider) = provider_for(&secret.rule_id) else {
            // The finding stays explicitly unverified rather than silently so.
            findings[index].verified = None;
            summary.skipped_no_validator += 1;
            continue;
        };
        let endpoint = overrides
            .get(&secret.rule_id)
            .cloned()
            .unwrap_or_else(|| provider.endpoint.to_string());
        match validate_one(&secret.value, http, &endpoint, provider.header).await {
            Some(true) => {
                findings[index].verified = Some(true);
                summary.checked += 1;
                summary.live += 1;
            }
            Some(false) => {
                findings[index].verified = Some(false);
                summary.checked += 1;
                summary.rejected += 1;
            }
            None => {
                findings[index].verified = None;
                summary.checked += 1;
            }
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn finding(id: &str, rule: &str) -> Finding {
        Finding {
            id: id.into(),
            category: "secret".into(),
            rule_id: rule.into(),
            rule_name: "test".into(),
            severity: "high".into(),
            title: "test".into(),
            description: String::new(),
            file_path: "x".into(),
            line: 1,
            column: 1,
            match_text: "[REDACTED]".into(),
            context: "[REDACTED]".into(),
            language: String::new(),
            cwe: None,
            cwe_exploited: false,
            cwe_exploited_count: 0,
            recommendation: String::new(),
            entropy: None,
            verified: None,
            analysis: Default::default(),
            analysis_gates: Vec::new(),
            observation_run_id: String::new(),
            resolved_by_run_id: None,
            fingerprint_version: 0,
            fingerprint: String::new(),
            in_test_region: false,
            scope: None,
            scope_reason: None,
            review: None,
            review_history: Vec::new(),
            diff_status: None,
        }
    }

    fn raw(id: &str, rule: &str, value: &str) -> RawSecret {
        RawSecret {
            finding_id: id.into(),
            rule_id: rule.into(),
            value: value.into(),
        }
    }

    /// Serve exactly one HTTP response, recording the Authorization header
    /// the credential was sent with. Every status below asserts what the
    /// real provider would say for that credential state.
    async fn serve_once(status: &str) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let status = status.to_owned();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&request).into_owned();
            if let Some(authorization) = text
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            {
                recorder
                    .lock()
                    .unwrap()
                    .push(authorization.trim().to_owned());
            }
            let response =
                format!("HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        (format!("http://{address}/user"), seen)
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn overrides(rule: &str, url: &str) -> HashMap<String, String> {
        HashMap::from([(rule.to_string(), url.to_string())])
    }

    #[tokio::test]
    async fn an_accepted_credential_is_live_and_travels_as_a_bearer_to_its_provider() {
        let (url, seen) = serve_once("200 OK").await;
        let mut findings = vec![finding("a", "github-token")];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![raw(
                "a",
                "github-token",
                "ghp_livecredentialxxxxxxxxxxxxxxxxxxxxxx",
            )],
            &client(),
            &overrides("github-token", &url),
        )
        .await;
        assert_eq!(findings[0].verified, Some(true));
        assert_eq!((summary.checked, summary.live), (1, 1));
        let sent = seen.lock().unwrap()[0].clone();
        assert_eq!(
            sent.to_ascii_lowercase(),
            "authorization: bearer ghp_livecredentialxxxxxxxxxxxxxxxxxxxxxx"
        );
    }

    #[tokio::test]
    async fn a_forbidden_response_is_still_an_authenticated_token() {
        let (url, seen) = serve_once("403 Forbidden").await;
        let verdict = validate_one("github_pat_scopeless", &client(), &url, "Authorization").await;
        assert_eq!(verdict, Some(true));
        assert!(seen.lock().unwrap()[0].contains("Bearer"));
    }

    #[tokio::test]
    async fn a_rejected_credential_is_reported_not_buried() {
        let (url, _seen) = serve_once("401 Unauthorized").await;
        let mut findings = vec![finding("a", "github-token")];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![raw(
                "a",
                "github-token",
                "ghp_revokedxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            )],
            &client(),
            &overrides("github-token", &url),
        )
        .await;
        assert_eq!(findings[0].verified, Some(false));
        assert_eq!((summary.checked, summary.rejected), (1, 1));
    }

    #[tokio::test]
    async fn provider_trouble_is_unknown_not_safe() {
        let (url, _seen) = serve_once("429 Too Many Requests").await;
        let mut findings = vec![finding("a", "github-token")];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![raw(
                "a",
                "github-token",
                "ghp_ratelimitedxxxxxxxxxxxxxxxxxxxxxxxx",
            )],
            &client(),
            &overrides("github-token", &url),
        )
        .await;
        assert_eq!(findings[0].verified, None);
        assert_eq!(summary.checked, 1);
        assert_eq!(summary.live + summary.rejected, 0);
    }

    #[tokio::test]
    async fn rules_without_a_validator_stay_explicitly_unverified() {
        let mut findings = vec![finding("a", "aws-access-key-id")];
        let summary = validate_raw_secrets(
            &mut findings,
            vec![raw("a", "aws-access-key-id", "AKIAZ9X8W7U6T5S4R3Q2")],
            &client(),
        )
        .await;
        assert_eq!(findings[0].verified, None);
        assert_eq!(summary.skipped_no_validator, 1);
        assert_eq!(summary.checked, 0);
    }

    #[tokio::test]
    async fn secrets_dropped_by_dedupe_are_not_validated() {
        let mut findings = vec![finding("kept", "github-token")];
        let summary = validate_raw_secrets(
            &mut findings,
            vec![raw(
                "dropped",
                "github-token",
                "ghp_duplicatexxxxxxxxxxxxxxxxxxxxxxxxxxx",
            )],
            &client(),
        )
        .await;
        assert_eq!(summary.skipped_not_kept, 1);
        assert_eq!(summary.checked, 0);
    }

    #[tokio::test]
    async fn the_validation_budget_bounds_wire_calls() {
        // An unreachable-but-local endpoint: every connection fails fast and
        // counts as an inconclusive check, which is enough to see the cap.
        let endpoint = "http://127.0.0.1:9/user";
        let mut findings: Vec<Finding> = (0..(MAX_VALIDATIONS + 5))
            .map(|index| finding(&format!("f{index}"), "github-token"))
            .collect();
        let raws: Vec<RawSecret> = (0..(MAX_VALIDATIONS + 5))
            .map(|index| {
                raw(
                    &format!("f{index}"),
                    "github-token",
                    "ghp_budgetxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                )
            })
            .collect();
        let summary = validate_with_endpoints(
            &mut findings,
            raws,
            &reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_millis(200))
                .build()
                .unwrap(),
            &overrides("github-token", endpoint),
        )
        .await;
        assert_eq!(summary.checked, MAX_VALIDATIONS);
        assert_eq!(summary.skipped_limit, 5);
    }

    #[test]
    fn the_provider_map_pins_production_endpoints() {
        let provider = provider_for("github-token").expect("github tokens are validated");
        assert_eq!(provider.endpoint, "https://api.github.com/user");
        assert!(provider_for("aws-access-key-id").is_none());
    }
}
