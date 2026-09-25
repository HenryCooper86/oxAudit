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
//!   nothing about the credential is logged. One measured exception: Slack
//!   reports a failed check as HTTP 200 with `{"ok": false}` in the body,
//!   so for Slack exactly one boolean field is read and the rest of the
//!   body is discarded like everything else.
//! - **Honest tri-state.** `Some(true)` means the provider authenticated the
//!   credential — treat it as live and rotate immediately. `Some(false)`
//!   means the provider rejected it — **not** a licence to skip rotation:
//!   the credential may still work against other surfaces, or be re-enabled.
//!   `None` means no validator exists for that rule or the check could not
//!   complete; the finding stays unverified.
//!
//! Two provider shapes exist. Bearer-token credentials (GitHub) travel as
//! `Authorization: Bearer …` to one fixed endpoint. AWS keys are a *pair* —
//! an access key id is only a username, and proving it live requires signing
//! with its secret access key — so an `aws-access-key-id` finding is only
//! validated when an `aws-secret-key` finding sits in the same file close
//! enough to be its other half (see [`PAIRING_WINDOW_LINES`]). The pair is
//! then Signature Version 4-signed onto an STS `GetCallerIdentity` call to
//! `sts.amazonaws.com` — the one AWS API every valid credential may call,
//! regardless of permissions. Temporary (`ASIA…`) keys are skipped: they
//! need a session token the scanner does not pair. A verdict lands on both
//! findings of the pair.
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
    /// The exact origin the credential is sent to. Telegram embeds the
    /// token in the URL path instead of a header, so this is the origin the
    /// path is built under.
    endpoint: &'static str,
    /// Fixed extra headers the provider requires alongside the credential
    /// (none carry credential material).
    extra_headers: &'static [(&'static str, &'static str)],
    /// Providers that answer HTTP 200 even for a failed check and report
    /// the verdict in the body (Slack): read exactly one boolean field and
    /// nothing else. Measured against the live service.
    body_verdict: bool,
    /// How the credential is presented. Most providers take a Bearer token;
    /// some take a named header (measured: Figma `X-Figma-Token`, Postman
    /// and New Relic `X-Api-Key`, Datadog `DD-API-KEY`); Telegram expects
    /// the token inside the URL path (`/bot<token>/getMe`).
    auth: AuthStyle,
    /// Datadog answers 403 for an INVALID key (measured) — the same status
    /// other providers in this map use for valid-but-limited tokens. For
    /// that provider alone, 403 means rejected; everywhere else the shipped
    /// mapping stands and 403 reads as authenticated.
    forbidden_is_rejected: bool,
}

/// How a provider expects the credential to be presented.
enum AuthStyle {
    /// `Authorization: Bearer <token>`.
    Bearer,
    /// The named header carries the raw credential value.
    Header(&'static str),
    /// Telegram: the token sits in the URL path, `/bot<token>/getMe`.
    TelegramPath,
}

/// Which bearer-token provider a rule's credential authenticates against. A
/// rule absent from this map has no validator and stays unverified. AWS keys
/// do not fit this shape — they sign instead of presenting a token — and are
/// handled by the SigV4 path below.
///
/// Rules deliberately absent, each for a reason sharper than "not yet":
/// - `slack-webhook`: the only check is POSTing a message into the channel —
///   a side effect visible to the workspace. Not worth an automated message
///   to prove a URL anyone can post to works.
/// - `google-api-key`: API keys are service-scoped; a key valid for one API
///   fails every other, so no single fixed endpoint can return an honest
///   verdict.
/// - `pypi-token`: upload tokens only authenticate the upload endpoint;
///   probing it means sending a (deliberately malformed) publish.
/// - `private-key`: proving a key material live means signing a request for
///   whichever service it belongs to — per-provider work with no shared
///   shape, and the key already carries its own risk signal.
fn provider_for(rule_id: &str) -> Option<Provider> {
    let bearer = |endpoint: &'static str| Provider {
        endpoint,
        extra_headers: &[],
        body_verdict: false,
        auth: AuthStyle::Bearer,
        forbidden_is_rejected: false,
    };
    match rule_id {
        "github-token" | "github-fine-grained-token" => Some(bearer("https://api.github.com/user")),
        "gitlab-pat" => Some(bearer("https://gitlab.com/api/v4/user")),
        "openai-api-key" => Some(bearer("https://api.openai.com/v1/models")),
        "anthropic-api-key" => Some(Provider {
            endpoint: "https://api.anthropic.com/v1/models",
            extra_headers: &[("anthropic-version", "2023-06-01")],
            body_verdict: false,
            auth: AuthStyle::Bearer,
            forbidden_is_rejected: false,
        }),
        "huggingface-token" => Some(bearer("https://huggingface.co/api/whoami-v2")),
        "npm-token" => Some(bearer("https://registry.npmjs.org/-/whoami")),
        "stripe-key" => Some(bearer("https://api.stripe.com/v1/charges?limit=1")),
        "slack-token" => Some(Provider {
            endpoint: "https://slack.com/api/auth.test",
            extra_headers: &[],
            body_verdict: true,
            auth: AuthStyle::Bearer,
            forbidden_is_rejected: false,
        }),
        // Measured 2026-09-26 with an invalid credential: each of these
        // answers 401 (Datadog 403) for a rejected credential and 2xx for a
        // valid one. Telegram embeds the token in the URL path and answers
        // 401 in the status line.
        "sentry-token" => Some(bearer("https://sentry.io/api/0/")),
        "square-access-token" => Some(bearer("https://connect.squareup.com/v2/merchants")),
        "figma-token" => Some(Provider {
            endpoint: "https://api.figma.com/v1/me",
            extra_headers: &[],
            body_verdict: false,
            auth: AuthStyle::Header("X-Figma-Token"),
            forbidden_is_rejected: false,
        }),
        "postman-api-key" => Some(Provider {
            endpoint: "https://api.getpostman.com/me",
            extra_headers: &[],
            body_verdict: false,
            auth: AuthStyle::Header("X-Api-Key"),
            forbidden_is_rejected: false,
        }),
        "newrelic-api-key" => Some(Provider {
            endpoint: "https://api.newrelic.com/v2/applications.json",
            extra_headers: &[],
            body_verdict: false,
            auth: AuthStyle::Header("X-Api-Key"),
            forbidden_is_rejected: false,
        }),
        "datadog-api-key" => Some(Provider {
            endpoint: "https://api.datadoghq.com/api/v1/validate",
            extra_headers: &[],
            body_verdict: false,
            auth: AuthStyle::Header("DD-API-KEY"),
            forbidden_is_rejected: true,
        }),
        "telegram-bot-token" => Some(Provider {
            endpoint: "https://api.telegram.org",
            extra_headers: &[],
            body_verdict: false,
            auth: AuthStyle::TelegramPath,
            forbidden_is_rejected: false,
        }),
        _ => None,
    }
}

/// Some rules match values that are not credentials even when the rule as a
/// whole is sound: Stripe's regex also catches `pk_…` publishable keys,
/// which are public by design and never authenticate the API. Only values
/// that could authenticate count as validatable.
fn value_is_validatable(rule_id: &str, value: &str) -> bool {
    match rule_id {
        "stripe-key" => value.starts_with("sk_") || value.starts_with("rk_"),
        _ => true,
    }
}

/// The fixed origin every AWS pair is validated against: STS answers
/// `GetCallerIdentity` for any valid credential, with no permissions gate,
/// so the call proves the key live without granting the scan any ability to
/// act on the account.
const AWS_STS_ENDPOINT: &str = "https://sts.amazonaws.com/";
const AWS_STS_QUERY: &str = "Action=GetCallerIdentity&Version=2011-06-15";
const AWS_REGION: &str = "us-east-1";
const AWS_SERVICE: &str = "sts";
/// The override key that steers AWS validation at a test server.
const AWS_RULE: &str = "aws-access-key-id";
const AWS_SECRET_RULE: &str = "aws-secret-key";

/// How far apart (in lines, same file) an access key id and a secret access
/// key may sit and still count as one leaked pair. Multi-profile
/// `credentials` files interleave `[profile]` headers and blank lines; this
/// window is wide enough for that and tight enough that unrelated keys in a
/// large config do not couple.
const PAIRING_WINDOW_LINES: usize = 10;

// ------------------------------------------------------------------- SigV4

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// The request being signed, in already-canonical form (sorted query,
/// encoded path). Production only ever constructs the fixed STS call; tests
/// construct AWS's official suite vectors.
struct SigV4Request<'a> {
    method: &'a str,
    canonical_uri: &'a str,
    canonical_query: &'a str,
    host: &'a str,
    amz_date: &'a str,
    region: &'a str,
    service: &'a str,
}

/// The Authorization header for one Signature Version 4-signed GET request.
///
/// The only requests this signs are the fixed STS call, whose pieces are
/// constants, so no caller can aim the signer at an arbitrary request.
/// Verified against AWS's official SigV4 test-suite vectors in the tests
/// below (`get-vanilla`, `get-vanilla-query-order-key-case`, `get-unreserved`,
/// `get-utf8`) using the suite's published credentials and signatures.
fn sigv4_authorization(key_id: &str, secret: &str, request: &SigV4Request<'_>) -> String {
    let SigV4Request {
        method,
        canonical_uri,
        canonical_query,
        host,
        amz_date,
        region,
        service,
    } = request;
    // A GET with no body: the payload hash is the SHA-256 of the empty
    // string, a constant the SigV4 reference documents alongside the
    // algorithm itself.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\nhost:{host}\nx-amz-date:{amz_date}\n\nhost;x-amz-date\n{EMPTY_SHA256}"
    );
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    // kSigning = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
    let signing_key = hmac_sha256(
        &hmac_sha256(
            &hmac_sha256(
                &hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes()),
                region.as_bytes(),
            ),
            service.as_bytes(),
        ),
        b"aws4_request",
    );
    let signature = hex_lower(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders=host;x-amz-date, Signature={signature}"
    )
}

/// The `host[:port]` an endpoint URL is sent to, exactly as the HTTP client
/// derives it from the URL. Signing against anything else would produce a
/// request the provider correctly rejects.
fn host_of(endpoint: &str) -> String {
    let rest = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    rest.split('/').next().unwrap_or(rest).to_owned()
}

/// Validate one bearer credential against its provider.
///
/// `None` for every outcome that is not a clear authentication verdict,
/// including transport failures and provider trouble (429/5xx): an unknown
/// answer must never be mistaken for a safe one. 403 counts as authenticated
/// — only an authenticated request can be told "forbidden" — which for
/// permission-scoped keys (Stripe restricted keys, scoped tokens) is the
/// correct reading.
async fn validate_one(
    value: &str,
    http: &reqwest::Client,
    endpoint: &str,
    extra_headers: &[(&str, &str)],
    body_verdict: bool,
    auth: &AuthStyle,
    forbidden_is_rejected: bool,
) -> Option<bool> {
    let mut request = match auth {
        AuthStyle::Bearer => http
            .get(endpoint)
            .header("Authorization", format!("Bearer {value}")),
        AuthStyle::Header(name) => http.get(endpoint).header(*name, value),
        // The token rides in the path under the fixed origin; `endpoint`
        // is that origin (or a test server standing in for it).
        AuthStyle::TelegramPath => http.get(format!("{endpoint}/bot{value}/getMe")),
    };
    for (name, header_value) in extra_headers {
        request = request.header(*name, *header_value);
    }
    let response = request.send().await.ok()?;
    let status = response.status().as_u16();
    if forbidden_is_rejected {
        // The one measured provider (Datadog) whose 403 rejects rather
        // than authenticates: a dead key must never read as live.
        if !body_verdict {
            return match status {
                200..=299 => Some(true),
                401 | 403 => Some(false),
                _ => None,
            };
        }
    }
    if !body_verdict {
        return match status {
            200 | 403 => Some(true),
            401 => Some(false),
            _ => None,
        };
    }
    // The one provider shape (Slack) that reports failure inside an
    // HTTP-200 body: read exactly the boolean verdict field and discard
    // everything else the body might carry.
    match status {
        200 | 403 => response
            .json::<serde_json::Value>()
            .await
            .ok()?
            .get("ok")?
            .as_bool(),
        401 => Some(false),
        _ => None,
    }
}

/// Validate one AWS key pair with a Signature Version 4-signed STS
/// `GetCallerIdentity` call. STS rejects unknown or expired access keys and
/// mismatched signatures alike as 403, so a single status class means
/// "this pair does not authenticate" — status in, status out.
async fn validate_aws_pair(
    key_id: &str,
    secret: &str,
    http: &reqwest::Client,
    endpoint: &str,
) -> Option<bool> {
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = host_of(endpoint);
    let authorization = sigv4_authorization(
        key_id,
        secret,
        &SigV4Request {
            method: "GET",
            canonical_uri: "/",
            canonical_query: AWS_STS_QUERY,
            host: &host,
            amz_date: &amz_date,
            region: AWS_REGION,
            service: AWS_SERVICE,
        },
    );
    let url = format!("{}?{AWS_STS_QUERY}", endpoint.trim_end_matches('/'));
    let response = http
        .get(&url)
        .header("x-amz-date", &amz_date)
        .header("Authorization", authorization)
        .send()
        .await
        .ok()?;
    match response.status().as_u16() {
        200 => Some(true),
        403 => Some(false),
        _ => None,
    }
}

/// One half of a candidate AWS credential pair, located where it was found.
struct AwsHalf {
    finding_index: usize,
    value: String,
    file: String,
    line: usize,
}

/// The index of the strictly nearest half in `pool` within the pairing
/// window and file, or `None` when nothing is in range or the nearest is a
/// tie — an ambiguous choice is no choice.
fn nearest_in_window(file: &str, line: usize, pool: &[AwsHalf]) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    let mut tie = false;
    for (index, half) in pool.iter().enumerate() {
        if half.file != file {
            continue;
        }
        let distance = half.line.abs_diff(line);
        if distance > PAIRING_WINDOW_LINES {
            continue;
        }
        match best {
            None => best = Some((index, distance)),
            Some((_, best_distance)) if distance < best_distance => {
                best = Some((index, distance));
                tie = false;
            }
            Some((_, best_distance)) if distance == best_distance => tie = true,
            _ => {}
        }
    }
    if tie {
        None
    } else {
        best.map(|(index, _)| index)
    }
}

/// Pair access key ids with the secret access key nearest to them in the
/// same file, requiring the choice to be mutual and unambiguous.
///
/// Nearest-not-just-nearby is what makes multi-profile credentials files
/// work: each key sits next to its own secret, so mutual nearest neighbors
/// pair correctly even though the window holds other profiles' secrets too.
/// A tie on either side (two secrets equidistant from one key, or vice
/// versa) leaves both halves unpaired — pairing the wrong secret would send
/// AWS a mis-signed request and report a live key as rejected.
fn pair_aws_keys(keys: &[AwsHalf], secrets: &[AwsHalf]) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    for (key_index, key) in keys.iter().enumerate() {
        let Some(secret_index) = nearest_in_window(&key.file, key.line, secrets) else {
            continue;
        };
        let secret = &secrets[secret_index];
        if nearest_in_window(&secret.file, secret.line, keys) == Some(key_index) {
            pairs.push((key_index, secret_index));
        }
    }
    pairs
}

/// What one validating run concluded, for the summary line.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationSummary {
    pub checked: usize,
    pub live: usize,
    pub rejected: usize,
    pub skipped_no_validator: usize,
    pub skipped_unpaired: usize,
    pub skipped_limit: usize,
    pub skipped_not_kept: usize,
}

impl ValidationSummary {
    pub fn describe(&self) -> String {
        format!(
            "validated {} secret(s) against their providers: {} live, {} rejected, {} unchecked (no validator, unpaired AWS key, or provider trouble)",
            self.checked,
            self.live,
            self.rejected,
            self.skipped_no_validator + self.skipped_unpaired + self.skipped_limit + self.skipped_not_kept
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

    // Split the credentials by shape: AWS halves carry their finding's
    // location for pairing; everything else takes the bearer path below.
    let mut rest = Vec::new();
    let mut keys: Vec<AwsHalf> = Vec::new();
    let mut secrets: Vec<AwsHalf> = Vec::new();
    for secret in raw {
        let Some(&index) = by_id.get(&secret.finding_id) else {
            summary.skipped_not_kept += 1;
            continue;
        };
        let is_key = secret.rule_id == AWS_RULE;
        let is_secret = secret.rule_id == AWS_SECRET_RULE;
        if is_key || is_secret {
            let half = AwsHalf {
                finding_index: index,
                value: secret.value,
                file: findings[index].file_path.clone(),
                line: findings[index].line,
            };
            if is_key {
                keys.push(half);
            } else {
                secrets.push(half);
            }
        } else {
            rest.push(secret);
        }
    }

    // Temporary credentials cannot be validated without their session
    // token, which the scanner does not pair; drop them from pairing so
    // they cannot consume another key's secret half.
    let mut paired_key = vec![false; keys.len()];
    let mut paired_secret = vec![false; secrets.len()];
    for (key_index, key) in keys.iter().enumerate() {
        if key.value.starts_with("ASIA") {
            findings[key.finding_index].verified = None;
            summary.skipped_unpaired += 1;
            paired_key[key_index] = true;
        }
    }

    let endpoint = overrides
        .get(AWS_RULE)
        .cloned()
        .unwrap_or_else(|| AWS_STS_ENDPOINT.to_string());
    for (key_index, secret_index) in pair_aws_keys(&keys, &secrets) {
        if paired_key[key_index] || paired_secret[secret_index] {
            continue;
        }
        paired_key[key_index] = true;
        paired_secret[secret_index] = true;
        if summary.checked >= MAX_VALIDATIONS {
            findings[keys[key_index].finding_index].verified = None;
            findings[secrets[secret_index].finding_index].verified = None;
            summary.skipped_limit += 1;
            continue;
        }
        let key = &keys[key_index];
        let secret = &secrets[secret_index];
        match validate_aws_pair(&key.value, &secret.value, http, &endpoint).await {
            Some(true) => {
                findings[key.finding_index].verified = Some(true);
                findings[secret.finding_index].verified = Some(true);
                summary.checked += 1;
                summary.live += 1;
            }
            Some(false) => {
                findings[key.finding_index].verified = Some(false);
                findings[secret.finding_index].verified = Some(false);
                summary.checked += 1;
                summary.rejected += 1;
            }
            None => {
                findings[key.finding_index].verified = None;
                findings[secret.finding_index].verified = None;
                summary.checked += 1;
            }
        }
    }
    for (index, is_paired) in paired_key.into_iter().enumerate() {
        if !is_paired {
            findings[keys[index].finding_index].verified = None;
            summary.skipped_unpaired += 1;
        }
    }
    for (index, is_paired) in paired_secret.into_iter().enumerate() {
        if !is_paired {
            findings[secrets[index].finding_index].verified = None;
            summary.skipped_unpaired += 1;
        }
    }

    for secret in rest {
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
        if !value_is_validatable(&secret.rule_id, &secret.value) {
            // The rule matched a value that is not a credential (Stripe's
            // publishable keys): same honest outcome as having no validator.
            findings[index].verified = None;
            summary.skipped_no_validator += 1;
            continue;
        }
        let endpoint = overrides
            .get(&secret.rule_id)
            .cloned()
            .unwrap_or_else(|| provider.endpoint.to_string());
        match validate_one(
            &secret.value,
            http,
            &endpoint,
            provider.extra_headers,
            provider.body_verdict,
            &provider.auth,
            provider.forbidden_is_rejected,
        )
        .await
        {
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

    /// AWS `UriEncode`: every byte except the unreserved set as `%XY` with
    /// uppercase hex, per the Signature Version 4 reference. Slash is
    /// unreserved in the canonical URI path only. The signer takes
    /// already-canonical pieces — the STS request is constant — so this
    /// lives with the vectors that prove it.
    fn uri_encode(value: &str, encode_slash: bool) -> String {
        let mut out = String::with_capacity(value.len());
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(byte as char)
                }
                b'/' if !encode_slash => out.push('/'),
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    }

    fn finding(id: &str, rule: &str) -> Finding {
        finding_at(id, rule, "x", 1)
    }

    fn finding_at(id: &str, rule: &str, file: &str, line: usize) -> Finding {
        Finding {
            id: id.into(),
            category: "secret".into(),
            rule_id: rule.into(),
            rule_name: "test".into(),
            severity: "high".into(),
            title: "test".into(),
            description: String::new(),
            file_path: file.into(),
            line,
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

    /// Serve exactly one HTTP response, recording the entire request head
    /// (request line plus headers) the credential produced.
    async fn serve_once(
        status: &str,
        body: &str,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let status = status.to_owned();
        let body = body.to_owned();
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
            recorder
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&request).into_owned());
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        (format!("http://{address}"), seen)
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn overrides(rule: &str, url: &str) -> HashMap<String, String> {
        HashMap::from([(rule.to_string(), url.to_string())])
    }

    fn header_value<'a>(request: &'a str, name: &str) -> &'a str {
        request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with(&format!("{name}:")))
            .and_then(|line| line.split_once(':').map(|(_, value)| value))
            .map(str::trim)
            .expect("header present")
    }

    // ------------------------------------------------------------ SigV4 vectors

    /// The suite's fixed test credentials and date, shared by every vector.
    const SUITE_KEY_ID: &str = "AKIDEXAMPLE";
    const SUITE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const SUITE_DATE: &str = "20150830T123600Z";
    const SUITE_HOST: &str = "example.amazonaws.com";
    const SUITE_REGION: &str = "us-east-1";
    const SUITE_SERVICE: &str = "service";

    fn suite_authz(canonical_uri: &str, canonical_query: &str) -> String {
        sigv4_authorization(
            SUITE_KEY_ID,
            SUITE_SECRET,
            &SigV4Request {
                method: "GET",
                canonical_uri,
                canonical_query,
                host: SUITE_HOST,
                amz_date: SUITE_DATE,
                region: SUITE_REGION,
                service: SUITE_SERVICE,
            },
        )
    }

    /// AWS's official `get-vanilla` vector: plain GET, no query.
    #[test]
    fn sigv4_matches_the_official_vanilla_vector() {
        assert_eq!(
            suite_authz("/", ""),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    /// AWS's official `get-vanilla-query-order-key-case` vector: query
    /// parameters sort into canonical order before signing.
    #[test]
    fn sigv4_matches_the_official_query_order_vector() {
        assert_eq!(
            suite_authz("/", "Param1=value1&Param2=value2"),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
    }

    /// AWS's official `get-unreserved` vector: unreserved URI bytes pass
    /// through the canonical path untouched.
    #[test]
    fn sigv4_matches_the_official_unreserved_vector() {
        assert_eq!(
            suite_authz(
                "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                ""
            ),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f"
        );
    }

    /// AWS's official `get-utf8` vector: non-ASCII path bytes percent-encode
    /// as their uppercase-hex UTF-8 sequence (`/ሴ` → `/%E1%88%B4`).
    #[test]
    fn sigv4_matches_the_official_utf8_vector() {
        assert_eq!(
            suite_authz(&uri_encode("/ሴ", false), ""),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85"
        );
    }

    #[test]
    fn uri_encoding_follows_the_sigv4_reference() {
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("a/b", false), "a/b");
        assert_eq!(uri_encode("A-z._~09", true), "A-z._~09");
        assert_eq!(uri_encode(" ", true), "%20");
        assert_eq!(uri_encode("ሴ", true), "%E1%88%B4");
    }

    // ------------------------------------------------------------ AWS pairing

    fn half(value: &str, file: &str, line: usize) -> AwsHalf {
        AwsHalf {
            finding_index: 0,
            value: value.into(),
            file: file.into(),
            line,
        }
    }

    #[test]
    fn multi_profile_files_pair_each_key_with_its_own_secret() {
        let keys = [half("AKIAONE", "creds", 2), half("AKIATWO", "creds", 5)];
        let secrets = [half("s1", "creds", 3), half("s2", "creds", 6)];
        assert_eq!(pair_aws_keys(&keys, &secrets), vec![(0, 0), (1, 1)]);
    }

    #[test]
    fn a_secret_between_two_keys_is_ambiguous_and_pairs_with_neither() {
        let keys = [half("AKIAONE", "creds", 1), half("AKIATWO", "creds", 3)];
        let secrets = [half("s1", "creds", 2)];
        assert!(pair_aws_keys(&keys, &secrets).is_empty());
    }

    #[test]
    fn halves_outside_the_window_or_in_other_files_do_not_pair() {
        let keys = [half("AKIAONE", "creds", 1)];
        let far = [half("s1", "creds", 1 + PAIRING_WINDOW_LINES + 1)];
        assert!(pair_aws_keys(&keys, &far).is_empty());
        let other_file = [half("s1", "other", 1)];
        assert!(pair_aws_keys(&keys, &other_file).is_empty());
    }

    #[tokio::test]
    async fn an_aws_pair_survives_a_signed_sts_call_and_verdicts_both_findings() {
        let (url, seen) = serve_once("200 OK", "{}").await;
        let mut findings = vec![
            finding_at("k", AWS_RULE, "creds", 2),
            finding_at("s", AWS_SECRET_RULE, "creds", 3),
        ];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![
                raw("k", AWS_RULE, "AKIAZ9X8W7U6T5S4R3Q2"),
                raw(
                    "s",
                    AWS_SECRET_RULE,
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYTESTPAIRED",
                ),
            ],
            &client(),
            &overrides(AWS_RULE, &url),
        )
        .await;
        assert_eq!(findings[0].verified, Some(true));
        assert_eq!(findings[1].verified, Some(true));
        assert_eq!(
            (summary.checked, summary.live, summary.skipped_unpaired),
            (1, 1, 0)
        );

        // The request that went on the wire must be exactly the fixed STS
        // call, correctly signed for its own host and date — recompute the
        // signature from what the server actually received.
        let request = seen.lock().unwrap()[0].clone();
        assert_eq!(
            request.lines().next().unwrap(),
            "GET /?Action=GetCallerIdentity&Version=2011-06-15 HTTP/1.1"
        );
        let host = header_value(&request, "host");
        let amz_date = header_value(&request, "x-amz-date");
        let expected = sigv4_authorization(
            "AKIAZ9X8W7U6T5S4R3Q2",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYTESTPAIRED",
            &SigV4Request {
                method: "GET",
                canonical_uri: "/",
                canonical_query: AWS_STS_QUERY,
                host,
                amz_date,
                region: AWS_REGION,
                service: AWS_SERVICE,
            },
        );
        assert_eq!(header_value(&request, "authorization"), expected);
    }

    #[tokio::test]
    async fn sts_rejecting_the_pair_reports_both_findings_rejected() {
        let (url, _seen) = serve_once("403 Forbidden", "{}").await;
        let mut findings = vec![
            finding_at("k", AWS_RULE, "creds", 2),
            finding_at("s", AWS_SECRET_RULE, "creds", 3),
        ];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![
                raw("k", AWS_RULE, "AKIAZ9X8W7U6T5S4R3Q2"),
                raw(
                    "s",
                    AWS_SECRET_RULE,
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYTESTPAIRED",
                ),
            ],
            &client(),
            &overrides(AWS_RULE, &url),
        )
        .await;
        assert_eq!(findings[0].verified, Some(false));
        assert_eq!(findings[1].verified, Some(false));
        assert_eq!((summary.checked, summary.rejected), (1, 1));
    }

    #[tokio::test]
    async fn an_unpaired_aws_key_touches_no_provider_and_stays_unverified() {
        // checked counts only wire attempts, so an unreachable endpoint
        // proves no request was made without needing a live listener.
        let mut findings = vec![finding_at("k", AWS_RULE, "creds", 2)];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![raw("k", AWS_RULE, "AKIAZ9X8W7U6T5S4R3Q2")],
            &client(),
            &overrides(AWS_RULE, "http://127.0.0.1:9/"),
        )
        .await;
        assert_eq!(findings[0].verified, None);
        assert_eq!(summary.skipped_unpaired, 1);
        assert_eq!(summary.checked, 0);
    }

    #[tokio::test]
    async fn temporary_asia_keys_are_never_signed_without_their_session_token() {
        let mut findings = vec![
            finding_at("k", AWS_RULE, "creds", 2),
            finding_at("s", AWS_SECRET_RULE, "creds", 3),
        ];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![
                raw("k", AWS_RULE, "ASIAZ9X8W7U6T5S4R3Q2"),
                raw(
                    "s",
                    AWS_SECRET_RULE,
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYTESTPAIRED",
                ),
            ],
            &client(),
            &overrides(AWS_RULE, "http://127.0.0.1:9/"),
        )
        .await;
        assert_eq!(findings[0].verified, None);
        // The secret half has no remaining partner once the ASIA key drops
        // out of pairing, so it is unpaired too — and nothing hit the wire.
        assert_eq!(findings[1].verified, None);
        assert_eq!(summary.skipped_unpaired, 2);
        assert_eq!(summary.checked, 0);
    }

    // ------------------------------------------------------------ Bearer path

    #[tokio::test]
    async fn an_accepted_credential_is_live_and_travels_as_a_bearer_to_its_provider() {
        let (url, seen) = serve_once("200 OK", "{}").await;
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
            header_value(&sent, "authorization").to_ascii_lowercase(),
            "bearer ghp_livecredentialxxxxxxxxxxxxxxxxxxxxxx"
        );
    }

    #[tokio::test]
    async fn a_forbidden_response_is_still_an_authenticated_token() {
        let (url, seen) = serve_once("403 Forbidden", "{}").await;
        let verdict = validate_one(
            "github_pat_scopeless",
            &client(),
            &url,
            &[],
            false,
            &AuthStyle::Bearer,
            false,
        )
        .await;
        assert_eq!(verdict, Some(true));
        assert!(seen.lock().unwrap()[0].contains("Bearer"));
    }

    #[tokio::test]
    async fn a_rejected_credential_is_reported_not_buried() {
        let (url, _seen) = serve_once("401 Unauthorized", "{}").await;
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
        let (url, _seen) = serve_once("429 Too Many Requests", "{}").await;
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
        // `validate_raw_secrets` uses production endpoints, so this must be
        // a rule with NO validator by design — any other choice would put
        // a fake credential on the real wire.
        let mut findings = vec![finding("a", "slack-webhook")];
        let summary = validate_raw_secrets(
            &mut findings,
            vec![raw(
                "a",
                "slack-webhook",
                "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            )],
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
        // Every wire call a validating run can make, and only these origins.
        let pinned = [
            ("github-token", "https://api.github.com/user"),
            ("github-fine-grained-token", "https://api.github.com/user"),
            ("gitlab-pat", "https://gitlab.com/api/v4/user"),
            ("openai-api-key", "https://api.openai.com/v1/models"),
            ("anthropic-api-key", "https://api.anthropic.com/v1/models"),
            ("huggingface-token", "https://huggingface.co/api/whoami-v2"),
            ("npm-token", "https://registry.npmjs.org/-/whoami"),
            ("stripe-key", "https://api.stripe.com/v1/charges?limit=1"),
            ("slack-token", "https://slack.com/api/auth.test"),
        ];
        for (rule, endpoint) in pinned {
            let provider = provider_for(rule).unwrap_or_else(|| panic!("{rule} is validated"));
            assert_eq!(provider.endpoint, endpoint, "{rule}");
            assert!(!provider.body_verdict || rule == "slack-token");
        }
        // Slack is the one provider whose verdict lives in the body.
        assert!(provider_for("slack-token").unwrap().body_verdict);
        // AWS keys are not bearer credentials: they sign instead, against
        // the STS origin pinned here.
        assert!(provider_for(AWS_RULE).is_none());
        assert_eq!(AWS_STS_ENDPOINT, "https://sts.amazonaws.com/");
        // Deliberately absent, each with its reason on provider_for.
        for rule in [
            "slack-webhook",
            "google-api-key",
            "pypi-token",
            "private-key",
        ] {
            assert!(
                provider_for(rule).is_none(),
                "{rule} has no validator by design"
            );
        }
    }

    #[test]
    fn anthropic_requires_its_version_header_and_others_do_not() {
        let anthropic = provider_for("anthropic-api-key").expect("anthropic keys are validated");
        assert_eq!(
            anthropic.extra_headers,
            &[("anthropic-version", "2023-06-01")]
        );
        for rule in [
            "github-token",
            "gitlab-pat",
            "openai-api-key",
            "huggingface-token",
            "npm-token",
            "stripe-key",
        ] {
            assert!(
                provider_for(rule).unwrap().extra_headers.is_empty(),
                "{rule} sends only the credential"
            );
        }
    }

    /// One wire round trip per provider: a 200 (or 403) authenticates, a
    /// 401 rejects, and anything else stays unknown — checked against the
    /// same local server shape for every rule so a provider that drifts
    /// from the shared contract fails here, not in an incident.
    #[tokio::test]
    async fn every_bearer_provider_maps_the_shared_status_contract() {
        let rules = [
            "github-token",
            "gitlab-pat",
            "openai-api-key",
            "anthropic-api-key",
            "huggingface-token",
            "npm-token",
            "stripe-key",
            "sentry-token",
            "square-access-token",
        ];
        for rule in rules {
            for (status, expected) in [
                ("200 OK", Some(true)),
                ("401 Unauthorized", Some(false)),
                ("403 Forbidden", Some(true)),
            ] {
                let (url, _seen) = serve_once(status, "{}").await;
                let provider = provider_for(rule).unwrap();
                let verdict = validate_one(
                    "provider-contract-probe-value-000000000000",
                    &client(),
                    &url,
                    provider.extra_headers,
                    provider.body_verdict,
                    &provider.auth,
                    provider.forbidden_is_rejected,
                )
                .await;
                assert_eq!(verdict, expected, "{rule} on {status}");
            }
        }
    }

    /// The measured header-style providers: the raw credential travels in
    /// the provider's own header, not a Bearer, and a 200 means live.
    #[tokio::test]
    async fn header_style_providers_present_the_credential_in_their_measured_header() {
        for (rule, header) in [
            ("figma-token", "x-figma-token"),
            ("postman-api-key", "x-api-key"),
            ("newrelic-api-key", "x-api-key"),
            ("datadog-api-key", "dd-api-key"),
        ] {
            let (url, seen) = serve_once("200 OK", "{}").await;
            let value = "probe-credential-0000000000000000";
            let provider = provider_for(rule).unwrap();
            let verdict = validate_one(
                value,
                &client(),
                &url,
                provider.extra_headers,
                provider.body_verdict,
                &provider.auth,
                provider.forbidden_is_rejected,
            )
            .await;
            assert_eq!(verdict, Some(true), "{rule}");
            let sent = seen.lock().unwrap()[0].clone();
            assert_eq!(header_value(&sent, header), value, "{rule} header shape");
            assert!(
                !sent.to_ascii_lowercase().contains("bearer"),
                "{rule} must not send a bearer"
            );
        }
    }

    /// Datadog answers 403 for an INVALID key (measured) — the shared
    /// contract's 403-is-authenticated mapping must be overridden there, or
    /// a dead key would read as VERIFIED LIVE.
    #[tokio::test]
    async fn datadogs_forbidden_is_rejected_never_live() {
        let (url, _seen) = serve_once("403 Forbidden", "{}").await;
        let mut findings = vec![finding("a", "datadog-api-key")];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![raw(
                "a",
                "datadog-api-key",
                "9f3a7c1e5b8d2046a7c3ef57b1d904a1",
            )],
            &client(),
            &overrides("datadog-api-key", &url),
        )
        .await;
        assert_eq!(findings[0].verified, Some(false));
        assert_eq!((summary.checked, summary.rejected), (1, 1));
    }

    /// Telegram embeds the token in the URL path under the fixed origin —
    /// never in a header — and its 401 rejects.
    #[tokio::test]
    async fn telegram_tokens_travel_in_the_url_path_under_the_fixed_origin() {
        let (url, seen) = serve_once("401 Unauthorized", "{}").await;
        let token = "482913755:AAHfk3sW4x9Q2mZpV7tY8uB1cD5eF6gH7i";
        let mut findings = vec![finding("a", "telegram-bot-token")];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![raw("a", "telegram-bot-token", token)],
            &client(),
            &overrides("telegram-bot-token", &url),
        )
        .await;
        assert_eq!(findings[0].verified, Some(false));
        assert_eq!((summary.checked, summary.rejected), (1, 1));
        let sent = seen.lock().unwrap()[0].clone();
        let request_line = sent.lines().next().unwrap();
        assert!(
            request_line.contains(&format!("/bot{token}/getMe")),
            "request line: {request_line}"
        );
    }

    /// Slack answers 200 for a failed check and reports it in the body;
    /// that measured exception is why the body_verdict flag exists.
    #[tokio::test]
    async fn slack_reports_its_verdict_in_the_body_of_a_200() {
        for (body, expected) in [
            ("{\"ok\":true}", Some(true)),
            ("{\"ok\":false,\"error\":\"invalid_auth\"}", Some(false)),
            ("not json", None),
            ("{}", None),
        ] {
            let (url, _seen) = serve_once("200 OK", body).await;
            let verdict = validate_one(
                "xoxb-contract-probe",
                &client(),
                &url,
                &[],
                true,
                &AuthStyle::Bearer,
                false,
            )
            .await;
            assert_eq!(verdict, expected, "body {body}");
        }
        // A plain 401 still rejects without reading anything.
        let (url, _seen) = serve_once("401 Unauthorized", "{}").await;
        let verdict = validate_one(
            "xoxb-contract-probe",
            &client(),
            &url,
            &[],
            true,
            &AuthStyle::Bearer,
            false,
        )
        .await;
        assert_eq!(verdict, Some(false));
    }

    #[tokio::test]
    async fn a_publishable_stripe_key_is_not_a_credential_and_never_leaves() {
        let mut findings = vec![finding("a", "stripe-key")];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![raw(
                "a",
                "stripe-key",
                "pk_live_publishablekeysarepublicbydesign00",
            )],
            &client(),
            &overrides("stripe-key", "http://127.0.0.1:9/"),
        )
        .await;
        assert_eq!(findings[0].verified, None);
        assert_eq!(summary.skipped_no_validator, 1);
        assert_eq!(summary.checked, 0);
    }

    #[tokio::test]
    async fn a_secret_stripe_key_validates_like_any_bearer_credential() {
        let (url, _seen) = serve_once("200 OK", "{}").await;
        let mut findings = vec![finding("a", "stripe-key")];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![raw(
                "a",
                "stripe-key",
                "sk_live_secretkeysauthenticateapicalls00000",
            )],
            &client(),
            &overrides("stripe-key", &url),
        )
        .await;
        assert_eq!(findings[0].verified, Some(true));
        assert_eq!((summary.checked, summary.live), (1, 1));
    }

    #[tokio::test]
    async fn an_anthropic_key_travels_with_the_version_header_the_api_requires() {
        let (url, seen) = serve_once("200 OK", "{}").await;
        let mut findings = vec![finding("a", "anthropic-api-key")];
        let summary = validate_with_endpoints(
            &mut findings,
            vec![raw(
                "a",
                "anthropic-api-key",
                "sk-ant-api03-contract-probe-value-000000",
            )],
            &client(),
            &overrides("anthropic-api-key", &url),
        )
        .await;
        assert_eq!(findings[0].verified, Some(true));
        assert_eq!((summary.checked, summary.live), (1, 1));
        let request = seen.lock().unwrap()[0].clone();
        assert_eq!(
            header_value(&request, "anthropic-version"),
            "2023-06-01",
            "the API rejects requests without it"
        );
        assert!(header_value(&request, "authorization").starts_with("Bearer "));
    }
}
