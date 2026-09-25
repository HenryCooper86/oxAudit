use once_cell::sync::Lazy;
use regex::Regex;

/// A compiled secret-detection rule.
pub struct SecretRule {
    pub id: &'static str,
    pub name: &'static str,
    pub regex: Regex,
    /// keywords that must appear somewhere in the *same line* (case-insensitive);
    /// empty means no keyword requirement
    pub keywords: &'static [&'static str],
    /// minimum Shannon entropy of the captured secret value (0 = skip check)
    pub min_entropy: f32,
    /// capture group index holding the secret value
    pub secret_group: usize,
    pub severity: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
}

macro_rules! rule {
    ($id:literal, $name:literal, $re:literal, $keywords:expr, $entropy:expr, $group:expr, $sev:literal, $desc:literal, $rec:literal) => {
        SecretRule {
            id: $id,
            name: $name,
            regex: Regex::new($re).expect(concat!("invalid regex for ", $id)),
            keywords: $keywords,
            min_entropy: $entropy,
            secret_group: $group,
            severity: $sev,
            description: $desc,
            recommendation: $rec,
        }
    };
}

pub static SECRET_RULES: Lazy<Vec<SecretRule>> = Lazy::new(|| {
    vec![
        rule!(
            "aws-access-key-id",
            "AWS Access Key ID",
            r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b",
            &[],
            0.0,
            1,
            "high",
            "An AWS Access Key ID (e.g. AKIA…) was found. It can be used with the corresponding secret key to call AWS APIs on your account.",
            "Rotate the key in the AWS console (IAM → Users → Security credentials), then remove it from the source tree. Use IAM roles or a secrets manager instead."
        ),
        rule!(
            "aws-secret-key",
            "AWS Secret Access Key",
            r#"(?i)(?:aws|amazon|s3|ec2|iam)[-_ ]?(?:secret|access)[-_ ]?(?:key)?[^A-Za-z0-9]{0,10}['"\s:=]+([A-Za-z0-9/+=]{40})"#,
            &["aws"],
            3.5,
            1,
            "high",
            "A 40-character AWS secret access key was found near AWS keywords. Combined with an access key ID this grants API access.",
            "Rotate the key in IAM and revoke it from any CI/CD or source location. Store secrets in AWS Secrets Manager / environment variables."
        ),
        rule!(
            "github-token",
            "GitHub Personal Access Token",
            r"\b(ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}\b",
            &[],
            0.0,
            0,
            "high",
            "A GitHub personal access token (ghp_/gho_/ghu_/ghs_) was found. It grants repository access to the token owner's account.",
            "Revoke the token at github.com/settings/tokens and rotate it. Use GitHub Apps or short-lived OIDC tokens in CI."
        ),
        rule!(
            "github-fine-grained-token",
            "GitHub Fine-Grained PAT",
            r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
            &[],
            0.0,
            0,
            "high",
            "A GitHub fine-grained personal access token was found.",
            "Revoke the token at github.com/settings/personal-access-tokens and replace it with a scoped, short-lived credential."
        ),
        rule!(
            "gitlab-pat",
            "GitLab Personal Access Token",
            r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
            &[],
            0.0,
            0,
            "high",
            "A GitLab personal access token (glpat-…) was found.",
            "Revoke it at gitlab.com/-/user_settings/personal_access_tokens and rotate any consumers."
        ),
        rule!(
            "slack-token",
            "Slack Token",
            r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b",
            &[],
            0.0,
            0,
            "high",
            "A Slack API/bot/user token (xoxb-, xoxp-, xoxa-…) was found. It can read and post to workspaces.",
            "Rotate the token at api.slack.com/apps and remove it from source. Use Slack scoped OAuth tokens with minimal permissions."
        ),
        rule!(
            "slack-webhook",
            "Slack Webhook URL",
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{22,26}",
            &[],
            0.0,
            0,
            "high",
            "A Slack incoming webhook URL was found. Anyone with the URL can post messages into the channel.",
            "Delete and recreate the webhook in the Slack app settings, and rotate any integrations using it."
        ),
        rule!(
            "stripe-key",
            "Stripe API Key",
            r"\b(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{20,99}\b",
            &[],
            0.0,
            0,
            "high",
            "A Stripe secret/restricted key (sk_live_/rk_live_) was found. It can read and modify payment data.",
            "Rotate the key in the Stripe dashboard and restrict permissions. Use Stripe's restricted keys with minimal scopes."
        ),
        rule!(
            "google-api-key",
            "Google API Key",
            r"\bAIza[0-9A-Za-z_\-]{35}\b",
            &[],
            0.0,
            0,
            "high",
            "A Google Cloud API key (AIza…) was found. Depending on its restrictions it may bill or expose Google services.",
            "Rotate the key in Google Cloud Console → APIs & Services → Credentials, and apply API/application restrictions."
        ),
        rule!(
            "openai-api-key",
            "OpenAI API Key",
            r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{24,}\b",
            &[],
            0.0,
            0,
            "high",
            "An OpenAI API key (sk-…) was found. It can be used to call paid OpenAI APIs.",
            "Revoke the key at platform.openai.com/api-keys and store it in a secrets manager or environment variable."
        ),
        rule!(
            "anthropic-api-key",
            "Anthropic API Key",
            r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
            &[],
            0.0,
            0,
            "high",
            "An Anthropic API key (sk-ant-…) was found.",
            "Revoke the key at console.anthropic.com and rotate any consumers."
        ),
        rule!(
            "huggingface-token",
            "Hugging Face Token",
            r"\bhf_[A-Za-z0-9]{34}\b",
            &[],
            0.0,
            0,
            "high",
            "A Hugging Face access token (hf_…) was found.",
            "Revoke it at huggingface.co/settings/tokens."
        ),
        rule!(
            "npm-token",
            "npm Access Token",
            r"\bnpm_[A-Za-z0-9]{36}\b",
            &[],
            0.0,
            0,
            "high",
            "An npm automation/granular access token (npm_…) was found. It can publish or read private packages.",
            "Revoke it at npmjs.com/settings/tokens."
        ),
        rule!(
            "pypi-token",
            "PyPI Upload Token",
            r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{40,}\b",
            &[],
            0.0,
            0,
            "high",
            "A PyPI project upload token (pypi-AgEI…) was found.",
            "Revoke it at pypi.org/manage/account/token/ and use trusted publishers instead."
        ),
        rule!(
            "private-key",
            "Private Key",
            r"(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            &[],
            0.0,
            0,
            "critical",
            "A private key (RSA/EC/OpenSSH/DSA/PGP) was found in the source tree. Anyone with this key can impersonate the identity it signs for.",
            "Generate a new key pair, revoke the old one wherever it is registered (SSH servers, code-signing, TLS, PGP), and never commit private keys."
        ),
        rule!(
            "heroku-api-key",
            "Heroku API Key",
            r"(?i)heroku.{0,40}?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            &["heroku"],
            0.0,
            1,
            "high",
            "A Heroku API key (UUID format) was found near the string 'heroku'.",
            "Rotate the key at dashboard.heroku.com/account and use OAuth flows where possible."
        ),
        rule!(
            "twilio-api-key",
            "Twilio API Key",
            r"\bSK[0-9a-fA-F]{32}\b",
            &[],
            0.0,
            0,
            "high",
            "A Twilio API key (SK… + 32 hex) was found.",
            "Revoke it in the Twilio console and rotate the associated secret."
        ),
        rule!(
            "sendgrid-api-key",
            "SendGrid API Key",
            r"\bSG\.[A-Za-z0-9_\-\.]{22,}\b",
            &[],
            0.0,
            0,
            "high",
            "A SendGrid API key (SG.…) was found. It can send email as your account.",
            "Rotate the key at app.sendgrid.com/settings/api_keys."
        ),
        rule!(
            "mailgun-api-key",
            "Mailgun API Key",
            r"\bkey-[0-9a-zA-Z]{32}\b",
            &[],
            0.0,
            0,
            "high",
            "A Mailgun API key (key-…) was found.",
            "Rotate the key in the Mailgun dashboard."
        ),
        rule!(
            "discord-webhook",
            "Discord Webhook URL",
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,68}",
            &[],
            0.0,
            0,
            "high",
            "A Discord webhook URL was found. Anyone with it can post messages into the Discord channel.",
            "Delete the webhook in Discord server settings → Integrations, and rotate any usage."
        ),
        rule!(
            "digitalocean-token",
            "DigitalOcean Token",
            r"\bdop_v1_[a-f0-9]{64}\b",
            &[],
            0.0,
            0,
            "high",
            "A DigitalOcean personal access token (dop_v1_…) was found.",
            "Revoke it at cloud.digitalocean.com/account/api/tokens."
        ),
        rule!(
            "shopify-token",
            "Shopify Access Token",
            r"\bshpat_[a-fA-F0-9]{32}\b",
            &[],
            0.0,
            0,
            "high",
            "A Shopify admin access token (shpat_…) was found.",
            "Rotate it in the Shopify admin and use scoped tokens with least privilege."
        ),
        rule!(
            "cloudflare-api-key",
            "Cloudflare API Key",
            r"(?i)(?:cloudflare|cf-api-key|x-auth-key).{0,30}?([a-zA-Z0-9]{37})",
            &["cloudflare"],
            0.0,
            1,
            "high",
            "A 37-character Cloudflare API key was found near Cloudflare keywords.",
            "Rotate the key in the Cloudflare dashboard and switch to scoped API tokens."
        ),
        rule!(
            "vault-token",
            "HashiCorp Vault Token",
            r"\bs\.[A-Za-z0-9]{24,}\b",
            &[],
            0.0,
            0,
            "high",
            "A HashiCorp Vault token (s.…) was found. It grants access to secrets stored in Vault.",
            "Revoke the token (`vault token revoke`) and use short-lived tokens, AppRole or OIDC auth."
        ),
        rule!(
            "jwt-token",
            "JWT",
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
            &[],
            0.0,
            0,
            "medium",
            "A JWT (JSON Web Token) was found. If it is a signed production token it can authenticate API requests.",
            "Verify whether the token is a real credential; rotate it if so. Never store live tokens in source — inject them at runtime."
        ),
        rule!(
            "basic-auth-url",
            "Credentials in URL",
            r"(?:https?|ftp)://[^/\s:@]+:[^@\s/]+@",
            &[],
            0.0,
            0,
            "high",
            "A URL containing embedded username:password credentials was found (basic auth).",
            "Remove credentials from URLs; use an HTTP client that reads them from environment variables or a secrets manager."
        ),
        rule!(
            "bearer-token",
            "Bearer Token",
            r"(?i)\b(?:authorization|bearer)\s*[:=]\s*([A-Za-z0-9\-._~+/]{12,}={0,2})",
            &["bearer", "authorization"],
            4.0,
            1,
            "high",
            "A high-entropy bearer/authorization token was found. It may grant API access to a remote service.",
            "Rotate the token and remove it from source. Prefer short-lived tokens fetched at runtime."
        ),
        rule!(
            "generic-api-key",
            "Generic API Key / Secret",
            r#"(?i)(?:^|[^A-Za-z0-9])(?:api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret|app[_-]?secret|consumer[_-]?secret|secret[_-]?key|private[_-]?key|token|credential)(?:$|[^A-Za-z0-9])[^A-Za-z0-9\r\n]{0,10}['"]([A-Za-z0-9_\-\.=+/]{16,200})"#,
            &[],
            3.5,
            1,
            "high",
            "A high-entropy value assigned to a key/secret/token variable was found. This pattern commonly indicates a leaked credential.",
            "Verify whether this is a real credential. If so, rotate it and move it to a secrets manager or environment variable."
        ),
        rule!(
            "generic-password",
            "Generic Password",
            r#"(?i)(?:^|[^A-Za-z0-9])(?:password|passwd|pwd|secret)[^A-Za-z0-9\r\n|,]{1,10}['"]([^'"\r\n]{8,64})['"]"#,
            &["password", "passwd", "pwd", "secret"],
            2.8,
            1,
            "medium",
            "A value assigned to a password/passwd/pwd/secret variable was found. It may be a hardcoded credential.",
            "Review the value: if it is a real credential, rotate it and store it in a secrets manager. Consider using `getpass`/env vars."
        ),
        rule!(
            "json-credential",
            "JSON/YAML Credential Field",
            r#"(?i)("(?:password|passwd|secret|api_key|apikey|token|client_secret|private_key)"\s*:\s*")([^"]{8,})"#,
            &[],
            3.0,
            2,
            "high",
            "A credential field (password/secret/token) with a value was found in a JSON/YAML configuration file.",
            "Move the credential out of the config file into environment variables or a secrets manager, then rotate it."
        ),
        rule!(
            "google-oauth-client-id",
            "Google OAuth Client ID",
            r"\b[0-9]{12,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b",
            &[],
            0.0,
            0,
            "info",
            "A Google OAuth client ID was found. Client IDs are not secret, but verify the matching client secret is not nearby.",
            "Keep the client secret out of source. Restrict the OAuth client's redirect URIs and origins."
        ),
        rule!(
            "telegram-bot-token",
            "Telegram Bot Token",
            r"\b([0-9]{8,10}:AA[A-Za-z0-9_-]{33})\b",
            &[],
            0.0,
            1,
            "high",
            "A Telegram bot token was found. It grants full control of the bot, including sending messages as it.",
            "Revoke the token with @BotFather (/revoke) and move it to environment variables or a secrets manager."
        ),
        rule!(
            "sentry-token",
            "Sentry Auth Token",
            r"\b(sntrys_[A-Za-z0-9_-]{40,})\b",
            &[],
            0.0,
            0,
            "high",
            "A Sentry user auth token (sntrys_) was found. It can read and modify the org's projects and events.",
            "Revoke the token at sentry.io → Settings → Auth Tokens and rotate it into a secrets manager."
        ),
        rule!(
            "newrelic-api-key",
            "New Relic User API Key",
            r"\b(NRAK-[A-Z0-9]{27})\b",
            &[],
            0.0,
            0,
            "high",
            "A New Relic user API key (NRAK-) was found. It can query and change the account's applications and alerts.",
            "Rotate the key at onenr.co → API keys and store the replacement in a secrets manager."
        ),
        rule!(
            "postman-api-key",
            "Postman API Key",
            r"\b(PMAK-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}-[A-Za-z0-9]{60,})\b",
            &[],
            0.0,
            0,
            "high",
            "A Postman API key (PMAK-) was found. It can read and update the workspace's collections and environments.",
            "Regenerate the key in Postman → Account → API keys and store it outside the repository."
        ),
        rule!(
            "linear-api-key",
            "Linear API Key",
            r"\b(lin_api_[A-Za-z0-9]{40})\b",
            &[],
            0.0,
            0,
            "high",
            "A Linear API key (lin_api_) was found. It can read and modify the workspace's issues and projects.",
            "Revoke the key at linear.app → Settings → API and rotate it into a secrets manager."
        ),
        rule!(
            "figma-token",
            "Figma Personal Access Token",
            r"\b(figd_[A-Za-z0-9]{40})\b",
            &[],
            0.0,
            0,
            "high",
            "A Figma personal access token (figd_) was found. It can read and edit the user's Figma files.",
            "Revoke the token at figma.com → Settings → Security → Personal access tokens."
        ),
        rule!(
            "grafana-service-account-token",
            "Grafana Service Account Token",
            r"\b(glsa_[A-Za-z0-9]{20,})\b",
            &[],
            3.0,
            0,
            "high",
            "A Grafana service account token (glsa_) was found. It can query and administer the Grafana instance it was minted for.",
            "Revoke the token in Grafana → Administration → Service accounts and rotate it."
        ),
        rule!(
            "square-access-token",
            "Square Access Token",
            r"\b((?:sq0atp-[0-9A-Za-z_-]{22,43}|EAAA[A-Za-z0-9_-]{50,}))\b",
            &[],
            3.0,
            1,
            "high",
            "A Square access token was found. It can access and charge the merchant's payment data.",
            "Revoke the token in the Square Developer Dashboard and rotate it into a secrets manager."
        ),
        rule!(
            "plaid-api-key",
            "Plaid Secret / API Key",
            r"\b((?:production|development|sandbox)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
            &[],
            0.0,
            1,
            "high",
            "A Plaid environment secret key was found. It authenticates API access to the Plaid environment it names.",
            "Rotate the secret in the Plaid Dashboard and store the replacement outside the repository."
        ),
        rule!(
            "datadog-api-key",
            "Datadog API Key",
            r#"(?i)(?:datadog|dd)[-_ ]?(?:api)?[-_ ]?key[^A-Za-z0-9]{0,10}[\'"\s:=]+([0-9a-f]{32})"#,
            &["datadog"],
            3.5,
            1,
            "high",
            "A 32-hex-character Datadog API key was found near Datadog keywords. It submits metrics and reads the account's data.",
            "Rotate the key at app.datadoghq.com → Organization Settings → API Keys."
        ),
        rule!(
            "azure-storage-account-key",
            "Azure Storage Account Key",
            r#"(?i)account[-_ ]?key[^A-Za-z0-9]{0,8}[\'"=\s]{0,4}([A-Za-z0-9+/=]{88})"#,
            &["account"],
            3.0,
            1,
            "high",
            "An 88-character Azure storage account key was found beside its AccountKey assignment. It grants full access to the storage account.",
            "Rotate the key in the Azure portal (Storage account → Access keys) and use managed identities instead."
        ),
    ]
});

/// Shannon entropy (base 2) of a string — used to distinguish random-looking
/// secret material from ordinary words.
pub fn shannon_entropy(s: &str) -> f32 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut entropy = 0.0f32;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Values that should never be flagged as credentials.
const PLACEHOLDERS: &[&str] = &[
    "changeme",
    "change_me",
    "change-me",
    "yourpassword",
    "your_password",
    "your-password",
    "password",
    "passw0rd",
    "example",
    "placeholder",
    "dummy",
    "test",
    "sample",
    "xxxxx",
    "xxxxxx",
    "*****",
    "******",
    "redacted",
    "todo",
    "fixme",
    "lorem",
    "secret123",
    "default",
    "unknown",
    "none",
    "null",
    "true",
    "false",
    "12345678",
    "abcdefgh",
];

/// Returns true if the value looks like a placeholder rather than a real secret.
///
/// The check is length-aware: short values may match placeholder *substrings*
/// ("example", "test", "changeme"…), but longer values are almost certainly
/// real credentials even when they happen to contain such words, so for them
/// only exact matches or all-symbol values count.
pub fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let len = lower.len();
    if len < 4 {
        return true;
    }
    // all-asterisk / all-x / dot-fill values (e.g. "******", "xxxxx")
    if value
        .chars()
        .all(|c| matches!(c, 'x' | 'X' | '*' | '.' | '0' | '-'))
    {
        return true;
    }
    if PLACEHOLDERS.iter().any(|p| lower == *p) {
        return true;
    }
    if len <= 24 {
        return PLACEHOLDERS
            .iter()
            .any(|p| p.len() >= 4 && lower.contains(p));
    }
    false
}

/// A single secret hit produced by the engine.
pub(super) struct SecretHit {
    pub(super) rule_index: usize,
    pub(super) offset: usize,
    pub(super) match_text: String,
    pub(super) secret_value: String,
    pub(super) entropy: f32,
}

/// Run all secret rules against a whole file's content.
/// Byte offsets are relative to `content`; the scanner maps them to line numbers.
pub(super) fn scan_content(content: &str) -> Vec<SecretHit> {
    scan_content_bounded(content, usize::MAX).0
}

pub(super) fn scan_content_bounded(content: &str, limit: usize) -> (Vec<SecretHit>, bool) {
    let mut hits = Vec::new();
    for (i, rule) in SECRET_RULES.iter().enumerate() {
        for caps in rule.regex.captures_iter(content) {
            let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let secret = caps
                .get(rule.secret_group)
                .map(|m| m.as_str())
                .unwrap_or(whole);
            if is_placeholder(secret) {
                continue;
            }
            if rule.min_entropy > 0.0 {
                let e = shannon_entropy(secret);
                if e < rule.min_entropy {
                    continue;
                }
            }
            // Keyword prefilter: the keyword must appear in the line containing
            // the match (cheap safeguard for broad rules).
            if !rule.keywords.is_empty() {
                let start = caps.get(0).map(|m| m.start()).unwrap_or(0);
                let line_start = content[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let line_end = content[line_start..]
                    .find('\n')
                    .map(|i| line_start + i)
                    .unwrap_or(content.len());
                let line_lower = content[line_start..line_end].to_ascii_lowercase();
                if !rule.keywords.iter().any(|k| line_lower.contains(k)) {
                    continue;
                }
            }
            let e = if rule.min_entropy > 0.0 {
                shannon_entropy(secret)
            } else {
                0.0
            };
            let off = caps.get(0).map(|m| m.start()).unwrap_or(0);
            if hits.len() >= limit {
                return (hits, true);
            }
            hits.push(SecretHit {
                rule_index: i,
                offset: off,
                match_text: whole.to_string(),
                secret_value: secret.to_string(),
                entropy: e,
            });
        }
    }
    (hits, false)
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}
