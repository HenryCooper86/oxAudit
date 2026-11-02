use once_cell::sync::Lazy;
use regex::Regex;

/// Rules whose matches stand even inside a source comment.
///
/// Comments usually hold prose about credentials, so most rules are
/// suppressed there. A vendor-prefixed token or a PEM key is different: its
/// shape alone proves what it is, and a commented-out credential is still a
/// leaked credential. History scans and `--staged` already report these.
const REPORTED_IN_COMMENTS: &[&str] = &[
    "aws-access-key-id",
    "github-token",
    "github-fine-grained-token",
    "gitlab-pat",
    "slack-token",
    "slack-webhook",
    "stripe-key",
    "google-api-key",
    "openai-api-key",
    "anthropic-api-key",
    "huggingface-token",
    "npm-token",
    "pypi-token",
    "private-key",
    "sendgrid-api-key",
    "discord-webhook",
    "digitalocean-token",
    "shopify-token",
    "vault-token",
    "telegram-bot-token",
    "sentry-token",
    "newrelic-api-key",
    "postman-api-key",
    "linear-api-key",
    "figma-token",
    "grafana-service-account-token",
    "square-access-token",
];

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

impl SecretRule {
    /// Whether a match inside a source comment is still reported.
    pub fn reported_in_comments(&self) -> bool {
        REPORTED_IN_COMMENTS.contains(&self.id)
    }
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
            r"\b(?:hv[sbr]\.[A-Za-z0-9_\-]{24,}|s\.[A-Za-z0-9]{24,})\b",
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
            r"(?i)\b(?:https?|ftp|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://[^/\s:@]*:[^@\s/$%{<][^@\s/]*@",
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
    pub(super) secret_offset: usize,
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
                secret_offset: caps
                    .get(rule.secret_group)
                    .or_else(|| caps.get(0))
                    .map_or(off, |secret| secret.start()),
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

#[cfg(test)]
mod tests {
    use super::*;

    const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const UPPER_DIGITS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const LOWER_HEX: &str = "0123456789abcdef";
    const BASE64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const DIGITS: &str = "0123456789";

    /// A deterministic high-entropy run, so samples are built at test time
    /// and no credential-shaped literal sits in the source tree.
    fn mix(seed: u64, len: usize, alphabet: &str) -> String {
        let alphabet = alphabet.as_bytes();
        let mut state = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                alphabet[((state >> 33) % alphabet.len() as u64) as usize] as char
            })
            .collect()
    }

    fn uuid(seed: u64) -> String {
        let hex = mix(seed, 32, LOWER_HEX);
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    }

    fn rule_ids(content: &str) -> Vec<&'static str> {
        scan_content(content)
            .into_iter()
            .map(|hit| SECRET_RULES[hit.rule_index].id)
            .collect()
    }

    fn samples() -> Vec<(&'static str, String)> {
        vec![
            (
                "aws-access-key-id",
                format!(
                    "key = {}{}",
                    "AK",
                    ["IA", &mix(1, 16, UPPER_DIGITS)].concat()
                ),
            ),
            (
                "aws-secret-key",
                format!("aws_secret_key = \"{}\"", mix(2, 40, BASE64)),
            ),
            (
                "github-token",
                format!("token = {}_{}", "ghp", mix(3, 36, ALNUM)),
            ),
            (
                "github-fine-grained-token",
                format!("token = {}_pat_{}", "github", mix(4, 82, ALNUM)),
            ),
            (
                "gitlab-pat",
                format!("token = {}-{}", "glpat", mix(5, 20, ALNUM)),
            ),
            (
                "slack-token",
                format!("token = {}-{}", "xoxb", mix(6, 40, ALNUM)),
            ),
            (
                "slack-webhook",
                format!(
                    "url = https://hooks.slack.com/services/T{}/B{}/{}",
                    mix(7, 10, UPPER_DIGITS),
                    mix(8, 10, UPPER_DIGITS),
                    mix(9, 24, ALNUM)
                ),
            ),
            (
                "stripe-key",
                format!("key = {}_live_{}", "sk", mix(10, 24, ALNUM)),
            ),
            (
                "google-api-key",
                format!("key = {}{}", "AI", ["za", &mix(11, 35, ALNUM)].concat()),
            ),
            (
                "openai-api-key",
                format!("key = {}-proj-{}", "sk", mix(12, 40, ALNUM)),
            ),
            (
                "anthropic-api-key",
                format!("key = {}-ant-{}", "sk", mix(13, 40, ALNUM)),
            ),
            (
                "huggingface-token",
                format!("token = {}_{}", "hf", mix(14, 34, ALNUM)),
            ),
            (
                "npm-token",
                format!(
                    "//registry.npmjs.org/:_authToken={}_{}",
                    "npm",
                    mix(15, 36, ALNUM)
                ),
            ),
            (
                "pypi-token",
                format!(
                    "password = {}-AgEIcHlwaS5vcmc{}",
                    "pypi",
                    mix(16, 50, ALNUM)
                ),
            ),
            (
                "private-key",
                format!(
                    "-----BEGIN RSA {} KEY-----\n{}\n-----END RSA {} KEY-----",
                    "PRIVATE",
                    mix(17, 64, BASE64),
                    "PRIVATE"
                ),
            ),
            ("heroku-api-key", format!("HEROKU_API_KEY={}", uuid(18))),
            (
                "twilio-api-key",
                format!("key = {}{}", "SK", mix(19, 32, LOWER_HEX)),
            ),
            (
                "sendgrid-api-key",
                format!(
                    "key = {}.{}.{}",
                    "SG",
                    mix(20, 22, ALNUM),
                    mix(21, 43, ALNUM)
                ),
            ),
            (
                "mailgun-api-key",
                format!("key = {}-{}", "key", mix(22, 32, ALNUM)),
            ),
            (
                "discord-webhook",
                format!(
                    "url = https://discord.com/api/webhooks/{}/{}",
                    mix(23, 18, DIGITS),
                    mix(24, 68, ALNUM)
                ),
            ),
            (
                "digitalocean-token",
                format!("token = {}_v1_{}", "dop", mix(25, 64, LOWER_HEX)),
            ),
            (
                "shopify-token",
                format!("token = {}_{}", "shpat", mix(26, 32, LOWER_HEX)),
            ),
            (
                "cloudflare-api-key",
                format!("CLOUDFLARE_API_KEY={}", mix(27, 37, ALNUM)),
            ),
            (
                "vault-token",
                format!("VAULT_TOKEN={}.{}", "hvs", mix(28, 90, ALNUM)),
            ),
            (
                "jwt-token",
                format!(
                    "token = {}{}.{}{}.{}",
                    "ey",
                    ["J", &mix(29, 20, ALNUM)].concat(),
                    "eyJ",
                    mix(30, 30, ALNUM),
                    mix(31, 43, ALNUM)
                ),
            ),
            (
                "basic-auth-url",
                format!(
                    "url = https://deploy:{}@example.com/repo",
                    mix(32, 16, ALNUM)
                ),
            ),
            (
                "bearer-token",
                format!("authorization = {}", mix(33, 40, ALNUM)),
            ),
            (
                "generic-api-key",
                format!("api_key = \"{}\"", mix(34, 32, ALNUM)),
            ),
            (
                "generic-password",
                format!("password = \"{}\"", mix(35, 16, ALNUM)),
            ),
            (
                "json-credential",
                format!("{{\"client_secret\": \"{}\"}}", mix(36, 24, ALNUM)),
            ),
            (
                "google-oauth-client-id",
                format!(
                    "id = {}-{}.apps.googleusercontent.com",
                    mix(37, 12, DIGITS),
                    mix(38, 32, "abcdefghijklmnopqrstuvwxyz0123456789")
                ),
            ),
            (
                "telegram-bot-token",
                format!("token = {}:AA{}", mix(39, 9, DIGITS), mix(40, 33, ALNUM)),
            ),
            (
                "sentry-token",
                format!("token = {}_{}", "sntrys", mix(41, 60, ALNUM)),
            ),
            (
                "newrelic-api-key",
                format!("key = {}-{}", "NRAK", mix(42, 27, UPPER_DIGITS)),
            ),
            (
                "postman-api-key",
                format!("key = {}-{}-{}", "PMAK", uuid(43), mix(44, 64, ALNUM)),
            ),
            (
                "linear-api-key",
                format!("key = {}_api_{}", "lin", mix(45, 40, ALNUM)),
            ),
            (
                "figma-token",
                format!("token = {}_{}", "figd", mix(46, 40, ALNUM)),
            ),
            (
                "grafana-service-account-token",
                format!("token = {}_{}", "glsa", mix(47, 32, ALNUM)),
            ),
            (
                "square-access-token",
                format!("token = {}-{}", "sq0atp", mix(48, 30, ALNUM)),
            ),
            (
                "plaid-api-key",
                format!("secret = {}_{}", "production", uuid(49)),
            ),
            (
                "datadog-api-key",
                format!("datadog_api_key = \"{}\"", mix(50, 32, LOWER_HEX)),
            ),
            (
                "azure-storage-account-key",
                format!("AccountKey={}==", mix(51, 86, BASE64)),
            ),
        ]
    }

    #[test]
    fn every_rule_detects_its_canonical_example() {
        let samples = samples();
        let mut sampled: Vec<&str> = samples.iter().map(|(id, _)| *id).collect();
        let mut rules: Vec<&str> = SECRET_RULES.iter().map(|rule| rule.id).collect();
        sampled.sort_unstable();
        rules.sort_unstable();
        assert_eq!(sampled, rules, "every secret rule needs a sample here");
        let missed: Vec<String> = samples
            .iter()
            .filter_map(|(id, sample)| {
                let fired = rule_ids(sample);
                (!fired.contains(id)).then(|| format!("{id} (fired {fired:?})"))
            })
            .collect();
        assert!(
            missed.is_empty(),
            "rules that missed their sample: {missed:#?}"
        );
    }

    #[test]
    fn comment_exemptions_name_existing_rules() {
        for id in REPORTED_IN_COMMENTS {
            assert!(SECRET_RULES.iter().any(|rule| rule.id == *id), "{id}");
        }
    }

    #[test]
    fn vault_service_batch_and_recovery_tokens_match() {
        for prefix in ["hvs", "hvb", "hvr"] {
            let line = format!("VAULT_TOKEN={prefix}.{}", mix(60, 90, ALNUM));
            assert!(rule_ids(&line).contains(&"vault-token"), "{prefix}");
        }
        let legacy = format!("VAULT_TOKEN={}.{}", "s", mix(61, 24, ALNUM));
        assert!(rule_ids(&legacy).contains(&"vault-token"));
    }

    #[test]
    fn database_connection_string_passwords_match() {
        let password = mix(62, 18, ALNUM);
        for url in [
            format!("postgres://app:{password}@db:5432/app"),
            format!("postgresql://app:{password}@db/app"),
            format!("mysql://root:{password}@127.0.0.1/app"),
            format!("mongodb+srv://admin:{password}@cluster0.example.net/app"),
            format!("redis://:{password}@cache:6379/0"),
            format!("amqp://guest:{password}@rabbit:5672/"),
        ] {
            let line = format!("DATABASE_URL = \"{url}\"");
            assert!(rule_ids(&line).contains(&"basic-auth-url"), "{url}");
        }
    }

    #[test]
    fn url_credentials_redact_the_whole_match_as_before() {
        // Fingerprints hash the redacted context, so changing what is
        // redacted would orphan every saved review decision for this rule.
        let line = format!(
            "url = https://deploy:{}@example.com/repo",
            mix(70, 16, ALNUM)
        );
        let hit = scan_content(&line)
            .into_iter()
            .find(|hit| SECRET_RULES[hit.rule_index].id == "basic-auth-url")
            .expect("basic-auth-url fires");
        assert_eq!(hit.secret_value, hit.match_text);
    }

    #[test]
    fn weak_real_url_passwords_are_still_reported() {
        for url in [
            "https://deploy-bot:Password1@intranet.example/",
            "postgres://app:latest2024x@db/app",
        ] {
            assert!(rule_ids(url).contains(&"basic-auth-url"), "{url}");
        }
    }

    #[test]
    fn templated_url_passwords_are_not_secrets() {
        for url in [
            "postgres://app:${DB_PASSWORD}@db/app",
            "postgres://app:%(password)s@db/app",
            "mysql://root:{{password}}@db/app",
            "https://deploy:<password>@example.com/",
        ] {
            assert!(!rule_ids(url).contains(&"basic-auth-url"), "{url}");
        }
    }
}
