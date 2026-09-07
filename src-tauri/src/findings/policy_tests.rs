//! Tests for [`super`].
//!
//! Kept a child module rather than moved to `tests/`: these reach private
//! items through `use super::*`, and widening their visibility to run them
//! from outside would be a worse design than a long file. This is purely a
//! split for readability — policy.rs was 5677 lines.

use std::{fs, path::Path};

use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};

use super::*;
use crate::{
    findings::domain::{
        PolicyStatus, ReviewOrigin, ReviewRecord, ReviewRequest, ReviewState, FINGERPRINT_VERSION,
    },
    models::Finding,
    triage::gates::{Gate, GateNote, GateVerdict},
};

const CANARY: &str = "oxaudit-secret-canary-7D4zP9q2";
const VALID_POLICY: &str = r#"{
  "version": 1,
  "entries": [
    {
      "kind": "finding",
      "fingerprintVersion": 1,
      "fingerprint": "abc123",
      "category": "vulnerability",
      "state": "falsePositive",
      "reason": "The affected branch is excluded from production",
      "gates": [
        {
          "gate": "reachable",
          "verdict": "eliminates",
          "evidence": "The production feature manifest excludes this branch"
        }
      ],
      "decidingGate": "reachable"
    },
    {
      "kind": "suppression",
      "ruleId": "gen-hardcoded-password",
      "pathPattern": "tests/**",
      "state": "suppressed",
      "reason": "Synthetic credential fixtures",
      "expiresAt": "2027-01-01T00:00:00Z"
    }
  ]
}"#;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0)
        .single()
        .unwrap()
}

fn write_policy(root: &Path, bytes: &[u8]) {
    fs::create_dir_all(root.join(".oxaudit")).unwrap();
    fs::write(root.join(".oxaudit/policy.json"), bytes).unwrap();
}

fn load_json(root: &Path, json: serde_json::Value) -> LoadedPolicy {
    write_policy(
        root,
        serde_json::to_string_pretty(&json).unwrap().as_bytes(),
    );
    load_policy(root).unwrap()
}

fn status_hash(loaded: &LoadedPolicy) -> Option<&str> {
    match loaded.status() {
        PolicyStatus::Valid { hash } => Some(hash),
        _ => None,
    }
}

fn apply(
    loaded: &LoadedPolicy,
    fingerprint: &str,
    category: &str,
    rule_id: &str,
    path: &str,
    local: Option<&ReviewRecord>,
) -> Result<ReviewRecord, crate::findings::error::CommandError> {
    apply_policy(
        loaded,
        "project-1",
        FINGERPRINT_VERSION,
        fingerprint,
        category,
        rule_id,
        path,
        local,
        now(),
    )
}

fn finding(category: &str) -> Finding {
    Finding {
        id: "observation-1".into(),
        category: category.into(),
        rule_id: "generic-api-key".into(),
        rule_name: format!("rule {CANARY}"),
        severity: "high".into(),
        title: format!("title {CANARY}"),
        description: format!("description {CANARY}"),
        file_path: "src/config.rs".into(),
        line: 8,
        column: 17,
        match_text: format!("token = {CANARY}"),
        context: format!("let token = \"{CANARY}\";"),
        language: "rust".into(),
        cwe: Some("CWE-798".into()),
        cwe_exploited: false,
        cwe_exploited_count: 0,
        recommendation: format!("rotate {CANARY}"),
        entropy: Some(4.95),
        verified: None,
        analysis: Default::default(),
        analysis_gates: Vec::new(),
        observation_run_id: format!("run-{CANARY}"),
        resolved_by_run_id: None,
        fingerprint_version: FINGERPRINT_VERSION,
        fingerprint: "abcdef0123456789".into(),
        in_test_region: false,
        scope: None,
        scope_reason: Some(format!("scope {CANARY}")),
        review: None,
        review_history: Vec::new(),
        diff_status: None,
    }
}

fn request(state: ReviewState, category: &str) -> ReviewRequest {
    ReviewRequest {
        project_id: "project-1".into(),
        fingerprint_version: FINGERPRINT_VERSION,
        fingerprint: "abcdef0123456789".into(),
        category: category.into(),
        state,
        reason: "Reviewed by the application security team".into(),
        evidence: None,
        entry_point: None,
        data_flow: None,
        gates: Vec::new(),
        deciding_gate: None,
        expires_at: Some("2027-01-01T00:00:00Z".into()),
        origin: ReviewOrigin::ProjectPolicy,
    }
}

fn local_review() -> ReviewRecord {
    ReviewRecord {
        id: "local-review".into(),
        project_id: "project-1".into(),
        fingerprint_version: FINGERPRINT_VERSION,
        fingerprint: "abc123".into(),
        state: ReviewState::AcceptedRisk,
        reason: "Local decision".into(),
        evidence: None,
        entry_point: None,
        data_flow: None,
        gates: Vec::new(),
        deciding_gate: None,
        expires_at: None,
        origin: ReviewOrigin::Local,
        policy_hash: None,
        updated_at: "2026-08-20T00:00:00Z".into(),
        superseded_at: None,
    }
}

#[test]
fn missing_policy_has_an_explicit_missing_status() {
    let root = tempfile::tempdir().unwrap();
    let loaded = load_policy(root.path()).unwrap();
    assert_eq!(loaded.status(), &PolicyStatus::Missing);
    assert!(loaded.policy().is_none());
}

#[test]
fn valid_policy_hashes_the_exact_authoritative_bytes_and_is_stable_on_reload() {
    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), VALID_POLICY.as_bytes());
    let expected = format!("{:x}", Sha256::digest(VALID_POLICY.as_bytes()));

    let first = load_policy(root.path()).unwrap();
    let second = load_policy(root.path()).unwrap();

    assert_eq!(status_hash(&first), Some(expected.as_str()));
    assert_eq!(status_hash(&second), Some(expected.as_str()));
    assert_eq!(first.policy().unwrap().entries.len(), 2);
}

#[test]
fn invalid_schema_is_reported_with_one_fixed_safe_status_and_preserved() {
    let invalid_cases = [
        serde_json::json!({"version": 2, "entries": []}),
        serde_json::json!({"version": 1, "entries": [], "unknown": "private"}),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
            "state": "suppressed", "reason": "valid", "context": CANARY
        }]}),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
            "state": "suppressed"
        }]}),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
            "state": "suppressed", "reason": "   "
        }]}),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
            "state": "candidate", "reason": "not portable"
        }]}),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "vulnerability", "state": "confirmed", "reason": "local only"
        }]}),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
            "state": "suppressed", "reason": "valid", "expiresAt": "tomorrow"
        }]}),
    ];

    for (index, policy) in invalid_cases.into_iter().enumerate() {
        let root = tempfile::tempdir().unwrap();
        let bytes = serde_json::to_vec(&policy).unwrap();
        write_policy(root.path(), &bytes);
        let loaded = load_policy(root.path()).unwrap();
        assert_eq!(
            loaded.status(),
            &PolicyStatus::Invalid {
                message: "The project policy is invalid.".into()
            },
            "case {index}"
        );
        assert!(loaded.policy().is_none(), "case {index}");
        assert_eq!(
            fs::read(root.path().join(".oxaudit/policy.json")).unwrap(),
            bytes,
            "case {index}"
        );
    }
}

#[test]
fn duplicate_json_keys_are_rejected_at_every_object_depth() {
    let duplicates = [
        r#"{"version":999,"version":1,"entries":[]}"#,
        r#"{"version":1,"entries":[{"kind":"unknown","kind":"suppression","ruleId":"rule","pathPattern":"tests/**","state":"suppressed","reason":"Fixture"}]}"#,
        r#"{"version":1,"entries":[{"kind":"suppression","ruleId":"rule","pathPattern":"tests/**","state":"acceptedRisk","state":"suppressed","reason":"Fixture"}]}"#,
        r#"{"version":1,"entries":[{"kind":"finding","fingerprintVersion":1,"fingerprint":"abc123","category":"vulnerability","category":"secret","state":"acceptedRisk","reason":"Fixture"}]}"#,
        r#"{"version":1,"entries":[{"kind":"finding","fingerprintVersion":1,"fingerprint":"abc123","category":"vulnerability","state":"falsePositive","reason":"Fixture","gates":[{"gate":"reachable","verdict":"survives","verdict":"eliminates","evidence":"Excluded"}],"decidingGate":"reachable"}]}"#,
    ];
    for (index, bytes) in duplicates.into_iter().enumerate() {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), bytes.as_bytes());
        assert!(
            matches!(
                load_policy(root.path()).unwrap().status(),
                PolicyStatus::Invalid { .. }
            ),
            "accepted duplicate-key fixture {index}"
        );
    }
}

#[test]
fn nonportable_and_unsafe_patterns_are_rejected_without_normalization() {
    for pattern in [
        "/tests/**",
        "C:/tests/**",
        "C:tests/**",
        "C:\\tests\\**",
        "tests/../src/**",
        "tests\\**",
        "!tests/private/**",
        "#tests/private/**",
        "   ",
        "",
    ] {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "suppression", "ruleId": "rule", "pathPattern": pattern,
                "state": "suppressed", "reason": "Fixture policy"
            }]}),
        );
        assert!(
            matches!(loaded.status(), PolicyStatus::Invalid { .. }),
            "{pattern}"
        );
    }
}

#[test]
fn category_state_evidence_matrix_is_strict() {
    let invalid_entries = [
        serde_json::json!({
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "secret", "state": "falsePositive", "reason": "Fixture",
            "evidence": "safe-looking evidence"
        }),
        serde_json::json!({
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "secret", "state": "falsePositive", "reason": "Fixture",
            "gates": [{"gate": "reachable", "verdict": "eliminates", "evidence": "Fixture only"}],
            "decidingGate": "reachable"
        }),
        serde_json::json!({
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "vulnerability", "state": "falsePositive", "reason": "Fixture"
        }),
        serde_json::json!({
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "vulnerability", "state": "falsePositive", "reason": "Fixture",
            "gates": [{"gate": "reachable", "verdict": "survives", "evidence": "Reachable"}],
            "decidingGate": "reachable"
        }),
        serde_json::json!({
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "vulnerability", "state": "acceptedRisk", "reason": "Accepted",
            "gates": [{"gate": "reachable", "verdict": "eliminates", "evidence": "Not allowed"}],
            "decidingGate": "reachable"
        }),
        serde_json::json!({
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "other", "state": "acceptedRisk", "reason": "Unknown category"
        }),
    ];
    for (index, entry) in invalid_entries.into_iter().enumerate() {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version": 1, "entries": [entry]}),
        );
        assert!(
            matches!(loaded.status(), PolicyStatus::Invalid { .. }),
            "case {index}"
        );
    }
}

#[test]
fn path_and_credential_shaped_evidence_is_rejected_safely() {
    for evidence in [
        "/Users/alice/private/source.rs:9",
        "verified path=/etc/passwd",
        "C:\\private\\source.rs:9",
        "checked at src/../private.rs:9",
        "Authorization: Bearer ghp_1234567890abcdefghijklmnop",
        "const value = input();\nexecute(value);",
        CANARY,
    ] {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
                "category": "vulnerability", "state": "falsePositive", "reason": "Excluded",
                "gates": [{"gate": "reachable", "verdict": "eliminates", "evidence": evidence}],
                "decidingGate": "reachable"
            }]}),
        );
        assert!(matches!(loaded.status(), PolicyStatus::Invalid { .. }));
    }
}

#[test]
fn structured_credential_forms_are_rejected_without_echoing_them() {
    let rejected = [
        "password = huntertwo",
        "api key: abcdefghijklmnop",
        "api_key = ABCDEFGHIJKLMNOP",
        "token : Zm9vYmFyYmF6cXV4",
        "Authorization: Basic YWJj",
        "Authorization: Bearer tiny-token",
        "-----BEGIN PRIVATE KEY-----",
        "AWS key AKIAIOSFODNN7EXAMPLE",
        "GitHub token ghp_abcdefghijklmnopqrstuvwxyz012345",
        "OpenAI key sk-abcdefghijklmnopqrstuvwxyz",
    ];
    for (index, value) in rejected.into_iter().enumerate() {
        assert!(
            !safe_required_text(value),
            "accepted credential-shaped fixture {index}"
        );
    }
}

#[test]
fn absolute_unc_uri_drive_and_traversal_path_tokens_are_rejected() {
    for value in [
        "path=//server/share",
        "file:///Users/alice/private.rs",
        "source=C:/private/source.rs",
        "source=C:private/source.rs",
        "checked /etc/passwd",
        "checked src/../../private.rs",
    ] {
        assert!(
            !safe_required_text(value),
            "accepted unsafe path-shaped input"
        );
    }
}

#[test]
fn benign_hash_identifiers_and_relative_paths_remain_portable() {
    for value in [
        "commit 0123456789abcdef0123456789abcdef01234567",
        "identifier ExtremelyLongApplicationSecurityIdentifier2026",
        "reviewed at src/security/policy.rs:42",
        "manifest fixtures/example-project/config.json",
    ] {
        assert!(
            safe_required_text(value),
            "rejected benign portable input: {value}"
        );
    }
}

#[test]
fn standalone_high_entropy_tokens_are_rejected() {
    for value in [
        "n7Qv2Lm9Rx4Za8Wp3Kd6Ty1Bc5Hf0JsU",
        "VGhpcy1pcy1ub3QtYS1yZWFsLXNlY3JldA==",
    ] {
        assert!(!safe_required_text(value));
    }
}

#[test]
fn short_credentials_and_auth_schemes_are_rejected() {
    for value in [
        "pwd=x",
        "password = x",
        "api key: z",
        "Bearer abc",
        "Basic abc",
        "sk-live",
        "ghp_x",
    ] {
        assert!(!safe_required_text(value), "accepted fixture {value:?}");
    }
}

#[test]
fn standalone_high_entropy_hex_is_rejected_but_contextual_hashes_are_allowed() {
    assert!(!safe_required_text(
        "a9f73c6d14e82b05f7c9134da6e28b40c17f5892"
    ));
    for value in [
        "commit a9f73c6d14e82b05f7c9134da6e28b40c17f5892",
        "sha256: a9f73c6d14e82b05f7c9134da6e28b40c17f5892",
    ] {
        assert!(safe_required_text(value), "rejected fixture {value:?}");
    }
}

#[test]
fn wrapped_absolute_and_traversal_paths_are_rejected() {
    for value in [
        "`/Users/alice/private.rs`",
        "source=`../private.rs`",
        "path=\"file:///Users/alice/private.rs\"",
        "location='//server/share'",
        "checked [/etc/passwd]",
        "checked (src/../../private.rs)",
    ] {
        assert!(!safe_required_text(value), "accepted fixture {value:?}");
    }
}

#[test]
fn angle_wrapped_unsafe_paths_are_rejected_without_rejecting_relational_prose() {
    for value in [
        "checked </etc/passwd>",
        "checked <../private.rs>",
        "checked <//server/share>",
        "checked <file:///Users/alice/private.rs>",
        "checked <C:/Users/alice/private.rs>",
        "path=</etc/passwd>",
    ] {
        assert!(!safe_required_text(value), "accepted fixture {value:?}");
    }
    for value in ["threshold < limit", "version >= minimum"] {
        assert!(safe_required_text(value), "rejected fixture {value:?}");
    }
}

#[test]
fn lexical_candidate_boundaries_reject_unsafe_paths_at_public_policy_boundaries() {
    let digest = "a9f73c6d14e82b05f7c9134da6e28b40c17f5892";
    let reasons = [
        "checked!/etc/passwd".to_owned(),
        "checked?/etc/passwd".to_owned(),
        format!("commit=<{digest}>=/etc/passwd"),
        "checked!!/etc/passwd".to_owned(),
        "checked::/etc/passwd".to_owned(),
        "checked@@/etc/passwd".to_owned(),
        "checked||/etc/passwd".to_owned(),
        "checked=:/etc/passwd".to_owned(),
        "checked><!/etc/passwd".to_owned(),
        "safe=src/security/policy.rs|/etc/passwd".to_owned(),
        "checked!file:///Users/alice/private.rs".to_owned(),
        "checked?//server/share".to_owned(),
        "checked|C:/Users/alice/private.rs".to_owned(),
        "checked@../private.rs".to_owned(),
        "See(https://docs.example.com/../private)".to_owned(),
        "See(https://user@docs.example.com/security)".to_owned(),
        "See(https://docs.example.com/security?token=value)".to_owned(),
        "See(https://docs.example.com/security#fragment)".to_owned(),
        "See(https://docs.example.com/security)|/etc/passwd".to_owned(),
        "token=abc".to_owned(),
        "checked(/etc/passwd)".to_owned(),
        "path[/etc/passwd]".to_owned(),
        "note{/etc/passwd}".to_owned(),
        "checked</etc/passwd>".to_owned(),
        "checked'/etc/passwd'".to_owned(),
        "checked\"/etc/passwd\"".to_owned(),
        "checked`/etc/passwd`".to_owned(),
        "checked(file:///Users/alice/private.rs)".to_owned(),
        "checked[//server/share]".to_owned(),
        "checked{C:/Users/alice/private.rs}".to_owned(),
        "checked(src/../../private.rs)".to_owned(),
        format!("commit=<{digest}></etc/passwd>"),
        format!("commit=<{digest}>(../private.rs)"),
    ];

    for reason in reasons {
        let load_root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            load_root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "finding",
                "fingerprintVersion": 1,
                "fingerprint": "abcdef0123456789",
                "category": "secret",
                "state": "acceptedRisk",
                "reason": reason.clone(),
            }]}),
        );
        assert_eq!(
            loaded.status(),
            &PolicyStatus::Invalid {
                message: INVALID_POLICY_MESSAGE.to_owned()
            },
            "load accepted unsafe reason {reason:?}"
        );

        let update_root = tempfile::tempdir().unwrap();
        let mut unsafe_request = request(ReviewState::AcceptedRisk, "secret");
        unsafe_request.reason = reason.clone();
        let error = update_policy_decision(
            update_root.path(),
            &finding("secret"),
            &unsafe_request,
            now(),
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::ReviewInvalid,
            "update accepted unsafe reason {reason:?}"
        );
        assert_eq!(error.message, "The review request is invalid.");
        assert_eq!(error.detail, None);
    }
}

#[test]
fn lexical_candidate_scan_preserves_safe_public_policy_reasons() {
    let digest = "a9f73c6d14e82b05f7c9134da6e28b40c17f5892";
    for reason in [
        "See(https://docs.example.com/security)".to_owned(),
        "See[https://docs.example.com/security]".to_owned(),
        "See<https://docs.example.com/security>".to_owned(),
        "See{https://docs.example.com/security}".to_owned(),
        "See'https://docs.example.com/security'".to_owned(),
        "See\"https://docs.example.com/security\"".to_owned(),
        "See`https://docs.example.com/security`".to_owned(),
        "See!?https://docs.example.com/security".to_owned(),
        "See(https://docs.example.com:8443/security)".to_owned(),
        format!("commit={digest}"),
        format!("commit=<{digest}>"),
        "See https://docs.example.com/security/production-feature-manifest".to_owned(),
        format!("sha256: {digest}"),
        "threshold < limit and version >= minimum".to_owned(),
        "comparison(a<b) and condition(x>y)".to_owned(),
        "production-feature-manifest".to_owned(),
        "checked(src/security/policy.rs)".to_owned(),
        "path[src/security/policy.rs]".to_owned(),
        "checked<refs/heads/main>".to_owned(),
        "ratio(1/2)".to_owned(),
    ] {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "finding",
                "fingerprintVersion": 1,
                "fingerprint": "abcdef0123456789",
                "category": "secret",
                "state": "acceptedRisk",
                "reason": reason.clone(),
            }]}),
        );
        assert!(
            matches!(loaded.status(), PolicyStatus::Valid { .. }),
            "load rejected safe reason {reason:?}"
        );

        let update_root = tempfile::tempdir().unwrap();
        let mut safe_request = request(ReviewState::AcceptedRisk, "secret");
        safe_request.reason = reason.clone();
        let review =
            update_policy_decision(update_root.path(), &finding("secret"), &safe_request, now())
                .unwrap_or_else(|error| {
                    panic!("update rejected safe reason {reason:?}: {error:?}")
                });
        assert_eq!(review.state, ReviewState::AcceptedRisk);
        assert_eq!(review.reason, reason);
        assert!(matches!(
            load_policy(update_root.path()).unwrap().status(),
            PolicyStatus::Valid { .. }
        ));
    }
}

#[test]
fn public_policy_validation_is_linear_for_punctuation_heavy_near_cap_text() {
    let empty = serde_json::to_vec(&serde_json::json!({"version": 1, "entries": [{
        "kind": "finding",
        "fingerprintVersion": 1,
        "fingerprint": "abcdef0123456789",
        "category": "secret",
        "state": "acceptedRisk",
        "reason": "",
    }]}))
    .unwrap();
    let reason_len = MAX_POLICY_BYTES as usize - empty.len() - 1;
    let reason = "a!".repeat(reason_len / 2)
        + if reason_len.is_multiple_of(2) {
            ""
        } else {
            "a"
        };
    let work = portable_text_validation_work(&reason);
    assert!(
        work <= reason.len().saturating_mul(8).saturating_add(64),
        "validation performed {work} operations for {} bytes",
        reason.len()
    );

    let load_root = tempfile::tempdir().unwrap();
    let policy = serde_json::to_vec(&serde_json::json!({"version": 1, "entries": [{
        "kind": "finding",
        "fingerprintVersion": 1,
        "fingerprint": "abcdef0123456789",
        "category": "secret",
        "state": "acceptedRisk",
        "reason": reason,
    }]}))
    .unwrap();
    assert!(policy.len() <= MAX_POLICY_BYTES as usize);
    write_policy(load_root.path(), &policy);
    assert!(matches!(
        load_policy(load_root.path()).unwrap().status(),
        PolicyStatus::Valid { .. }
    ));

    let update_root = tempfile::tempdir().unwrap();
    let mut update = request(ReviewState::AcceptedRisk, "secret");
    update.reason = "a!".repeat((MAX_POLICY_BYTES as usize - 512) / 2);
    let saved = update_policy_decision(update_root.path(), &finding("secret"), &update, now())
        .expect("near-cap punctuation-heavy update remains responsive and valid");
    assert_eq!(saved.state, ReviewState::AcceptedRisk);
}

#[test]
fn malformed_or_encoded_urls_are_rejected_at_public_policy_boundaries() {
    let unsafe_urls = [
        "See(https://:/etc/passwd)",
        "See(https://docs.example.com/%2e%2e/etc/passwd)",
        "See(https://docs.example.com/%2E%2e/etc/passwd)",
        "See(https://docs.example.com/security%2fprivate)",
        "See(https://docs.example.com/security%2Fprivate)",
        "See(https://docs.example.com/security%5cprivate)",
        "See(https://docs.example.com/security%5Cprivate)",
        "See(https://docs.example.com/security%)",
        "See(https://docs.example.com/security%2)",
        "See(https://docs.example.com:abc/security)",
        "See(https://docs.example.com:/security)",
        "See(https://./security)",
        "See(https://docs..example.com/security)",
        "See(https://-docs.example.com/security)",
        "See(https://docs-.example.com/security)",
        "See(https://user@docs.example.com/security)",
        "See(https://docs.example.com/security?mode=review)",
        "See(https://docs.example.com/security#review)",
    ];

    for reason in unsafe_urls {
        let load_root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            load_root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "finding",
                "fingerprintVersion": 1,
                "fingerprint": "abcdef0123456789",
                "category": "secret",
                "state": "acceptedRisk",
                "reason": reason,
            }]}),
        );
        assert!(
            matches!(loaded.status(), PolicyStatus::Invalid { .. }),
            "load accepted unsafe URL {reason:?}"
        );

        let update_root = tempfile::tempdir().unwrap();
        let mut update = request(ReviewState::AcceptedRisk, "secret");
        update.reason = reason.into();
        let error = update_policy_decision(update_root.path(), &finding("secret"), &update, now())
            .expect_err("unsafe URL must not be persisted");
        assert_eq!(error.code, crate::findings::error::ErrorCode::ReviewInvalid);
        assert_eq!(error.message, "The review request is invalid.");
        assert_eq!(error.detail, None);
    }
}

#[test]
fn exact_valid_url_spans_preserve_safe_portable_text() {
    let digest = "a9f73c6d14e82b05f7c9134da6e28b40c17f5892";
    for reason in [
        "See(https://docs.example.com/security%20review)".to_owned(),
        "See(https://docs.example.com:8443/security)".to_owned(),
        "See!https://docs.example.com/security then src/security/policy.rs".to_owned(),
        "See(https://docs.example.com/security) and production-feature-manifest".to_owned(),
        "See(https://docs.example.com/security) threshold < limit".to_owned(),
        format!("See(https://docs.example.com/security) commit={digest}"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version": 1, "entries": [{
                "kind": "finding",
                "fingerprintVersion": 1,
                "fingerprint": "abcdef0123456789",
                "category": "secret",
                "state": "acceptedRisk",
                "reason": reason,
            }]}),
        );
        assert!(
            matches!(loaded.status(), PolicyStatus::Valid { .. }),
            "load rejected safe URL text {reason:?}"
        );
    }
}

#[test]
fn contextual_hash_assignments_are_allowed_before_generic_entropy_checks() {
    let digest = "a9f73c6d14e82b05f7c9134da6e28b40c17f5892";
    for label in ["commit", "sha256", "hash", "digest", "fingerprint"] {
        for value in [format!("{label}={digest}"), format!("{label}=<{digest}>")] {
            assert!(safe_required_text(&value), "rejected fixture {value:?}");
        }
    }
    assert!(!safe_required_text(digest));
}

#[test]
fn windows_temp_handle_is_explicitly_closed_before_path_publication() {
    let source = include_str!("policy.rs");
    // Source checkout line endings are not part of the handle-lifetime contract.
    // Exercise both spellings on every platform, including LF-only CI runners.
    let lf_source = source.replace("\r\n", "\n");
    for source in [lf_source.clone(), lf_source.replace("\n", "\r\n")] {
        let source = source.replace("\r\n", "\n");
        let windows_write = source
            .split("#[cfg(windows)]\nfn atomic_write_policy(")
            .nth(1)
            .expect("Windows policy writer remains present");
        let validation = windows_write
            .find("parse_and_validate(&persisted")
            .expect("the temp bytes are validated before publication");
        let close = windows_write
            .find("drop(temp);")
            .expect("the Windows temp handle has an explicit lifetime boundary");
        let publication = windows_write
            .find("windows_fs::durable_replace(")
            .expect("the Windows writer publishes through the durable helper");

        assert!(validation < close);
        assert!(close < publication);
    }
}

#[test]
fn safe_urls_and_conventional_kebab_identifiers_are_allowed() {
    for value in [
        "See https://docs.example.com/security/production-feature-manifest",
        "production-feature-manifest",
    ] {
        assert!(safe_required_text(value), "rejected fixture {value:?}");
    }
}

#[test]
fn expired_entries_are_retained_but_do_not_apply() {
    let root = tempfile::tempdir().unwrap();
    let loaded = load_json(
        root.path(),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "secret", "state": "acceptedRisk", "reason": "Temporary",
            "expiresAt": "2026-01-01T00:00:00Z"
        }, {
            "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
            "state": "suppressed", "reason": "Temporary fixtures",
            "expiresAt": "2026-01-01T00:00:00Z"
        }]}),
    );
    assert_eq!(loaded.policy().unwrap().entries.len(), 2);
    let review = apply(&loaded, "abc123", "secret", "rule", "tests/a.rs", None).unwrap();
    assert_eq!(review.state, ReviewState::Candidate);
}

#[test]
fn precedence_is_local_then_exact_then_last_suppression_then_candidate() {
    let root = tempfile::tempdir().unwrap();
    let loaded = load_json(
        root.path(),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
            "state": "suppressed", "reason": "First suppression"
        }, {
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "secret", "state": "acceptedRisk", "reason": "Exact decision"
        }, {
            "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/unit/**",
            "state": "suppressed", "reason": "Last suppression"
        }]}),
    );

    let local = local_review();
    assert_eq!(
        apply(
            &loaded,
            "abc123",
            "secret",
            "rule",
            "tests/unit/a.rs",
            Some(&local)
        )
        .unwrap()
        .reason,
        "Local decision"
    );
    let exact = apply(&loaded, "abc123", "secret", "rule", "tests/unit/a.rs", None).unwrap();
    assert_eq!(exact.reason, "Exact decision");
    assert_eq!(exact.origin, ReviewOrigin::ProjectPolicy);
    assert_eq!(exact.policy_hash.as_deref(), status_hash(&loaded));
    let suppression = apply(&loaded, "def456", "secret", "rule", "tests/unit/a.rs", None).unwrap();
    assert_eq!(suppression.reason, "Last suppression");
    let candidate = apply(&loaded, "def456", "secret", "other", "src/a.rs", None).unwrap();
    assert_eq!(candidate.state, ReviewState::Candidate);
}

#[test]
fn derived_review_ids_include_project_and_authoritative_policy_hash() {
    let first_root = tempfile::tempdir().unwrap();
    write_policy(first_root.path(), VALID_POLICY.as_bytes());
    let first = load_policy(first_root.path()).unwrap();
    let project_one = apply_policy(
        &first,
        "project-1",
        1,
        "abc123",
        "vulnerability",
        "rule",
        "src/a.rs",
        None,
        now(),
    )
    .unwrap();
    let project_two = apply_policy(
        &first,
        "project-2",
        1,
        "abc123",
        "vulnerability",
        "rule",
        "src/a.rs",
        None,
        now(),
    )
    .unwrap();
    assert_ne!(project_one.id, project_two.id);

    let second_root = tempfile::tempdir().unwrap();
    let changed = VALID_POLICY.replace(
        "The affected branch is excluded from production",
        "The deployment manifest excludes this branch",
    );
    write_policy(second_root.path(), changed.as_bytes());
    let second = load_policy(second_root.path()).unwrap();
    let changed_review = apply_policy(
        &second,
        "project-1",
        1,
        "abc123",
        "vulnerability",
        "rule",
        "src/a.rs",
        None,
        now(),
    )
    .unwrap();
    assert_ne!(project_one.id, changed_review.id);
    assert_eq!(
        project_one.id,
        apply_policy(
            &first,
            "project-1",
            1,
            "abc123",
            "vulnerability",
            "rule",
            "src/a.rs",
            None,
            now(),
        )
        .unwrap()
        .id
    );
}

#[test]
fn candidate_review_ids_do_not_collide_across_projects() {
    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let loaded = load_policy(root.path()).unwrap();
    let one = apply_policy(
        &loaded,
        "project-1",
        1,
        "abc123",
        "secret",
        "rule",
        "src/a.rs",
        None,
        now(),
    )
    .unwrap();
    let two = apply_policy(
        &loaded,
        "project-2",
        1,
        "abc123",
        "secret",
        "rule",
        "src/a.rs",
        None,
        now(),
    )
    .unwrap();
    assert_ne!(one.id, two.id);
}

#[test]
fn exact_fingerprint_category_mismatch_is_invalid_and_never_falls_through() {
    let root = tempfile::tempdir().unwrap();
    let loaded = load_json(
        root.path(),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "vulnerability", "state": "acceptedRisk", "reason": "Exact"
        }, {
            "kind": "suppression", "ruleId": "rule", "pathPattern": "tests/**",
            "state": "suppressed", "reason": "Weaker suppression"
        }]}),
    );
    let error = apply(&loaded, "abc123", "secret", "rule", "tests/a.rs", None).unwrap_err();
    assert_eq!(error.code, crate::findings::error::ErrorCode::PolicyInvalid);
    assert_eq!(error.message, "The project policy is invalid.");
    assert!(error.detail.is_none());
}

#[test]
fn unsafe_observation_paths_are_rejected_instead_of_normalized() {
    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let loaded = load_policy(root.path()).unwrap();
    for path in [
        "/src/a.rs",
        "C:/src/a.rs",
        "C:src/a.rs",
        "src/../a.rs",
        "src\\a.rs",
    ] {
        assert!(apply(&loaded, "abc123", "secret", "rule", path, None).is_err());
    }
}

#[test]
fn update_is_allowlisted_and_never_serializes_finding_canaries() {
    let root = tempfile::tempdir().unwrap();
    let finding = finding("secret");
    let request = request(ReviewState::FalsePositive, "secret");

    let review = update_policy_decision(root.path(), &finding, &request, now()).unwrap();
    let bytes = fs::read(root.path().join(".oxaudit/policy.json")).unwrap();
    let serialized = String::from_utf8(bytes.clone()).unwrap();

    assert!(!serialized.contains(CANARY));
    for forbidden in [
        "matchText",
        "context",
        "title",
        "description",
        "recommendation",
        "entropy",
        "observationRunId",
        "scopeReason",
    ] {
        assert!(!serialized.contains(forbidden), "serialized {forbidden}");
    }
    assert!(serialized.ends_with('\n'));
    assert!(serialized.contains("\n  \"entries\": ["));
    let expected_hash = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(review.policy_hash.as_deref(), Some(expected_hash.as_str()));
    assert_eq!(
        status_hash(&load_policy(root.path()).unwrap()),
        Some(expected_hash.as_str())
    );
}

#[test]
fn update_rejects_identity_mismatch_credentials_and_nonfuture_expiry() {
    let root = tempfile::tempdir().unwrap();
    let finding = finding("secret");

    let mut mismatch = request(ReviewState::FalsePositive, "secret");
    mismatch.fingerprint = "deadbeef".into();
    assert!(update_policy_decision(root.path(), &finding, &mismatch, now()).is_err());

    let mut credential = request(ReviewState::FalsePositive, "secret");
    credential.reason = format!("Copied token {CANARY}");
    assert!(update_policy_decision(root.path(), &finding, &credential, now()).is_err());

    let mut expired = request(ReviewState::FalsePositive, "secret");
    expired.expires_at = Some("2026-08-21T11:59:59Z".into());
    assert!(update_policy_decision(root.path(), &finding, &expired, now()).is_err());
    assert!(!root.path().join(".oxaudit/policy.json").exists());
}

#[test]
fn vulnerability_false_positive_round_trips_one_eliminating_gate() {
    let root = tempfile::tempdir().unwrap();
    let finding = finding("vulnerability");
    let mut request = request(ReviewState::FalsePositive, "vulnerability");
    request.gates = vec![GateNote {
        gate: Gate::Reachable,
        verdict: GateVerdict::Eliminates,
        evidence: "The production manifest excludes src/dev.rs:8".into(),
    }];
    request.deciding_gate = Some(Gate::Reachable);

    let review = update_policy_decision(root.path(), &finding, &request, now()).unwrap();
    assert_eq!(review.gates, request.gates);
    assert_eq!(review.deciding_gate, Some(Gate::Reachable));

    let loaded = load_policy(root.path()).unwrap();
    let applied = apply(
        &loaded,
        &finding.fingerprint,
        "vulnerability",
        &finding.rule_id,
        &finding.file_path,
        None,
    )
    .unwrap();
    assert_eq!(applied.gates, request.gates);
    assert_eq!(applied.deciding_gate, Some(Gate::Reachable));
}

#[test]
fn vulnerability_false_positive_preserves_unique_multi_gate_investigation() {
    let root = tempfile::tempdir().unwrap();
    let gates = vec![
        GateNote {
            gate: Gate::Intended,
            verdict: GateVerdict::Survives,
            evidence: "The behavior is not intended".into(),
        },
        GateNote {
            gate: Gate::Reachable,
            verdict: GateVerdict::Eliminates,
            evidence: "The production manifest excludes src/dev.rs:8".into(),
        },
        GateNote {
            gate: Gate::AttackerControlled,
            verdict: GateVerdict::Survives,
            evidence: "The input cannot be controlled externally".into(),
        },
    ];
    let loaded = load_json(
        root.path(),
        serde_json::json!({"version": 1, "entries": [{
            "kind": "finding", "fingerprintVersion": 1, "fingerprint": "abc123",
            "category": "vulnerability", "state": "falsePositive", "reason": "Unreachable",
            "gates": gates, "decidingGate": "reachable"
        }]}),
    );
    assert!(matches!(loaded.status(), PolicyStatus::Valid { .. }));
    let review = apply(&loaded, "abc123", "vulnerability", "rule", "src/a.rs", None).unwrap();
    assert_eq!(review.gates, gates);
}

#[test]
fn vulnerability_false_positive_rejects_duplicate_or_multiple_eliminating_gates() {
    let invalid_gate_sets = [
        serde_json::json!([
            {"gate":"reachable","verdict":"survives","evidence":"Checked"},
            {"gate":"reachable","verdict":"eliminates","evidence":"Excluded"}
        ]),
        serde_json::json!([
            {"gate":"intended","verdict":"eliminates","evidence":"Designed"},
            {"gate":"reachable","verdict":"eliminates","evidence":"Excluded"}
        ]),
        serde_json::json!([
            {"gate":"intended","verdict":"survives","evidence":"   "},
            {"gate":"reachable","verdict":"eliminates","evidence":"Excluded"}
        ]),
        serde_json::json!([
            {"gate":"intended","verdict":"unknown","evidence":"Not evaluated"},
            {"gate":"reachable","verdict":"eliminates","evidence":"Excluded"}
        ]),
    ];
    for gates in invalid_gate_sets {
        let root = tempfile::tempdir().unwrap();
        let loaded = load_json(
            root.path(),
            serde_json::json!({"version":1,"entries":[{
                "kind":"finding","fingerprintVersion":1,"fingerprint":"abc123",
                "category":"vulnerability","state":"falsePositive","reason":"Excluded",
                "gates":gates,"decidingGate":"reachable"
            }]}),
        );
        assert!(matches!(loaded.status(), PolicyStatus::Invalid { .. }));
    }
}

#[test]
fn vulnerability_false_positive_retains_only_sanitized_review_evidence_fields() {
    let root = tempfile::tempdir().unwrap();
    let finding = finding("vulnerability");
    let mut request = request(ReviewState::FalsePositive, "vulnerability");
    request.evidence = Some("The production manifest excludes the development route".into());
    request.entry_point = Some("src/router.rs:18".into());
    request.data_flow = Some("router -> development handler".into());
    request.gates = vec![GateNote {
        gate: Gate::Reachable,
        verdict: GateVerdict::Eliminates,
        evidence: "The production manifest excludes src/dev.rs:8".into(),
    }];
    request.deciding_gate = Some(Gate::Reachable);

    let review = update_policy_decision(root.path(), &finding, &request, now()).unwrap();

    assert_eq!(review.evidence, request.evidence);
    assert_eq!(review.entry_point, request.entry_point);
    assert_eq!(review.data_flow, request.data_flow);
}

#[test]
fn invalid_existing_policy_is_never_overwritten() {
    let root = tempfile::tempdir().unwrap();
    let original = br#"{"version":999,"private":"do not replace"}"#;
    write_policy(root.path(), original);
    let error = update_policy_decision(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
    )
    .unwrap_err();
    assert_eq!(error.code, crate::findings::error::ErrorCode::PolicyInvalid);
    assert_eq!(
        fs::read(root.path().join(".oxaudit/policy.json")).unwrap(),
        original
    );
}

#[test]
fn injected_failure_preserves_prior_bytes_and_cleans_only_its_temp() {
    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let policy_path = root.path().join(".oxaudit/policy.json");
    let original = fs::read(&policy_path).unwrap();
    let stale = root.path().join(".oxaudit/.policy.json.stale.tmp");
    fs::write(&stale, b"unrelated").unwrap();

    let error = update_policy_decision_with_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::AfterTempSync,
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(&policy_path).unwrap(), original);
    assert_eq!(fs::read(&stale).unwrap(), b"unrelated");
    let owned_temps = fs::read_dir(root.path().join(".oxaudit"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with(".policy.json.") && name != ".policy.json.stale.tmp"
        })
        .count();
    assert_eq!(owned_temps, 0);
}

#[cfg(unix)]
#[test]
fn writes_reject_symlink_and_non_directory_escape_surfaces() {
    use std::os::unix::fs::symlink;

    let outer = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    symlink(target.path(), outer.path().join(".oxaudit")).unwrap();
    assert!(update_policy_decision(
        outer.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
    )
    .is_err());
    assert!(!target.path().join("policy.json").exists());

    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join(".oxaudit")).unwrap();
    let outside = root.path().join("outside.json");
    fs::write(&outside, b"outside").unwrap();
    symlink(&outside, root.path().join(".oxaudit/policy.json")).unwrap();
    assert!(update_policy_decision(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
    )
    .is_err());
    assert_eq!(fs::read(outside).unwrap(), b"outside");

    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join(".oxaudit"), b"not a directory").unwrap();
    assert!(update_policy_decision(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn policy_open_does_not_block_when_a_checked_target_becomes_a_fifo() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), VALID_POLICY.as_bytes());
    let policy_path = root.path().join(".oxaudit/policy.json");

    let loaded = load_policy_with_test_hook(root.path(), |stage| {
        if stage == IoStage::BeforePolicyOpen {
            fs::remove_file(&policy_path).unwrap();
            let path = CString::new(policy_path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        }
    })
    .unwrap();

    assert!(matches!(loaded.status(), PolicyStatus::Invalid { .. }));
}

#[cfg(unix)]
#[test]
fn policy_read_is_bounded_from_the_open_handle_when_the_file_grows() {
    use std::io::Write as _;

    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), VALID_POLICY.as_bytes());
    let policy_path = root.path().join(".oxaudit/policy.json");

    let loaded = load_policy_with_test_hook(root.path(), |stage| {
        if stage == IoStage::AfterPolicyOpen {
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(&policy_path)
                .unwrap();
            file.write_all(&vec![b'x'; MAX_POLICY_BYTES as usize + 1])
                .unwrap();
        }
    })
    .unwrap();

    assert!(matches!(loaded.status(), PolicyStatus::Invalid { .. }));
}

#[cfg(unix)]
#[test]
fn policy_read_stays_on_the_open_inode_when_the_name_is_swapped() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), VALID_POLICY.as_bytes());
    let policy_path = root.path().join(".oxaudit/policy.json");
    let held_path = root.path().join(".oxaudit/original-policy");
    let outside = root.path().join("outside-policy");
    fs::write(&outside, br#"{"version":999,"secret":"outside"}"#).unwrap();
    let expected_hash = format!("{:x}", Sha256::digest(VALID_POLICY.as_bytes()));

    let loaded = load_policy_with_test_hook(root.path(), |stage| {
        if stage == IoStage::AfterPolicyOpen {
            fs::rename(&policy_path, &held_path).unwrap();
            symlink(&outside, &policy_path).unwrap();
        }
    })
    .unwrap();

    assert_eq!(status_hash(&loaded), Some(expected_hash.as_str()));
}

#[cfg(unix)]
#[test]
fn concurrent_valid_or_invalid_policy_update_wins_without_being_overwritten() {
    for external in [
        br#"{ "version": 1, "entries": [] }
"#
        .as_slice(),
        br#"{"version":999,"external":"invalid-but-authoritative"}"#.as_slice(),
    ] {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == IoStage::BeforeReplace {
                    fs::write(&policy_path, external).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(&policy_path).unwrap(), external);
    }
}

#[cfg(unix)]
#[test]
fn recovery_tamper_with_exact_candidate_restored_reports_committed_success() {
    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let external = br#"{ "version": 1, "entries": [] }
"#;
    let mut modified_recovery = None;
    let mut candidate_bytes = None;

    let result = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::AfterReplaceBeforeDirectorySync,
        |stage| {
            if stage == IoStage::AfterReplace {
                candidate_bytes = Some(fs::read(root.path().join(".oxaudit/policy.json")).unwrap());
                let recovery = fs::read_dir(root.path().join(".oxaudit"))
                    .unwrap()
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".policy.json.")
                            && path.extension().is_some_and(|extension| extension == "tmp")
                    })
                    .unwrap();
                fs::write(&recovery, external).unwrap();
                modified_recovery = Some(recovery);
            }
        },
    );

    assert_eq!(
        fs::read(root.path().join(".oxaudit/policy.json")).unwrap(),
        candidate_bytes.unwrap()
    );
    assert_eq!(fs::read(modified_recovery.unwrap()).unwrap(), external);
    let review = result.unwrap_or_else(|error| {
        panic!("verified committed candidate was reported as failure: {error:?}")
    });
    assert_eq!(review.state, ReviewState::FalsePositive);
    assert!(matches!(
        load_policy(root.path()).unwrap().status(),
        PolicyStatus::Valid { .. }
    ));
}

#[cfg(unix)]
#[test]
fn concurrently_created_policy_wins_when_the_initial_policy_was_missing() {
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join(".oxaudit/policy.json");
    let external = br#"{"version":999,"external":"created"}"#;

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| {
            if stage == IoStage::BeforeReplace {
                fs::write(&policy_path, external).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(policy_path).unwrap(), external);
}

#[cfg(unix)]
#[test]
fn project_root_swap_after_read_aborts_before_mutating_the_pinned_project() {
    let parent = tempfile::tempdir().unwrap();
    let project = parent.path().join("project");
    let held = parent.path().join("project-held");
    fs::create_dir(&project).unwrap();
    write_policy(&project, br#"{"version":1,"entries":[]}"#);
    let original = fs::read(project.join(".oxaudit/policy.json")).unwrap();

    let error = update_policy_decision_with_test_hook(
        &project,
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| {
            if stage == IoStage::BeforeTempCreate {
                fs::rename(&project, &held).unwrap();
                fs::create_dir(&project).unwrap();
                fs::create_dir(project.join(".oxaudit")).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(
        fs::read(held.join(".oxaudit/policy.json")).unwrap(),
        original
    );
    assert!(!project.join(".oxaudit/policy.json").exists());
}

#[cfg(unix)]
#[test]
fn in_place_edit_after_preflight_wins_the_atomic_compare_exchange() {
    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let policy_path = root.path().join(".oxaudit/policy.json");
    let external = br#"{ "version": 1, "entries": [] }
"#;

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| {
            if stage == IoStage::AfterPolicyPreflight {
                fs::write(&policy_path, external).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(policy_path).unwrap(), external);
}

#[cfg(unix)]
#[test]
fn replacement_after_preflight_wins_the_atomic_compare_exchange() {
    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let policy_path = root.path().join(".oxaudit/policy.json");
    let displaced = root.path().join(".oxaudit/displaced-policy");
    let external = br#"{ "version": 1, "entries": [] }
"#;

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| {
            if stage == IoStage::AfterPolicyPreflight {
                fs::rename(&policy_path, &displaced).unwrap();
                fs::write(&policy_path, external).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(policy_path).unwrap(), external);
}

#[cfg(unix)]
#[test]
fn late_edit_during_cas_mismatch_reversal_is_never_overwritten() {
    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let policy_path = root.path().join(".oxaudit/policy.json");
    let first_external = br#"{ "version": 1, "entries": [] }
"#;
    let latest_external = br#"{"version":999,"latest":"external"}"#;

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| match stage {
            IoStage::AfterPolicyPreflight => {
                fs::write(&policy_path, first_external).unwrap();
            }
            IoStage::BeforeRollbackExchange => {
                fs::write(&policy_path, latest_external).unwrap();
            }
            _ => {}
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(policy_path).unwrap(), latest_external);
}

#[cfg(unix)]
#[test]
fn oversized_replacement_after_preflight_is_exchanged_back_unchanged() {
    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let policy_path = root.path().join(".oxaudit/policy.json");
    let oversized = vec![b'x'; MAX_POLICY_BYTES as usize + 1];

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| {
            if stage == IoStage::AfterPolicyPreflight {
                fs::write(&policy_path, &oversized).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(policy_path).unwrap(), oversized);
}

#[cfg(unix)]
#[test]
fn nonregular_replacement_after_preflight_is_exchanged_back_unchanged() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let policy_path = root.path().join(".oxaudit/policy.json");
    let displaced = root.path().join(".oxaudit/displaced-policy");
    let outside = root.path().join("outside.json");
    fs::write(&outside, b"outside").unwrap();

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| {
            if stage == IoStage::AfterPolicyPreflight {
                fs::rename(&policy_path, &displaced).unwrap();
                symlink(&outside, &policy_path).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert!(fs::symlink_metadata(&policy_path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(policy_path).unwrap(), b"outside");
}

#[cfg(unix)]
#[test]
fn creation_after_missing_preflight_wins_no_clobber_publication() {
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join(".oxaudit/policy.json");
    let external = br#"{ "version": 1, "entries": [] }
"#;

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| {
            if stage == IoStage::AfterPolicyPreflight {
                fs::write(&policy_path, external).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(policy_path).unwrap(), external);
}

#[cfg(unix)]
#[test]
fn rollback_never_overwrites_in_place_or_replaced_external_final_bytes() {
    for replace_inode in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let original = br#"{"version":1,"entries":[]}"#;
        write_policy(root.path(), original);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let displaced = root.path().join(".oxaudit/attempt-displaced");
        let external = br#"{ "version": 1, "entries": [] }
"#;

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::AfterReplaceBeforeDirectorySync,
            |stage| {
                if stage == IoStage::AfterReplace {
                    if replace_inode {
                        fs::rename(&policy_path, &displaced).unwrap();
                    }
                    fs::write(&policy_path, external).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(&policy_path).unwrap(), external);
        let recovery = fs::read_dir(root.path().join(".oxaudit"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".policy.json.")
                    && entry.path().extension().is_some_and(|value| value == "tmp")
            })
            .unwrap();
        assert_eq!(fs::read(recovery.path()).unwrap(), original);
    }
}

#[cfg(unix)]
#[test]
fn late_in_place_edit_immediately_before_rollback_exchange_wins() {
    let root = tempfile::tempdir().unwrap();
    let original = br#"{"version":1,"entries":[]}"#;
    write_policy(root.path(), original);
    let policy_path = root.path().join(".oxaudit/policy.json");
    let external = br#"{ "version": 1, "entries": [] }
"#;

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::AfterReplaceBeforeDirectorySync,
        |stage| {
            if stage == IoStage::BeforeRollbackExchange {
                fs::write(&policy_path, external).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(policy_path).unwrap(), external);
    let recovery = fs::read_dir(root.path().join(".oxaudit"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".policy.json.")
                && entry.path().extension().is_some_and(|value| value == "tmp")
        })
        .unwrap();
    assert_eq!(fs::read(recovery.path()).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn late_edit_after_undo_recheck_is_compensated_back_to_policy() {
    for replace_inode in [false, true] {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let policy_path = root.path().join(".oxaudit/policy.json");
        let held_late_policy = root.path().join(".oxaudit/late-policy-held");
        let recovery_tamper = br#"{ "version": 1, "entries": [] }
"#;
        let latest = br#"{"version":999,"latest":"authoritative"}"#;
        let mut candidate = None;
        let mut recovery_path = None;

        let result = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::AfterReplaceBeforeDirectorySync,
            |stage| match stage {
                IoStage::AfterReplace => {
                    candidate = Some(fs::read(&policy_path).unwrap());
                    let recovery = fs::read_dir(root.path().join(".oxaudit"))
                        .unwrap()
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .find(|path| {
                            path.file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with(".policy.json.")
                                && path.extension().is_some_and(|value| value == "tmp")
                        })
                        .unwrap();
                    fs::write(&recovery, recovery_tamper).unwrap();
                    recovery_path = Some(recovery);
                }
                IoStage::AfterRollbackRecheckBeforeUndo => {
                    if replace_inode {
                        fs::rename(&policy_path, &held_late_policy).unwrap();
                    }
                    fs::write(&policy_path, latest).unwrap();
                }
                _ => {}
            },
        );

        let error = result.unwrap_err();
        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(&policy_path).unwrap(), latest);
        assert_eq!(
            fs::read(recovery_path.unwrap()).unwrap(),
            candidate.unwrap()
        );
        if replace_inode {
            assert_eq!(fs::read(&held_late_policy).unwrap(), recovery_tamper);
        }
        assert!(matches!(
            load_policy(root.path()).unwrap().status(),
            PolicyStatus::Invalid { .. }
        ));
    }
}

#[cfg(unix)]
#[test]
fn late_edit_before_missing_policy_rollback_is_not_unlinked() {
    for replace_inode in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let policy_path = root.path().join(".oxaudit/policy.json");
        let displaced = root.path().join(".oxaudit/late-attempt");
        let external = br#"{"version":999,"latest":"external"}"#;

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::AfterReplaceBeforeDirectorySync,
            |stage| {
                if stage == IoStage::BeforeRollbackExchange {
                    if replace_inode {
                        fs::rename(&policy_path, &displaced).unwrap();
                    }
                    fs::write(&policy_path, external).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert_eq!(fs::read(policy_path).unwrap(), external);
    }
}

#[cfg(unix)]
#[test]
fn swapped_policy_directory_and_temp_name_cannot_redirect_a_write() {
    use std::os::unix::fs::symlink;

    for swap_stage in [IoStage::BeforeTempCreate, IoStage::AfterTempSync] {
        let root = tempfile::tempdir().unwrap();
        write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
        let original = fs::read(root.path().join(".oxaudit/policy.json")).unwrap();
        let held = root.path().join(".oxaudit-held");
        let attacker = root.path().join("attacker");
        fs::create_dir(&attacker).unwrap();

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::Never,
            |stage| {
                if stage == swap_stage {
                    fs::rename(root.path().join(".oxaudit"), &held).unwrap();
                    symlink(&attacker, root.path().join(".oxaudit")).unwrap();
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );
        assert!(!attacker.join("policy.json").exists());
        assert_eq!(fs::read(held.join("policy.json")).unwrap(), original);
    }
}

#[cfg(unix)]
#[test]
fn swapped_attempt_owned_temp_name_cannot_redirect_or_remove_another_file() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let policy_path = root.path().join(".oxaudit/policy.json");
    let original = fs::read(&policy_path).unwrap();
    let outside = root.path().join("outside.json");
    fs::write(&outside, b"outside").unwrap();

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| {
            if stage == IoStage::AfterTempSync {
                let temp_path = fs::read_dir(root.path().join(".oxaudit"))
                    .unwrap()
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".policy.json.")
                            && path.extension().is_some_and(|value| value == "tmp")
                    })
                    .unwrap();
                fs::rename(&temp_path, temp_path.with_extension("stolen")).unwrap();
                symlink(&outside, &temp_path).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(policy_path).unwrap(), original);
    assert_eq!(fs::read(outside).unwrap(), b"outside");
}

#[cfg(unix)]
#[test]
fn swapped_final_policy_name_cannot_redirect_a_write() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    write_policy(root.path(), br#"{"version":1,"entries":[]}"#);
    let policy_path = root.path().join(".oxaudit/policy.json");
    let held = root.path().join(".oxaudit/policy-held");
    let outside = root.path().join("outside.json");
    fs::write(&outside, b"outside").unwrap();

    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::Never,
        |stage| {
            if stage == IoStage::BeforeReplace {
                fs::rename(&policy_path, &held).unwrap();
                symlink(&outside, &policy_path).unwrap();
            }
        },
    )
    .unwrap_err();

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(fs::read(held).unwrap(), br#"{"version":1,"entries":[]}"#);
    assert_eq!(fs::read(outside).unwrap(), b"outside");
}

#[cfg(unix)]
#[test]
fn post_replace_sync_failure_restores_prior_or_missing_policy_exactly() {
    for had_policy in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let original = br#"{"version":1,"entries":[]}"#;
        let mut recovery_before_rollback = None;
        if had_policy {
            write_policy(root.path(), original);
        }

        let error = update_policy_decision_with_test_hook(
            root.path(),
            &finding("secret"),
            &request(ReviewState::FalsePositive, "secret"),
            now(),
            WriteFailure::AfterReplaceBeforeDirectorySync,
            |stage| {
                if had_policy && stage == IoStage::AfterReplace {
                    recovery_before_rollback = fs::read_dir(root.path().join(".oxaudit"))
                        .unwrap()
                        .filter_map(Result::ok)
                        .find(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".policy.json.")
                                && entry.path().extension().is_some_and(|value| value == "tmp")
                        })
                        .map(|entry| fs::read(entry.path()).unwrap());
                }
            },
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PolicyWriteFailed
        );

        let policy_path = root.path().join(".oxaudit/policy.json");
        if had_policy {
            assert_eq!(fs::read(policy_path).unwrap(), original);
            assert_eq!(recovery_before_rollback.unwrap(), original);
            assert!(matches!(
                load_policy(root.path()).unwrap().status(),
                PolicyStatus::Valid { .. }
            ));
        } else {
            assert!(!policy_path.exists());
            assert_eq!(
                load_policy(root.path()).unwrap().status(),
                &PolicyStatus::Missing
            );
        }
        assert!(!fs::read_dir(root.path().join(".oxaudit"))
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".policy.json.")));
    }
}

#[cfg(unix)]
#[test]
fn failed_new_directory_root_sync_never_reports_a_policy_write() {
    let root = tempfile::tempdir().unwrap();
    let error = update_policy_decision_with_test_hook(
        root.path(),
        &finding("secret"),
        &request(ReviewState::FalsePositive, "secret"),
        now(),
        WriteFailure::AfterDirectoryCreateBeforeRootSync,
        |_| {},
    )
    .unwrap_err();
    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert!(!root.path().join(".oxaudit/policy.json").exists());
}
