//! Rule library, benchmark, and data source commands.
//!
//! Split out of `commands/mod.rs`. A child module rather than a sibling
//! file, so `use super::*` still reaches the shared state and helpers
//! without widening anything to `pub`.

use super::*;

#[tauri::command]
pub fn list_data_sources(
    findings: State<'_, FindingsState>,
) -> Result<Vec<DataSourceStatus>, String> {
    data_source_statuses(findings.service().map_err(|error| error.to_string())?)
}

#[tauri::command]
pub async fn refresh_data_source(
    provider_id: String,
    state: State<'_, AppState>,
    findings: State<'_, FindingsState>,
) -> Result<DataSourceStatus, String> {
    const MAX_PROVIDER_BYTES: u64 = 32 * 1024 * 1024;
    let definition = DATA_SOURCES
        .iter()
        .find(|definition| definition.id == provider_id)
        .ok_or_else(|| "unknown provider".to_string())?;
    let response = state
        .http
        .get(definition.source_url)
        .send()
        .await
        .map_err(|error| format!("{} refresh failed: {error}", definition.name))?;
    if !response.status().is_success() {
        return Err(format!(
            "{} returned {}",
            definition.name,
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_PROVIDER_BYTES)
    {
        return Err("provider response exceeded the 32 MiB safety limit".into());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("{} response could not be read: {error}", definition.name))?;
    if bytes.len() as u64 > MAX_PROVIDER_BYTES {
        return Err("provider response exceeded the 32 MiB safety limit".into());
    }
    let content: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("provider JSON is invalid: {error}"))?;
    let record_count = match definition.id {
        "cisa-kev" => content.get("vulnerabilities"),
        "nvd" => content.get("vulnerabilities"),
        "epss" => content.get("data"),
        _ => None,
    }
    .and_then(serde_json::Value::as_array)
    .map_or(1, |records| records.len() as u64);
    let content_sha256 = {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(&bytes))
    };
    let fetched_at_ms = epoch_millis();
    let snapshot_id = format!("provider_{}", uuid::Uuid::new_v4());
    let snapshot = crate::findings::repository::ProviderSnapshotRecord {
        id: snapshot_id,
        provider_id: definition.id.into(),
        fetched_at_ms,
        content_sha256,
        payload: serde_json::json!({
            "schemaVersion": 1,
            "recordCount": record_count,
            "sourceUrl": definition.source_url,
            "content": content,
        }),
    };
    let service = findings.service().map_err(|error| error.to_string())?;
    service
        .repository()
        .provider_save_snapshot(&snapshot)
        .map_err(|error| error.to_string())?;
    data_source_statuses(service)?
        .into_iter()
        .find(|status| status.id == provider_id)
        .ok_or_else(|| "refreshed provider status is unavailable".into())
}

/// Return immutable, offline metadata for every built-in rule family.
/// Embedded source/secret engines are reported honestly as legacy compiled
/// packs while their public declarative snapshots are completed.
#[tauri::command]
pub fn rule_library_status() -> Result<Vec<RuleLibraryPackStatus>, String> {
    use sha2::Digest;

    let source_snapshot_sha256 = format!(
        "{:x}",
        sha2::Sha256::digest(include_bytes!("../scanners/patterns.rs"))
    );
    let secret_snapshot_sha256 = format!(
        "{:x}",
        sha2::Sha256::digest(include_bytes!("../scanners/secrets.rs"))
    );
    let signature = crate::binscan::native::signature::signature_provenance_status()?;
    let verified: std::collections::BTreeSet<_> =
        signature.verified_products.iter().cloned().collect();
    let mut binary_rules = signature
        .verified_products
        .iter()
        .chain(signature.unverified_products.iter())
        .map(|product| RuleLibraryRuleStatus {
            id: format!("binary.{product}"),
            title: product.clone(),
            severity: "inventory".into(),
            scope: signature.architectures.clone(),
            fixture_health: if verified.contains(product) {
                "verified".into()
            } else {
                "coverageNeeded".into()
            },
            provenance: "independently derived from known-version binaries".into(),
        })
        .collect::<Vec<_>>();
    binary_rules.sort_by(|left, right| left.title.cmp(&right.title));

    let source_rules = crate::scanners::patterns::SOURCE_RULES
        .iter()
        .map(|rule| RuleLibraryRuleStatus {
            id: rule.id.into(),
            title: rule.name.into(),
            severity: rule.severity.into(),
            scope: if rule.languages.is_empty() {
                vec!["all supported languages".into()]
            } else {
                rule.languages
                    .iter()
                    .map(|language| (*language).into())
                    .collect()
            },
            fixture_health: if matches!(
                rule.id,
                "js-eval" | "py-subprocess-shell" | "c-strcpy" | "go-weak-hash"
            ) {
                "verified".into()
            } else {
                "coverageNeeded".into()
            },
            provenance: "repository-authored Apache-2.0 rule".into(),
        })
        .collect::<Vec<_>>();
    let secret_rules = crate::scanners::secrets::SECRET_RULES
        .iter()
        .map(|rule| RuleLibraryRuleStatus {
            id: rule.id.into(),
            title: rule.name.into(),
            severity: rule.severity.into(),
            scope: vec!["text source and configuration".into()],
            fixture_health: "unitTested".into(),
            provenance: "repository-authored Apache-2.0 rule".into(),
        })
        .collect::<Vec<_>>();

    Ok(vec![
        RuleLibraryPackStatus {
            id: "oxaudit.source.builtin".into(),
            name: "Built-in source checks".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            engine: "source.regex.v1".into(),
            enabled: true,
            license: "Apache-2.0".into(),
            source: "oxAudit repository-authored rules".into(),
            creation_method: "authored".into(),
            content_sha256: source_snapshot_sha256,
            validation: "compiledSnapshotVerified".into(),
            fixture_summary: "4 committed cross-language positive/negative pairs; remaining rules require fixture provenance".into(),
            rules: source_rules,
        },
        RuleLibraryPackStatus {
            id: "oxaudit.secrets.builtin".into(),
            name: "Built-in secret checks".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            engine: "secret.regex.v1".into(),
            enabled: true,
            license: "Apache-2.0".into(),
            source: "oxAudit repository-authored rules".into(),
            creation_method: "authored".into(),
            content_sha256: secret_snapshot_sha256,
            validation: "compiledSnapshotVerified".into(),
            fixture_summary: "Unit coverage plus a committed generic-key positive/negative pair; most rules still require provenance fixtures".into(),
            rules: secret_rules,
        },
        RuleLibraryPackStatus {
            id: signature.pack_id,
            name: "Native binary component signatures".into(),
            version: signature.version,
            engine: "binary.signature.v1".into(),
            enabled: true,
            license: signature.license,
            source: signature.source,
            creation_method: signature.creation_method,
            content_sha256: signature.content_sha256,
            validation: "provenanceVerified".into(),
            fixture_summary: format!(
                "{} of {} signatures have provenance-linked fixtures; {} remain explicitly unverified",
                signature.verified_fixture_count,
                signature.signature_count,
                signature.unverified_products.len()
            ),
            rules: binary_rules,
        },
    ])
}

/// Validate an external declarative pack and all referenced fixtures without
/// installing it or executing rule-supplied code. The compiler and fixture
/// reader enforce independent size and path-containment budgets.
#[tauri::command]
pub fn validate_rule_pack(path: String) -> Result<RulePackValidationPreview, String> {
    const MAX_PACK_BYTES: u64 = 2 * 1024 * 1024;
    let path = Path::new(&path)
        .canonicalize()
        .map_err(|error| format!("cannot resolve the rule pack: {error}"))?;
    let metadata = path
        .metadata()
        .map_err(|error| format!("cannot inspect the rule pack: {error}"))?;
    if !metadata.is_file() {
        return Err("the selected rule pack is not a file".into());
    }
    if metadata.len() > MAX_PACK_BYTES {
        return Err("the selected rule pack exceeds the 2 MiB manifest limit".into());
    }
    let input = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read the rule pack: {error}"))?;
    let pack = oxaudit_scanners::RulePack::parse_toml(&input).map_err(|error| error.to_string())?;
    let compiled = oxaudit_scanners::CompiledRulePack::compile(pack.clone())
        .map_err(|error| error.to_string())?;
    let root = path
        .parent()
        .ok_or_else(|| "the rule pack has no containing directory".to_string())?;
    pack.validate_fixture_files(root)
        .map_err(|error| error.to_string())?;
    let engines = pack
        .rules
        .iter()
        .map(|rule| {
            serde_json::to_value(rule.engine)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".into())
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let fixture_count = pack
        .rules
        .iter()
        .map(|rule| rule.positive_fixtures.len() + rule.negative_fixtures.len())
        .sum();
    Ok(RulePackValidationPreview {
        id: compiled.metadata().id.to_string(),
        name: compiled.metadata().name.clone(),
        version: compiled.metadata().version.clone(),
        content_sha256: compiled.metadata().content_sha256.clone(),
        rule_count: pack.rules.len(),
        engines,
        fixture_count,
        license: compiled.metadata().provenance.license.clone(),
        source: compiled.metadata().provenance.source.clone(),
        validation: "schema, provenance, content hash, regex budgets, fixture hashes, and fixture containment verified".into(),
    })
}

/// Score the committed corpus and record the result.
///
/// The same corpus and the same scoring the command line uses, embedded so the
/// packaged app can reach it. This previously read a separate, much smaller
/// suite, so the desktop app reported ten fixtures while the CLI and the README
/// reported fifty — two answers to one question.
///
/// The result stays honest about the corpus boundary and is not presented as a
/// representative ecosystem-wide recall claim.
#[tauri::command]
pub fn quality_status(findings: State<'_, FindingsState>) -> Result<QualityStatus, String> {
    let suite = crate::quality::embedded_suite().map_err(|error| error.to_string())?;
    let report = crate::quality::run_embedded(&suite).map_err(|error| error.to_string())?;

    let service = findings.service().map_err(|error| error.to_string())?;
    let previous = service
        .repository()
        .benchmark_latest(&suite.id)
        .map_err(|error| error.to_string())?
        .and_then(|value| serde_json::from_value::<QualityStatus>(value).ok());

    let regression = previous.as_ref().is_some_and(|previous| {
        report.totals.false_positives as usize > previous.false_positives
            || report.totals.false_negatives as usize > previous.false_negatives
            || matches!((report.precision, previous.precision), (Some(current), Some(old)) if current < old)
            || matches!((report.recall, previous.recall), (Some(current), Some(old)) if current < old)
    });

    let negatives = suite
        .targets
        .iter()
        .filter(|target| !target.expected_absent.is_empty())
        .count();
    let languages = suite
        .targets
        .iter()
        .filter_map(|target| target.language.as_deref())
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    let status = QualityStatus {
        schema_version: 1,
        suite_id: suite.id.clone(),
        suite_version: suite.version.clone(),
        description: suite.description.clone(),
        corpus_targets: suite.targets.len(),
        // A fixture passes when it produced neither a miss nor a false positive.
        passed_targets: suite.targets.len()
            - report.misses.len()
            - report.totals.false_positives as usize,
        true_positives: report.totals.true_positives as usize,
        false_positives: report.totals.false_positives as usize,
        false_negatives: report.totals.false_negatives as usize,
        precision: report.precision,
        recall: report.recall,
        runtime_ms: report.runtime_ms,
        misses: report.misses.clone(),
        unexpected: report
            .collateral
            .iter()
            .map(|hit| format!("{} fired on {}", hit.rule_id, hit.fixture))
            .collect(),
        limitation: format!(
            "{} repository-authored fixtures, {negatives} of them negatives drawn from shapes this \
             scanner was observed reporting incorrectly, across {languages} languages. This is a \
             regression contract, not a representative ecosystem-wide recall claim.",
            suite.targets.len()
        ),
        previous_precision: previous.as_ref().and_then(|previous| previous.precision),
        previous_recall: previous.as_ref().and_then(|previous| previous.recall),
        regression,
    };

    service
        .repository()
        .benchmark_save(
            &format!("benchmark_{}", uuid::Uuid::new_v4()),
            &suite.id,
            &suite.version,
            epoch_millis(),
            &status,
        )
        .map_err(|error| error.to_string())?;
    Ok(status)
}
