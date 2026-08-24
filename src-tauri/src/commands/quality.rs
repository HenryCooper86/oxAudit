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

/// Execute the committed deterministic cross-language contract suite.
/// The result is honest about the corpus boundary and is not presented as a
/// representative ecosystem-wide recall claim.
#[tauri::command]
pub fn quality_status(findings: State<'_, FindingsState>) -> Result<QualityStatus, String> {
    let started = Instant::now();
    let suite: oxaudit_benchmark::BenchmarkSuite = serde_json::from_str(include_str!(
        "../../../benchmarks/ground-truth/source-smoke/suite.json"
    ))
    .map_err(|error| error.to_string())?;
    suite.validate().map_err(|error| error.to_string())?;
    let fixtures = [
        (
            "source-js-eval-positive",
            include_str!("../../../benchmarks/ground-truth/source-smoke/positive.js"),
        ),
        (
            "source-js-eval-negative",
            include_str!("../../../benchmarks/ground-truth/source-smoke/negative.js"),
        ),
        (
            "source-python-shell-positive",
            include_str!("../../../benchmarks/ground-truth/source-smoke/python-shell-positive.py"),
        ),
        (
            "source-python-shell-negative",
            include_str!("../../../benchmarks/ground-truth/source-smoke/python-shell-negative.py"),
        ),
        (
            "source-c-strcpy-positive",
            include_str!("../../../benchmarks/ground-truth/source-smoke/c-strcpy-positive.c"),
        ),
        (
            "source-c-strcpy-negative",
            include_str!("../../../benchmarks/ground-truth/source-smoke/c-strcpy-negative.c"),
        ),
        (
            "source-go-md5-positive",
            include_str!("../../../benchmarks/ground-truth/source-smoke/go-md5-positive.go"),
        ),
        (
            "source-go-md5-negative",
            include_str!("../../../benchmarks/ground-truth/source-smoke/go-md5-negative.go"),
        ),
        (
            "secret-generic-api-key-positive",
            include_str!(
                "../../../benchmarks/ground-truth/source-smoke/generic-api-key-positive.txt"
            ),
        ),
        (
            "secret-generic-api-key-negative",
            include_str!(
                "../../../benchmarks/ground-truth/source-smoke/generic-api-key-negative.txt"
            ),
        ),
    ];
    let mut passed_targets = 0;
    let mut true_positives = 0;
    let mut false_positives = 0;
    let mut false_negatives = 0;
    let mut misses = Vec::new();
    let mut unexpected = Vec::new();
    for (target_id, content) in fixtures {
        let target = suite
            .targets
            .iter()
            .find(|target| target.id == target_id)
            .ok_or_else(|| format!("benchmark target {target_id} is missing"))?;
        let families = if target.scanner_families.is_empty() {
            vec!["source-pattern".to_string()]
        } else {
            target.scanner_families.clone()
        };
        let actual = crate::scanners::benchmark_observations(
            content,
            target.language.as_deref().unwrap_or(""),
            families.iter().any(|family| family == "source-pattern"),
            families.iter().any(|family| family == "secret"),
        )
        .into_iter()
        .map(
            |(rule_id, evidence_kind)| oxaudit_benchmark::ActualObservation {
                identity: oxaudit_benchmark::ObservationIdentity {
                    rule_id: rule_id.into(),
                    artifact_path: target.input_path.clone(),
                },
                evidence_kind: evidence_kind.into(),
            },
        )
        .collect::<Vec<_>>();
        let result = oxaudit_benchmark::judge(
            target,
            oxaudit_benchmark::ExecutionResult {
                observations: actual,
                runtime_ms: 0,
                peak_memory_bytes: None,
            },
        );
        true_positives += result.true_positives as usize;
        false_positives += result.false_positives as usize;
        false_negatives += result.false_negatives as usize;
        misses.extend(result.misses.into_iter().map(|identity| {
            format!(
                "{target_id}: {} @ {}",
                identity.rule_id, identity.artifact_path
            )
        }));
        unexpected.extend(result.unexpected.into_iter().map(|identity| {
            format!(
                "{target_id}: {} @ {}",
                identity.rule_id, identity.artifact_path
            )
        }));
        if result.status == oxaudit_benchmark::TargetStatus::Passed {
            passed_targets += 1;
        }
    }
    let precision_denominator = true_positives + false_positives;
    let recall_denominator = true_positives + false_negatives;
    let service = findings.service().map_err(|error| error.to_string())?;
    let previous = service
        .repository()
        .benchmark_latest(&suite.id)
        .map_err(|error| error.to_string())?
        .and_then(|value| serde_json::from_value::<QualityStatus>(value).ok());
    let precision =
        (precision_denominator > 0).then_some(true_positives as f64 / precision_denominator as f64);
    let recall =
        (recall_denominator > 0).then_some(true_positives as f64 / recall_denominator as f64);
    let regression = previous.as_ref().is_some_and(|previous| {
        false_positives > previous.false_positives
            || false_negatives > previous.false_negatives
            || matches!((precision, previous.precision), (Some(current), Some(old)) if current < old)
            || matches!((recall, previous.recall), (Some(current), Some(old)) if current < old)
    });
    let status = QualityStatus {
        schema_version: suite.schema_version,
        suite_id: suite.id.clone(),
        suite_version: suite.version.clone(),
        description: suite.description,
        corpus_targets: suite.targets.len(),
        passed_targets,
        true_positives,
        false_positives,
        false_negatives,
        precision,
        recall,
        runtime_ms: started.elapsed().as_millis() as u64,
        misses,
        unexpected,
        limitation: "Ten repository-authored targets cover four source languages and one secret family with paired negatives. This is a stronger regression contract, not a representative ecosystem-wide recall claim.".into(),
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
