//! Signature pack commands: validate, install, list, enable, remove.
//!
//! Each Tauri command is a thin wrapper over an `_inner` function that the
//! headless server's dispatch calls too. Validation and installation read
//! archives, hash files and compile rules, so they run on a blocking thread,
//! never on an async runtime worker.

use std::path::Path;

use serde::Deserialize;
use tauri::State;

use crate::sigpacks::{
    validate_pack, InstalledSigPack, PackKind, PackMetadata, PackPreview, SigPacksState,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallSignaturePackRequest {
    pub kind: PackKind,
    /// A rule file, a folder, or a `.zip`.
    pub path: String,
    pub name: String,
    pub license: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub authors: Option<String>,
}

pub(crate) async fn validate_signature_pack_inner(
    kind: PackKind,
    path: &str,
) -> Result<PackPreview, String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || validate_pack(kind, Path::new(&path)))
        .await
        .map_err(|error| format!("the pack validation did not finish: {error}"))?
}

pub(crate) async fn install_signature_pack_inner(
    packs: &SigPacksState,
    request: InstallSignaturePackRequest,
) -> Result<InstalledSigPack, String> {
    let store = packs.shared()?.clone();
    tokio::task::spawn_blocking(move || {
        store.install(
            request.kind,
            Path::new(&request.path),
            &PackMetadata {
                name: request.name,
                license: request.license,
                version: request.version,
                source: request.source,
                authors: request.authors,
            },
            &chrono::Utc::now().to_rfc3339(),
        )
    })
    .await
    .map_err(|error| format!("the pack installation did not finish: {error}"))?
}

pub(crate) fn list_signature_packs_inner(
    packs: &SigPacksState,
) -> Result<Vec<InstalledSigPack>, String> {
    packs.store()?.list()
}

pub(crate) fn set_signature_pack_enabled_inner(
    packs: &SigPacksState,
    id: &str,
    enabled: bool,
) -> Result<(), String> {
    packs.store()?.set_enabled(id, enabled)
}

pub(crate) fn remove_signature_pack_inner(packs: &SigPacksState, id: &str) -> Result<(), String> {
    packs.store()?.remove(id)
}

/// Preview an import without writing anything.
#[tauri::command]
pub async fn validate_signature_pack(kind: PackKind, path: String) -> Result<PackPreview, String> {
    validate_signature_pack_inner(kind, &path).await
}

#[tauri::command]
pub async fn install_signature_pack(
    packs: State<'_, SigPacksState>,
    request: InstallSignaturePackRequest,
) -> Result<InstalledSigPack, String> {
    install_signature_pack_inner(&packs, request).await
}

#[tauri::command]
pub fn list_signature_packs(
    packs: State<'_, SigPacksState>,
) -> Result<Vec<InstalledSigPack>, String> {
    list_signature_packs_inner(&packs)
}

#[tauri::command]
pub fn set_signature_pack_enabled(
    packs: State<'_, SigPacksState>,
    id: String,
    enabled: bool,
) -> Result<(), String> {
    set_signature_pack_enabled_inner(&packs, &id, enabled)
}

#[tauri::command]
pub fn remove_signature_pack(packs: State<'_, SigPacksState>, id: String) -> Result<(), String> {
    remove_signature_pack_inner(&packs, &id)
}

#[cfg(all(test, feature = "yara"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// On a single-threaded runtime, a task spawned before the call can only
    /// run while the call is waiting. If the pack were read and compiled on
    /// the runtime thread, the task would not have run when the call returns.
    #[test]
    fn validation_and_installation_do_not_block_the_runtime_thread() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        for i in 0..50 {
            std::fs::write(
                rules.join(format!("r{i}.yar")),
                format!("rule r{i} {{ strings: $a = \"marker-{i}\" condition: $a }}"),
            )
            .unwrap();
        }
        let packs = SigPacksState::available(
            crate::sigpacks::SigPackStore::open(&dir.path().join("data/rule-packs.sqlite3"))
                .unwrap(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let ran = Arc::new(AtomicBool::new(false));
            let flag = ran.clone();
            tokio::spawn(async move { flag.store(true, Ordering::SeqCst) });
            let preview = validate_signature_pack_inner(PackKind::Yara, &rules.to_string_lossy())
                .await
                .unwrap();
            assert_eq!(preview.rule_count, 50);
            assert!(ran.load(Ordering::SeqCst), "validation blocked the runtime");

            let ran = Arc::new(AtomicBool::new(false));
            let flag = ran.clone();
            tokio::spawn(async move { flag.store(true, Ordering::SeqCst) });
            let installed = install_signature_pack_inner(
                &packs,
                InstallSignaturePackRequest {
                    kind: PackKind::Yara,
                    path: rules.to_string_lossy().into_owned(),
                    name: "fifty".into(),
                    license: "Apache-2.0".into(),
                    version: None,
                    source: None,
                    authors: None,
                },
            )
            .await
            .unwrap();
            assert_eq!(installed.rule_count, 50);
            assert!(
                ran.load(Ordering::SeqCst),
                "installation blocked the runtime"
            );
        });
    }
}
