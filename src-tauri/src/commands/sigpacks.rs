//! Signature pack commands: validate, install, list, enable, remove.
//!
//! Each Tauri command is a thin wrapper over an `_inner` function that the
//! headless server's dispatch calls too.

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

pub(crate) fn validate_signature_pack_inner(
    kind: PackKind,
    path: &str,
) -> Result<PackPreview, String> {
    validate_pack(kind, Path::new(path))
}

pub(crate) fn install_signature_pack_inner(
    packs: &SigPacksState,
    request: InstallSignaturePackRequest,
) -> Result<InstalledSigPack, String> {
    let store = packs.store()?;
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
    validate_signature_pack_inner(kind, &path)
}

#[tauri::command]
pub async fn install_signature_pack(
    packs: State<'_, SigPacksState>,
    request: InstallSignaturePackRequest,
) -> Result<InstalledSigPack, String> {
    install_signature_pack_inner(&packs, request)
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
