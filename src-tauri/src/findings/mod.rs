pub mod coverage;
pub mod domain;
pub mod error;
pub mod fingerprint;
pub mod policy;
pub mod redaction;
pub mod repository;
pub mod review;
pub mod service;

pub(crate) fn database_path(app_data_root: &std::path::Path) -> std::path::PathBuf {
    app_data_root.join("findings").join("findings.sqlite3")
}
