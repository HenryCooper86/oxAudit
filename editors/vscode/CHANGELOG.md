# Changelog

## 0.2.6

- Align with the corrected oxAudit release, which selects and verifies the application
  Rust SBOM. Includes the scanner precision fixes documented below.

## 0.2.5

- Align the extension version with the oxAudit 0.2.5 patch release. The CLI fixes
  Rust SQL literal/comment false positives and generic credential matches across
  alternative pattern labels; install the updated CLI to receive those fixes.

## 0.1.0

- Initial release: workspace scanning via the `oxaudit-cli` JSON output, findings as diagnostics, status bar integration, configurable CLI path / scan-on-open / max findings.
