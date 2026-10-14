# oxAudit for VS Code

Static security scanning for your workspace, surfaced as native VS Code diagnostics. The extension spawns the [oxAudit CLI](https://github.com/HenryCooper86/oxAudit) (`oxaudit-cli scan --format json --quiet`) and maps its findings into the Problems panel — secrets, dependency vulnerabilities, and code-level security issues, with file/line/column precision.

## Requirements

- **oxaudit-cli** installed and on your `PATH` (or point `oxaudit.cliPath` at the binary). See the [install instructions](https://github.com/HenryCooper86/oxAudit#install).

## Commands

| Command | Description |
| --- | --- |
| `oxAudit: Scan Workspace` | Scan the first workspace folder and publish findings as diagnostics. |
| `oxAudit: Clear Findings` | Clear all oxAudit diagnostics. |

## Settings

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `oxaudit.cliPath` | string | `"oxaudit-cli"` | Path to the `oxaudit-cli` executable (resolved from `PATH` by default). |
| `oxaudit.scanOnOpen` | boolean | `false` | Run one scan automatically when a workspace folder is opened. |
| `oxaudit.maxFindings` | number | `500` | Maximum number of findings published as diagnostics per scan. |

## Status bar

The status bar item (left side) shows the scanner state: idle, scanning (spinner), or the finding count from the last scan. Click it to re-scan. If results exceed `oxaudit.maxFindings`, the tooltip notes the truncation.

Scans are seconds-long and run only on demand (or once on open if enabled) — there is deliberately no auto-scan on save.

## Run from source

```sh
cd editors/vscode
npm install
npm run compile
```

Then press `F5` in VS Code to launch an Extension Development Host with the extension loaded.
