// oxAudit VS Code extension: wraps the oxaudit-cli scanner and surfaces
// findings as native diagnostics. Spawns the CLI via execFile (never a
// shell) and parses its stable JSON contract:
//   oxaudit-cli scan <dir> --format json --quiet
//     stdout: { "summary": ScanSummary, "findings": Finding[] }
//     exit 0: clean, exit 1: findings present, exit 2: usage, exit 3: failure

import * as vscode from 'vscode';
import { execFile } from 'node:child_process';

const INSTALL_URL = 'https://github.com/HenryCooper86/oxAudit#install';
const DIAGNOSTIC_SOURCE = 'oxaudit';

interface CliFinding {
  filePath: string;
  line: number;
  column: number;
  ruleId: string;
  ruleName: string;
  severity: string;
  title: string;
  description: string;
  matchText: string;
}

interface CliReport {
  summary: unknown;
  findings: CliFinding[];
}

let collection: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let scanning = false;

export function activate(context: vscode.ExtensionContext): void {
  collection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
  context.subscriptions.push(collection);

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'oxaudit.scanWorkspace';
  setIdleStatus();
  statusBar.show();
  context.subscriptions.push(statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand('oxaudit.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('oxaudit.clearDiagnostics', () => {
      collection.clear();
      setIdleStatus();
    }),
  );

  const config = vscode.workspace.getConfiguration('oxaudit');
  if (config.get<boolean>('scanOnOpen', false) && vscode.workspace.workspaceFolders?.length) {
    void scanWorkspace();
  }
}

export function deactivate(): void {
  collection?.dispose();
  statusBar?.dispose();
}

function setIdleStatus(): void {
  statusBar.text = '$(shield) oxAudit';
  statusBar.tooltip = 'oxAudit: click to scan the workspace';
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'low':
    case 'info':
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function toDiagnostic(finding: CliFinding): vscode.Diagnostic {
  // CLI positions are 1-based; VS Code ranges are 0-based.
  const line = Math.max(0, finding.line - 1);
  const column = Math.max(0, finding.column - 1);
  const width = Math.max(1, finding.matchText?.length ?? 1);
  const range = new vscode.Range(line, column, line, column + width);
  const diagnostic = new vscode.Diagnostic(
    range,
    `${finding.title} (${finding.ruleId})`,
    mapSeverity(finding.severity),
  );
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = finding.ruleId;
  return diagnostic;
}

function isFinding(value: unknown): value is CliFinding {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const f = value as Record<string, unknown>;
  return (
    typeof f.filePath === 'string' &&
    typeof f.line === 'number' &&
    typeof f.column === 'number' &&
    typeof f.ruleId === 'string' &&
    typeof f.severity === 'string' &&
    typeof f.title === 'string'
  );
}

function parseReport(stdout: string): CliReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error('oxaudit-cli produced malformed output (expected JSON on stdout).');
  }
  if (!parsed || typeof parsed !== 'object' || !('findings' in parsed)) {
    throw new Error('oxaudit-cli output is missing the "findings" array.');
  }
  const findings: unknown = parsed.findings;
  if (!Array.isArray(findings) || !findings.every(isFinding)) {
    throw new Error('oxaudit-cli output has an unexpected "findings" shape.');
  }
  return { summary: undefined, findings };
}

interface ScanResult {
  stdout: string;
  code: number;
}

function runCli(cliPath: string, args: string[], cwd: string): Promise<ScanResult> {
  return new Promise((resolve, reject) => {
    execFile(cliPath, args, { cwd, maxBuffer: 64 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        // execFile errors carry the exit code (number) or spawn errno (string).
        const code = error.code;
        if (code === 'ENOENT') {
          reject(new Error(
            `oxaudit-cli not found at "${cliPath}". Install it first: ${INSTALL_URL}`,
          ));
          return;
        }
        // Exit code 1 means "findings present" — not an error for us.
        if (code === 1) {
          resolve({ stdout, code: 1 });
          return;
        }
        const detail = typeof stderr === 'string' && stderr.trim() ? `: ${stderr.trim()}` : '';
        reject(new Error(`oxaudit-cli scan failed (exit ${String(code)})${detail}`));
        return;
      }
      resolve({ stdout, code: 0 });
    });
  });
}

async function scanWorkspace(): Promise<void> {
  if (scanning) {
    return;
  }
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showWarningMessage('oxAudit: open a workspace folder before scanning.');
    return;
  }

  const config = vscode.workspace.getConfiguration('oxaudit');
  const cliPath = config.get<string>('cliPath', 'oxaudit-cli');
  const maxFindings = Math.max(1, config.get<number>('maxFindings', 500));

  scanning = true;
  statusBar.text = '$(sync~spin) oxAudit: scanning…';
  statusBar.tooltip = 'oxAudit: scan in progress';
  try {
    const { stdout } = await runCli(
      cliPath,
      ['scan', folder.uri.fsPath, '--format', 'json', '--quiet'],
      folder.uri.fsPath,
    );
    const report = parseReport(stdout);

    const truncated = report.findings.length > maxFindings;
    const capped = truncated ? report.findings.slice(0, maxFindings) : report.findings;

    // Finding filePath values are scan-root-relative; join with the folder.
    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const finding of capped) {
      const uri = vscode.Uri.joinPath(folder.uri, finding.filePath);
      const key = uri.toString();
      const list = byFile.get(key) ?? [];
      list.push(toDiagnostic(finding));
      byFile.set(key, list);
    }

    collection.clear();
    for (const [key, diagnostics] of byFile) {
      collection.set(vscode.Uri.parse(key), diagnostics);
    }

    statusBar.text = `$(shield) oxAudit: ${capped.length} findings`;
    statusBar.tooltip = truncated
      ? `oxAudit: showing the first ${capped.length} findings (capped by oxaudit.maxFindings). Click to re-scan.`
      : 'oxAudit: click to re-scan';
  } catch (error) {
    setIdleStatus();
    const message = error instanceof Error ? error.message : String(error);
    void vscode.window.showErrorMessage(`oxAudit: ${message}`);
  } finally {
    scanning = false;
  }
}
