# Inert pilot fixtures

These files are scan inputs, not an application. Do not execute or import them,
install dependencies, or provide credentials. `vulnerable/handler.js` evaluates
a caller's JSON input as code; `corrected/handler.js` parses JSON and checks that
it is an object. The correction fits this deliberately narrow input contract.
The truncated `malformed-dependency/package-lock.json` must produce an incomplete
scan error, never a completed clean dependency result.

Copy a fixture into temporary writable space before editing. From the oxAudit
checkout on macOS/Linux:

```bash
pilot_dir=$(mktemp -d "${TMPDIR:-/tmp}/oxaudit-demo.XXXXXX")
cp -R examples/pilot/vulnerable "$pilot_dir/project"
printf '%s\n' "$pilot_dir/project"
# Select the printed project folder in oxAudit. Do not run its JavaScript.
# After inspecting js-eval, edit handler.js using corrected/handler.js as a guide.
```

PowerShell:

```powershell
$pilotDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $pilotDir
Copy-Item -Recurse examples/pilot/vulnerable (Join-Path $pilotDir 'project')
Write-Output (Join-Path $pilotDir 'project')
```

Keep the malformed lockfile in a separate project for the failure task. It must
not block the first source-finding task. Delete only the temporary directory you
created when finished. Production self-scans exclude directory names `pilot`
and `benchmarks`; neither fixture tree is production evidence.

For automated assertions, build the CLI and run:

```bash
npm run pilot:smoke -- --cli /absolute/path/to/oxaudit-cli
```

Use `--keep` to retain its owned temporary directory and reports. By default the
harness removes that directory, emits a JSON receipt, and exits nonzero on any
failed assertion. See [the pilot protocol](../../docs/pilot-validation.md) for
network limits, evidence semantics, and the empty feedback form.
