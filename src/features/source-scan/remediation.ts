export interface Remediation { before: string; after: string; constraint: string; verify: string[] }
const dataOnly: Remediation = {
  before: "const value = eval(request.body.expression);",
  after: "// Only when the input contract is JSON data:\nconst value = JSON.parse(request.body.json);\nvalidateExpectedSchema(value);",
  constraint: "JSON.parse applies only to JSON data, not arbitrary JavaScript expressions. Validate the parsed shape and handle invalid JSON. If evaluation is intentional, redesign it as explicit allowlisted operations; Function constructors retain code-execution risk.",
  verify: ["Test expected data, malformed JSON, unexpected keys and rejected code input.", "Trace input through validation to its consumers, save the file, then recheck this finding."],
};
const jsCommand: Remediation = {
  before: 'exec("convert " + request.body.file + " output.png");',
  after: 'import { execFile } from "node:child_process";\nconst file = allowedInputs.get(request.body.inputId);\nif (!file) throw new Error("Unknown input");\nexecFile("/usr/bin/convert", [file, "output.png"], { shell: false }, handleResult);',
  constraint: "Use an allowlist of owned input files and a fixed executable. Choose its trusted absolute path for your deployment. Separate arguments remove shell expansion, but the program can still interpret flags, paths or expressions; validate each argument for that program. This example intentionally removes pipes and redirection.",
  verify: ["Test valid inputs and reject unknown IDs, option-like arguments and traversal attempts.", "Verify the program's argument semantics, output/error handling and intended behavior before rechecking."],
};
const pyCommand: Remediation = {
  before: 'subprocess.run("convert " + user_file + " output.png", shell=True)',
  after: 'import subprocess\nfile = allowed_inputs[input_id]  # allowlist of owned files\nsubprocess.run(["/usr/bin/convert", file, "output.png"], shell=False, check=True)',
  constraint: "Use an allowlist of owned files and a fixed trusted executable path appropriate for the deployment. shell=False and argument lists remove shell parsing; they do not validate program-specific flags, paths or expressions. Pipes and redirection need an explicit redesign.",
  verify: ["Test valid work and reject unknown input IDs, option injection and traversal.", "Check subprocess failure handling and application behavior, save and recheck."],
};
const jsSql: Remediation = {
  before: 'db.query("SELECT * FROM users WHERE id = " + userId);',
  after: '// node-postgres value binding:\nawait db.query("SELECT * FROM users WHERE id = $1", [userId]);',
  constraint: "This example uses node-postgres placeholders for values. Use your driver's binding syntax. Placeholders do not bind identifiers such as table/column names or SQL keywords: map those to fixed allowlisted SQL fragments. Keep authorization and input type checks.",
  verify: ["Test normal IDs and quote/comment input as data; inspect which rows are returned.", "Test authorization separately, verify no concatenated query remains, save and recheck."],
};
const pySql: Remediation = {
  before: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
  after: '# Python sqlite3 value binding:\ncursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
  constraint: "This example uses sqlite3 value placeholders; other drivers may require %s or named bindings. Do not interpolate the placeholders yourself. Placeholders cannot substitute identifiers, table/column names or keywords; use fixed allowlisted SQL for those. Preserve authorization checks.",
  verify: ["Test ordinary input and SQL metacharacters as bound values, checking returned rows.", "Test authorization independently, save the query change and recheck."],
};
const rotation: Remediation = {
  before: 'const apiKey = "<hard-coded credential>";',
  after: 'const apiKey = process.env.SERVICE_API_KEY;\nif (!apiKey) throw new Error("Missing service credential");',
  constraint: "Illustrative environment injection only. Provision a new credential through your secret manager or deployment environment; never paste a detected value into this example. Removing a literal does not invalidate a leaked credential or remove it from repository history.",
  verify: ["Revoke or rotate the exposed credential at its issuer, update consumers and confirm the old credential no longer works.", "Review access logs and repository/history exposure; remove remaining copies following your incident process.", "Test the application's new credential configuration and recheck for literals. Scan absence does not verify rotation."],
};
const examples: Record<string, Remediation> = {
  "js-eval": dataOnly,
  "js-function-ctor": { ...dataOnly, before: 'const value = new Function("return " + expression)();' },
  "js-child-process": jsCommand,
  "js-exec-concat": jsCommand,
  "js-sql-concat": jsSql,
  "py-subprocess-shell": pyCommand,
  "py-os-system": { ...pyCommand, before: 'os.system("convert " + user_file + " output.png")' },
  "py-sql-fstring": pySql,
  "py-sql-concat": { ...pySql, before: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)' },
};
export function remediationFor(ruleId: string, category: string): Remediation | undefined {
  return category === "secret" ? rotation : examples[ruleId];
}
