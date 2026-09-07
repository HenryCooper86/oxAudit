import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

const repo = new URL("../../", import.meta.url);
const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

test("an autocrlf checkout preserves bundled evidence hashes and exact binary bytes", async () => {
  const owned = await mkdtemp(path.join(tmpdir(), "oxaudit-evidence-checkout-"));
  try {
    // Only this disposable repository's objects/index are written. Global Git
    // configuration and the caller's Git/index environment cannot affect it.
    const env: NodeJS.ProcessEnv = Object.fromEntries(
      Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
    );
    // A hostile default user attributes file must not alter this checkout.
    const userConfig = path.join(owned, "user-config");
    await mkdir(path.join(userConfig, "git"), { recursive: true });
    await writeFile(path.join(userConfig, "git", "attributes"), "* -text\n");
    env.XDG_CONFIG_HOME = userConfig;
    Object.assign(env, { GIT_CONFIG_NOSYSTEM: "1", GIT_ATTR_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: path.join(owned, "no-global-config") });
    const git = (args: string[], input?: Buffer | string) => {
      const result = spawnSync("git", ["-C", owned, "-c", "core.autocrlf=true",
        "-c", `core.attributesFile=${path.join(owned, "no-user-attributes")}`, ...args], { env, input });
      if (result.error) throw result.error;
      assert.equal(result.status, 0, `Git ${args[0]} failed: ${result.stderr.toString()}`);
      return result.stdout;
    };
    git(["init", "--quiet"]);
    const files = new Map<string, Buffer>();
    files.set(".gitattributes", await readFile(new URL(".gitattributes", repo)));
    const signaturePath = "src-tauri/src/binscan/native/signatures.toml";
    const provenancePath = "src-tauri/src/binscan/native/signatures.provenance.toml";
    files.set(signaturePath, await readFile(new URL(signaturePath, repo)));
    files.set(provenancePath, await readFile(new URL(provenancePath, repo)));
    const expectedSignature = files.get(provenancePath)!.toString().match(/^signatures_sha256 = "([a-f0-9]{64})"$/m)?.[1];
    assert.ok(expectedSignature, "signature provenance must name its content hash");
    const expected = new Map<string, string>([[signaturePath, expectedSignature]]);
    for (const corpus of ["benchmarks/corpus", "benchmarks/ground-truth/source-smoke"]) {
      const suitePath = `${corpus}/suite.json`;
      const bytes = await readFile(new URL(suitePath, repo));
      files.set(suitePath, bytes);
      const suite = JSON.parse(bytes.toString());
      for (const target of suite.targets) {
        const file = `${corpus}/${target.inputPath}`;
        files.set(file, await readFile(new URL(file, repo)));
        expected.set(file, target.inputSha256);
      }
    }
    // Include mixed line endings and NULs to detect an over-broad text=eol
    // normalization fix that would corrupt future byte-addressed binary inputs.
    const binary = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 13, 10, 0xff, 10]);
    const mixedText = Buffer.from("first\r\nsecond\n", "utf8");
    files.set("benchmarks/corpus/checkout-byte-probe.bin", binary);
    files.set("benchmarks/ground-truth/checkout-byte-probe.txt", mixedText);
    files.set("checkout-probe.pdf", Buffer.from("%PDF-1.7\r\nprobe\n", "utf8"));
    files.set("checkout-control.txt", Buffer.from("ordinary\ntext\n", "utf8"));
    const index = [];
    for (const [file, bytes] of files) {
      // --stdin without a path writes the original blob without clean filters.
      const id = git(["hash-object", "-w", "--stdin"], bytes).toString().trim();
      index.push(`100644 ${id}\t${file}\n`);
    }
    git(["update-index", "--index-info"], index.join(""));
    git(["checkout-index", "--all", "--force"]);
    assert.equal((await readFile(path.join(owned, "checkout-control.txt"))).toString(), "ordinary\r\ntext\r\n", "the checkout must actually exercise autocrlf conversion");
    for (const [file, hash] of expected) {
      assert.equal(sha256(await readFile(path.join(owned, file))), hash, `${file}: checkout changed content-addressed evidence`);
    }
    for (const [file, original] of files) {
      if (file === ".gitattributes" || file === "checkout-control.txt") continue;
      assert.deepEqual(await readFile(path.join(owned, file)), original, `${file}: exact fixture bytes must survive checkout`);
    }
  } finally {
    await rm(owned, { recursive: true, force: true });
  }
});
