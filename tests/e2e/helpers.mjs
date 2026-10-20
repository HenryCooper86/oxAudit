// Shared harness for the daily browser smoke tests.
//
// One `backend` fixture per test: it copies the inert pilot fixtures into an
// isolated temp root, starts a refusing loopback proxy for the server's
// optional network enrichment (the same boundary as tools/pilot-smoke.mjs),
// and spawns a real oxaudit-server against the repository's built dist/ with
// a fresh ephemeral token. Backend diagnostics (process output, refused
// enrichment requests, the server's own log files) are attached as test
// artifacts when a test fails; the temp root is always removed.
import { test as base, expect } from "@playwright/test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer as createHttpServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { copyFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "..", "..");
const fixturesRoot = path.join(repoRoot, "examples", "pilot");

/** The locally built server binary (set OXAUDIT_E2E_SERVER to override). */
function serverBinary() {
  const override = process.env.OXAUDIT_E2E_SERVER;
  const candidates = override
    ? [...new Set([path.resolve(override), path.resolve(repoRoot, override)])]
    : [
        path.join(repoRoot, "src-tauri", "target", "debug", "oxaudit-server"),
        path.join(repoRoot, "src-tauri", "target", "debug", "oxaudit-server.exe"),
      ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(
    `No built oxaudit-server found (tried: ${candidates.join(", ")}). Build it with ` +
      "`cargo build --locked --features server --manifest-path src-tauri/Cargo.toml --bin oxaudit-server` " +
      "or point OXAUDIT_E2E_SERVER at an existing binary.",
  );
}

/** The frontend this suite exercises must already be built; never rebuilt here. */
function webRoot() {
  const dist = path.join(repoRoot, "dist");
  if (!existsSync(path.join(dist, "index.html"))) {
    throw new Error("dist/index.html is missing; run `npm run build` before the browser smoke suite.");
  }
  return dist;
}

/** Reserve an ephemeral loopback port for the server to bind. */
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createNetServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

/** Optional enrichment (CISA/OSV feeds) must fail closed: 502 everything. */
class RefusingProxy {
  constructor() {
    this.requests = [];
    this.server = createHttpServer((request, response) => {
      this.requests.push(`${request.method} ${request.url}`);
      response.writeHead(502);
      response.end("Optional network enrichment refused by the browser smoke\n");
    });
    this.server.on("connect", (request, socket) => {
      this.requests.push(`CONNECT ${request.url}`);
      socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    });
  }

  async start() {
    await new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(0, "127.0.0.1", resolve);
    });
    this.url = `http://127.0.0.1:${this.server.address().port}`;
  }

  async stop() {
    if (!this.server.listening) return;
    this.server.closeAllConnections();
    await new Promise((resolve) => this.server.close(resolve));
  }
}

const OUTPUT_LIMIT = 120_000;

class Backend {
  static async create() {
    const binary = serverBinary();
    const web = webRoot();
    const root = await mkdtemp(path.join(tmpdir(), "oxaudit-e2e-"));
    const proxy = new RefusingProxy();
    const backend = new Backend({
      binary,
      web,
      root,
      token: randomUUID(),
      proxy,
    });
    try {
      await proxy.start();
      await mkdir(path.join(backend.root, "export"), { recursive: true });
      await backend.start();
      return backend;
    } catch (error) {
      // Never leave a listening proxy, a child process, or a temp root
      // behind on startup failures; the thrown error already carries the
      // process output.
      await backend.dispose({ status: "skipped", attach: async () => {} });
      throw error;
    }
  }

  constructor({ binary, web, root, token, proxy }) {
    this.binary = binary;
    this.web = web;
    this.root = root;
    this.token = token;
    this.proxy = proxy;
    this.dataDir = path.join(root, "data");
    this.configDir = path.join(root, "config");
    this.child = null;
    this.port = null;
    this.output = [];
  }

  get origin() {
    return `http://127.0.0.1:${this.port}`;
  }

  childEnvironment() {
    // reqwest honours these proxy settings; an explicit empty NO_PROXY stops
    // user bypasses from defeating the enrichment boundary.
    const proxyVars = {
      HTTP_PROXY: this.proxy.url,
      HTTPS_PROXY: this.proxy.url,
      ALL_PROXY: this.proxy.url,
      http_proxy: this.proxy.url,
      https_proxy: this.proxy.url,
      all_proxy: this.proxy.url,
      NO_PROXY: "",
      no_proxy: "",
    };
    return { ...process.env, OXAUDIT_SERVER_TOKEN: this.token, ...proxyVars };
  }

  async start() {
    const port = this.port ?? (await freePort());
    const child = spawn(
      this.binary,
      [
        "--bind", `127.0.0.1:${port}`,
        "--data-dir", this.dataDir,
        "--config-dir", this.configDir,
        "--web-root", this.web,
      ],
      { env: this.childEnvironment(), stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
    );
    this.child = child;
    const launched = once(child, "spawn");
    const capture = (chunk) => {
      this.output.push(chunk.toString("utf8"));
      if (this.output.join("").length > OUTPUT_LIMIT) {
        this.output = [this.output.join("").slice(-OUTPUT_LIMIT)];
      }
    };
    child.stdout.on("data", capture);
    child.stderr.on("data", capture);
    try {
      await launched;
      await this.waitUntilReady(port);
      this.port = port;
    } catch (error) {
      await this.stopChild();
      throw error;
    }
  }

  outputText() {
    return this.output.join("").trim();
  }

  async waitUntilReady(port) {
    const origin = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline) {
      if (this.child.exitCode !== null || this.child.signalCode !== null) {
        throw new Error(
          `oxaudit-server exited during startup (exit ${this.child.exitCode ?? this.child.signalCode}):\n${this.outputText()}`,
        );
      }
      try {
        const env = await fetch(`${origin}/env.js`, { signal: AbortSignal.timeout(1500) });
        if (env.ok) {
          // The API must refuse unauthenticated calls before we call it ready.
          const api = await fetch(`${origin}/api/invoke/list_compiled_grammars`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: "{}",
            signal: AbortSignal.timeout(1500),
          });
          if (api.status === 401) return;
        }
      } catch {
        // keep polling until the listener is up
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error(`oxaudit-server did not become ready at ${origin}:\n${this.outputText()}`);
  }

  async stopChild() {
    const child = this.child;
    this.child = null;
    if (!child || child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return;
    const closed = once(child, "close");
    const forceKill = setTimeout(() => child.kill("SIGKILL"), 8000);
    forceKill.unref();
    child.kill("SIGTERM");
    try {
      await closed;
    } finally {
      clearTimeout(forceKill);
    }
  }

  /** Real process restart against the same data/config directories and port. */
  async restart() {
    await this.stopChild();
    this.output = [];
    await this.start();
  }

  /** Copy one inert pilot fixture variant into an isolated temp project. */
  async materializePilotProject(variant, name) {
    const directory = path.join(this.root, name);
    await mkdir(directory, { recursive: true });
    await copyFile(
      path.join(fixturesRoot, variant, "handler.js"),
      path.join(directory, "handler.js"),
    );
    return directory;
  }

  /** A valid npm lockfile whose inventory is exactly the root package. */
  async materializeEmptyLockfileProject(name) {
    const directory = path.join(this.root, name);
    await mkdir(directory, { recursive: true });
    await writeFile(
      path.join(directory, "package-lock.json"),
      `${JSON.stringify(
        {
          name,
          version: "0.0.0",
          lockfileVersion: 3,
          requires: true,
          packages: { "": { name, version: "0.0.0" } },
        },
        null,
        2,
      )}\n`,
    );
    return directory;
  }

  async logFiles() {
    const files = [];
    const logs = path.join(this.dataDir, "logs");
    if (!existsSync(logs)) return files;
    for (const entry of await readdir(logs)) {
      const file = path.join(logs, entry);
      try {
        files.push({ name: entry, body: await readFile(file, "utf8") });
      } catch {
        // a log that cannot be read is not worth failing teardown over
      }
    }
    return files;
  }

  /** Stop everything; on failure keep diagnostics as test artifacts; always clean temp. */
  async dispose(testInfo) {
    try {
      await this.stopChild();
    } finally {
      await this.proxy.stop().catch(() => {});
    }
    const failed = testInfo && testInfo.status !== "passed" && testInfo.status !== "skipped";
    if (failed) {
      const summary = [
        `binary: ${this.binary}`,
        `origin: ${this.origin}`,
        `data-dir: ${this.dataDir}`,
        `config-dir: ${this.configDir}`,
      ].join("\n");
      await testInfo
        .attach("backend-summary.txt", { contentType: "text/plain", body: summary })
        .catch(() => {});
      if (this.outputText()) {
        await testInfo
          .attach("backend-process-output.txt", { contentType: "text/plain", body: this.outputText() })
          .catch(() => {});
      }
      if (this.proxy.requests.length > 0) {
        await testInfo
          .attach("refused-enrichment-requests.txt", {
            contentType: "text/plain",
            body: this.proxy.requests.join("\n"),
          })
          .catch(() => {});
      }
      for (const log of await this.logFiles()) {
        await testInfo
          .attach(`backend-log-${log.name}`, {
            contentType: "text/plain",
            body: log.body.slice(-OUTPUT_LIMIT),
          })
          .catch(() => {});
      }
    }
    await rm(this.root, { recursive: true, force: true });
  }
}

const test = base.extend({
  backend: async ({}, use, testInfo) => {
    const backend = await Backend.create();
    try {
      await use(backend);
    } finally {
      await backend.dispose(testInfo);
    }
  },
});

/** Fill the server access gate and land in the authenticated workbench. */
async function connectThroughGate(page, backend) {
  await page.goto(backend.origin);
  const gate = page.getByRole("dialog");
  await expect(gate.getByRole("heading", { name: "Server access token" })).toBeVisible();
  await gate.getByLabel("Access token").fill(backend.token);
  await gate.getByRole("button", { name: "Connect" }).click();
  await expect(page.locator('aside[aria-label="Primary navigation"]')).toBeVisible();
}

/** Dismiss the first-launch wizard without configuring anything. */
async function skipReadinessWizard(page) {
  const title = page.locator("#readiness-wizard-title");
  await expect(title).toBeVisible();
  await page.getByRole("button", { name: "Skip for now" }).click();
  await expect(title).toHaveCount(0);
}

/** The value cell of a summary metric such as "Files" or "Vulnerabilities". */
function metric(scope, label) {
  return scope.locator(`div:has(> p:text-is("${label}")) > p`).nth(1);
}

/**
 * Hold matching /api/invoke/{cmd} requests until released. `matcher` receives
 * the Playwright request (JSON body available via postDataJSON). Always call
 * `dispose()` in a finally block so live requests settle even on failure.
 */
function holdInvokes(page, cmd, { limit = 8, matcher } = {}) {
  const url = `**/api/invoke/${cmd}`;
  const held = [];
  let released = false;
  const handler = async (route) => {
    if (released || held.length >= limit || (matcher && !matcher(route.request()))) {
      await route.continue().catch(() => {});
      return;
    }
    const gate = Promise.withResolvers();
    held.push({ route, gate });
    await gate.promise;
    await route.continue().catch(() => {});
  };
  const ready = page.route(url, handler);
  return {
    ready,
    async waitForHeld(count = 1, timeoutMs = 15_000) {
      await expect.poll(() => held.length, { timeout: timeoutMs }).toBeGreaterThanOrEqual(count);
      return held.length;
    },
    heldCount: () => held.length,
    /** Resolve every held request; afterwards await an observable outcome. */
    release() {
      released = true;
      for (const entry of held.splice(0)) entry.gate.resolve();
    },
    async dispose() {
      released = true;
      for (const entry of held.splice(0)) entry.gate.resolve();
      await ready.then(() => page.unroute(url, handler)).catch(() => {});
    },
  };
}

/** Fail the first matching invoke with an explicit transport error, then pass through. */
function failFirstInvoke(page, cmd, { status = 503, body = "transient transport failure" } = {}) {
  const url = `**/api/invoke/${cmd}`;
  let failed = false;
  let handler;
  const ready = page.route(
    url,
    (handler = async (route) => {
      if (failed) {
        await route.continue().catch(() => {});
        return;
      }
      failed = true;
      await route.fulfill({ status, contentType: "text/plain", body }).catch(() => {});
    }),
  );
  return {
    ready,
    async dispose() {
      await ready.then(() => page.unroute(url, handler)).catch(() => {});
    },
  };
}

export {
  test,
  expect,
  Backend,
  fixturesRoot,
  connectThroughGate,
  skipReadinessWizard,
  metric,
  holdInvokes,
  failFirstInvoke,
};
