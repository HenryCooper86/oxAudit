import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

/**
 * oxAudit exposes one command surface three ways:
 *
 *   1. the desktop app registers commands with Tauri's `generate_handler!`
 *      (src-tauri/src/lib.rs),
 *   2. the headless server resolves the same names in `dispatch`
 *      (src-tauri/src/server/dispatch.rs),
 *   3. the GUI calls them by string through `src/lib/api.ts`, which routes to
 *      whichever of the two is running.
 *
 * Nothing ties the three lists together at compile time. A command the GUI
 * calls but Tauri never registered fails only when a user clicks the button;
 * one the server forgot answers "Unknown command" only in the browser
 * workbench; a dead arm or registration (as `cancel_history_scan` was) is
 * attack surface nobody reviews. This test holds the three lists equal, with
 * every deliberate difference named below together with its reason.
 */

const ROOT = new URL("../", import.meta.url);
const read = (path: string) => readFileSync(new URL(path, ROOT), "utf8");

/**
 * Registered with Tauri and present in `dispatch`, but deliberately answered
 * with an error by the headless server. Each needs a reason; the test also
 * checks the server really refuses them, so a stale entry fails.
 */
const SERVER_REFUSED: Record<string, string> = {
  stream_chat: "The AI assistant's streaming engine is still wired to the Tauri app handle.",
  research_cve: "Runs through the same streaming assistant engine as stream_chat.",
  test_ai: "Exercises the assistant engine, which the headless server does not host yet.",
  test_ai_with: "Exercises the assistant engine, which the headless server does not host yet.",
  open_scan_finding: "Opens a file in the user's local editor, which needs the desktop app.",
};

/** Registered with Tauri, intentionally absent from `dispatch`. Name → reason. */
const TAURI_ONLY: Record<string, string> = {};

/** Served by `dispatch`, intentionally not registered with Tauri. Name → reason. */
const SERVER_ONLY: Record<string, string> = {};

const IDENT = /^[a-z][a-z0-9_]*$/;

/**
 * Blank out comments and the contents of string and char literals (keeping
 * their quotes and every offset), so brace matching and regexes below never
 * trip over a `{`, `]` or `"cmd" =>` that appears inside a literal or comment.
 * `keepStrings` leaves string literal contents in place.
 */
function maskRust(source: string, keepStrings = false): string {
  const out = source.split("");
  const blank = (from: number, to: number) => {
    for (let index = from; index < to; index += 1) if (out[index] !== "\n") out[index] = " ";
  };
  let index = 0;
  while (index < source.length) {
    const rest = source.slice(index, index + 2);
    if (rest === "//") {
      const end = source.indexOf("\n", index);
      const stop = end === -1 ? source.length : end;
      blank(index, stop);
      index = stop;
    } else if (rest === "/*") {
      let depth = 0;
      let cursor = index;
      while (cursor < source.length) {
        if (source.startsWith("/*", cursor)) {
          depth += 1;
          cursor += 2;
        } else if (source.startsWith("*/", cursor)) {
          depth -= 1;
          cursor += 2;
          if (depth === 0) break;
        } else cursor += 1;
      }
      blank(index, cursor);
      index = cursor;
    } else if (/^r#*"/.test(source.slice(index, index + 8)) && !/[A-Za-z0-9_]/.test(source[index - 1] ?? "")) {
      const hashes = source.slice(index + 1).match(/^#*/)![0];
      const open = index + 1 + hashes.length;
      const close = source.indexOf(`"${hashes}`, open + 1);
      const stop = close === -1 ? source.length : close + 1 + hashes.length;
      if (!keepStrings) blank(open + 1, stop - 1 - hashes.length);
      index = stop;
    } else if (source[index] === '"') {
      let cursor = index + 1;
      while (cursor < source.length && source[cursor] !== '"') cursor += source[cursor] === "\\" ? 2 : 1;
      if (!keepStrings) blank(index + 1, cursor);
      index = cursor + 1;
    } else if (source[index] === "'") {
      // A char literal ('x', '\n', '\u{1F600}') — otherwise a lifetime ('_, 'a).
      const char = source.slice(index).match(/^'(?:\\u\{[0-9a-fA-F]+\}|\\.|[^\\'\n])'/);
      if (char) {
        blank(index + 1, index + char[0].length - 1);
        index += char[0].length;
      } else index += 1;
    } else index += 1;
  }
  return out.join("");
}

/** Index of the bracket closing the one at `open`, in already-masked source. */
function closingBracket(masked: string, open: number): number {
  const pairs: Record<string, string> = { "(": ")", "[": "]", "{": "}" };
  const stack: string[] = [];
  for (let index = open; index < masked.length; index += 1) {
    const char = masked[index];
    if (pairs[char]) stack.push(pairs[char]);
    else if (char === ")" || char === "]" || char === "}") {
      assert.equal(char, stack.pop(), `unbalanced ${char} at offset ${index}`);
      if (stack.length === 0) return index;
    }
  }
  throw new Error(`unterminated bracket at offset ${open}`);
}

/**
 * `text[from, to)` with everything nested inside brackets blanked out, so only
 * the top level remains. Bracket depth is read from `masked`, so brackets
 * inside literals and comments never count.
 */
function topLevelOnly(masked: string, text: string, from: number, to: number): string {
  const out = text.slice(from, to).split("");
  let depth = 0;
  masked.slice(from, to).split("").forEach((char, index) => {
    const closes = char === ")" || char === "]" || char === "}";
    if (closes) depth -= 1;
    if (depth > 0 && char !== "\n") out[index] = " ";
    if (char === "(" || char === "[" || char === "{") depth += 1;
  });
  return out.join("");
}

function tauriCommands(): string[] {
  const path = "src-tauri/src/lib.rs";
  const masked = maskRust(read(path));
  const macro = masked.match(/generate_handler\s*!\s*([[({])/);
  assert.ok(macro?.index !== undefined, `${path}: no generate_handler! invocation found`);
  const open = macro.index + macro[0].length - 1;
  const body = masked.slice(open + 1, closingBracket(masked, open));
  const names = body
    .split(",")
    .map((entry) => entry.replace(/\s+/g, ""))
    .filter(Boolean)
    .map((path) => path.split("::").pop()!);
  for (const name of names) assert.match(name, IDENT, `${path}: unparseable handler entry \`${name}\``);
  return names;
}

interface DispatchArm {
  names: string[];
  refused: boolean;
}

function dispatchArms(): DispatchArm[] {
  const path = "src-tauri/src/server/dispatch.rs";
  const source = read(path);
  const masked = maskRust(source);
  const withStrings = maskRust(source, true);
  const fn = masked.match(/\bfn\s+dispatch\b/);
  assert.ok(fn?.index !== undefined, `${path}: no \`fn dispatch\` found`);
  const matchCmd = /\bmatch\s+cmd\s*\{/g;
  matchCmd.lastIndex = fn.index;
  const found = matchCmd.exec(masked);
  assert.ok(found, `${path}: \`dispatch\` has no \`match cmd { ... }\``);
  const open = found.index + found[0].length - 1;
  const close = closingBracket(masked, open);

  // Keep only the match's own level — arm patterns and `=>`, with their
  // string contents — so nested matches inside an arm body are invisible.
  const level = topLevelOnly(masked, withStrings, open + 1, close);
  const armPattern = /((?:"[^"\n]*"\s*\|\s*)*"[^"\n]*")\s*(?:if\b[^=]*)?=>/g;
  const heads = [...level.matchAll(armPattern)];
  return heads.map((head, index) => {
    const bodyStart = open + 1 + head.index! + head[0].length;
    const bodyEnd = index + 1 < heads.length ? open + 1 + heads[index + 1].index! : close;
    const body = masked.slice(bodyStart, bodyEnd).replace(/\s+/g, "");
    const names = [...head[1].matchAll(/"([^"]*)"/g)].map((match) => match[1]);
    for (const name of names) assert.match(name, IDENT, `${path}: unexpected arm pattern "${name}"`);
    return { names, refused: /^\{?Err\(disabled\(/.test(body) };
  });
}

/**
 * Command names the frontend sends. In api.ts every call goes through the
 * local `invoke` wrapper (or the transport it wraps); elsewhere in src/ a
 * component may call `httpInvoke` directly. Any call whose first argument is
 * not a string literal is an error, except the wrapper's own forwarding.
 */
function frontendCommands(): Map<string, string[]> {
  const callers = /\b(invoke|tauriInvoke|httpInvoke)\s*(?=[<(])/g;
  const forwarding = /^(cmd)\b/;
  const found = new Map<string, string[]>();
  const files = ["src/lib/api.ts", ...sourceFiles("src/")].filter(
    (file, index, all) => all.indexOf(file) === index,
  );
  for (const file of files) {
    const source = read(file);
    const isApi = file === "src/lib/api.ts";
    for (const call of source.matchAll(callers)) {
      if (!isApi && call[1] === "invoke") continue; // only api.ts owns the wrapper name
      let cursor = call.index! + call[0].length;
      // Skip a declaration (`function invoke<T>(cmd: string`) or import alias.
      const before = source.slice(Math.max(0, call.index! - 20), call.index!);
      if (/(function|as|export async function)\s+$/.test(before)) continue;
      if (source[cursor] === "<") {
        let depth = 0;
        for (; cursor < source.length; cursor += 1) {
          if (source[cursor] === "<") depth += 1;
          if (source[cursor] === ">" && --depth === 0) break;
        }
        cursor += 1;
      }
      const rest = source.slice(cursor).replace(/^\s*/, "");
      if (!rest.startsWith("(")) continue; // a type position, not a call
      const argument = rest.slice(1).replace(/^\s*/, "");
      const literal = argument.match(/^(["'`])([^"'`$\\]*)\1/);
      const line = source.slice(0, call.index!).split("\n").length;
      if (literal) {
        assert.match(literal[2], IDENT, `${file}:${line}: unexpected command name "${literal[2]}"`);
        const sites = found.get(literal[2]) ?? [];
        sites.push(`${file}:${line}`);
        found.set(literal[2], sites);
      } else {
        assert.ok(
          isApi && forwarding.test(argument),
          `${file}:${line}: ${call[1]}() is called with a computed command name; ` +
            "use a string literal so this parity check can see it",
        );
      }
    }
  }
  return found;
}

function sourceFiles(directory: string): string[] {
  return readdirSync(new URL(directory, ROOT), { withFileTypes: true }).flatMap((entry) => {
    const path = `${directory}${entry.name}`;
    if (entry.isDirectory()) return sourceFiles(`${path}/`);
    if (!/\.(ts|tsx)$/.test(entry.name) || /\.test\.tsx?$/.test(entry.name)) return [];
    return [path];
  });
}

const tauri = tauriCommands();
const arms = dispatchArms();
const served = arms.flatMap((arm) => arm.names);
const refused = arms.filter((arm) => arm.refused).flatMap((arm) => arm.names);
const frontend = frontendCommands();

const duplicates = (names: string[]) => names.filter((name, index) => names.indexOf(name) !== index);
const missing = (names: Iterable<string>, from: Set<string>) => [...names].filter((name) => !from.has(name)).sort();

test("each command list parses to a plausible, duplicate-free set", () => {
  // A parser that silently matches nothing would make every check below pass.
  assert.ok(tauri.length >= 50, `parsed only ${tauri.length} Tauri commands from generate_handler!`);
  assert.ok(served.length >= 50, `parsed only ${served.length} dispatch arms`);
  assert.ok(frontend.size >= 50, `parsed only ${frontend.size} frontend command names`);
  assert.deepEqual(duplicates(tauri), [], "a command is registered with Tauri twice");
  assert.deepEqual(duplicates(served), [], "a command has two dispatch arms");
});

test("every command the frontend invokes is registered with Tauri", () => {
  const registered = new Set(tauri);
  const unregistered = missing(frontend.keys(), registered).map(
    (name) => `${name} (${frontend.get(name)!.join(", ")})`,
  );
  assert.deepEqual(unregistered, [], "the GUI calls commands the desktop app never registered");
});

test("every Tauri command is dispatched by the headless server", () => {
  const dispatched = new Set([...served, ...Object.keys(TAURI_ONLY)]);
  assert.deepEqual(
    missing(tauri, dispatched),
    [],
    "add a dispatch arm (refuse it there and in SERVER_REFUSED if it cannot run headless)",
  );
});

test("every dispatch arm corresponds to a Tauri command", () => {
  const registered = new Set([...tauri, ...Object.keys(SERVER_ONLY)]);
  assert.deepEqual(missing(served, registered), [], "dispatch serves commands the desktop app does not");
});

test("the server refuses exactly the commands documented as refused", () => {
  assert.deepEqual(
    [...refused].sort(),
    Object.keys(SERVER_REFUSED).sort(),
    "update SERVER_REFUSED with a reason, or remove a command the server now serves",
  );
  for (const [name, reason] of Object.entries({ ...SERVER_REFUSED, ...TAURI_ONLY, ...SERVER_ONLY })) {
    assert.ok(reason.trim().length > 0, `${name} needs a reason`);
  }
});
