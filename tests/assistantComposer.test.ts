import assert from "node:assert/strict";
import test from "node:test";
import {
  applyMode,
  CHAT_MODE_STORAGE_KEY,
  composerLayout,
  parseAttachedContext,
  PLAN_PREFIX,
  readChatMode,
  saveChatMode,
} from "../src/lib/assistantComposer";
import {
  ASSISTANT_PANEL_STORAGE_KEY,
  readAssistantPanel,
  saveAssistantPanel,
  toggleAssistantPanel,
} from "../src/lib/assistantPanels";

function memoryStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    values,
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => {
      values.set(key, value);
    },
  };
}

const throwing = {
  getItem: () => {
    throw new Error("denied");
  },
  setItem: () => {
    throw new Error("denied");
  },
};

test("auto mode sends the message unchanged", () => {
  assert.equal(applyMode("find the injection sinks", "auto"), "find the injection sinks");
});

test("plan mode prepends the planning instruction and keeps the message last", () => {
  const sent = applyMode("find the injection sinks", "plan");
  assert.ok(sent.startsWith("[Plan mode]"));
  assert.ok(sent.includes("step-by-step plan"));
  assert.equal(sent, `${PLAN_PREFIX}\n\nfind the injection sinks`);
  assert.ok(sent.endsWith("find the injection sinks"));
});

test("the composer mode is remembered, and anything unknown reads as Auto", () => {
  const storage = memoryStorage();
  assert.equal(readChatMode(storage), "auto");
  saveChatMode("plan", storage);
  assert.equal(storage.values.get(CHAT_MODE_STORAGE_KEY), "plan");
  assert.equal(readChatMode(storage), "plan");
  assert.equal(readChatMode(memoryStorage({ [CHAT_MODE_STORAGE_KEY]: "turbo" })), "auto");
  assert.equal(readChatMode(null), "auto");
  assert.equal(readChatMode(throwing), "auto");
  assert.doesNotThrow(() => saveChatMode("plan", throwing));
});

test("the composer starts at about three lines and grows to 40% of the window", () => {
  assert.deepEqual(composerLayout({ scrollHeight: 20, expanded: false, viewportHeight: 900 }), {
    height: 76,
    scroll: false,
  });
  assert.deepEqual(composerLayout({ scrollHeight: 200, expanded: false, viewportHeight: 900 }), {
    height: 200,
    scroll: false,
  });
  assert.deepEqual(composerLayout({ scrollHeight: 800, expanded: false, viewportHeight: 900 }), {
    height: 360,
    scroll: true,
  });
});

test("the expanded composer has a 200px floor and a 50% ceiling", () => {
  assert.deepEqual(composerLayout({ scrollHeight: 20, expanded: true, viewportHeight: 900 }), {
    height: 200,
    scroll: false,
  });
  assert.deepEqual(composerLayout({ scrollHeight: 800, expanded: true, viewportHeight: 900 }), {
    height: 450,
    scroll: true,
  });
  // A short window never pushes the ceiling below the floor.
  assert.deepEqual(composerLayout({ scrollHeight: 300, expanded: true, viewportHeight: 300 }), {
    height: 200,
    scroll: true,
  });
});

test("attached source context is recognised by the prefix Attach context writes", () => {
  assert.deepEqual(
    parseAttachedContext("[User-attached source context: Finding: SQLi [users.py]]\n\ncursor.execute(q)"),
    { label: "Finding: SQLi [users.py]", body: "cursor.execute(q)" },
  );
  assert.equal(parseAttachedContext("Is this exploitable?"), null);
  assert.equal(parseAttachedContext("[User-attached source context: x] no blank line"), null);
});

test("panels are mutually exclusive and closed unless one was remembered", () => {
  assert.equal(toggleAssistantPanel(null, "sessions"), "sessions");
  assert.equal(toggleAssistantPanel("sessions", "activity"), "activity");
  assert.equal(toggleAssistantPanel("activity", "activity"), null);

  const storage = memoryStorage();
  assert.equal(readAssistantPanel(storage), null);
  saveAssistantPanel("activity", storage);
  assert.equal(readAssistantPanel(storage), "activity");
  saveAssistantPanel(null, storage);
  assert.equal(storage.values.get(ASSISTANT_PANEL_STORAGE_KEY), "none");
  assert.equal(readAssistantPanel(storage), null);
  assert.equal(readAssistantPanel(throwing), null);
  assert.doesNotThrow(() => saveAssistantPanel("sessions", throwing));
});
