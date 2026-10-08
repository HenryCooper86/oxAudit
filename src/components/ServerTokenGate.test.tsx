import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { ServerTokenGate } from "./ServerTokenGate";
import { setServerToken } from "../lib/transport";

afterEach(() => {
  vi.unstubAllGlobals();
  setServerToken("");
});

test("connecting works without persistent storage or a page reload", async () => {
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("Blocked", "SecurityError"); });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true, data: {} }))));
  const connected = vi.fn();
  render(<ServerTokenGate onConnected={connected} />);
  await userEvent.type(screen.getByLabelText("Access token"), "session-token");
  await userEvent.click(screen.getByRole("button", { name: "Connect" }));
  await waitFor(() => expect(connected).toHaveBeenCalledOnce());
  expect(fetch).toHaveBeenCalledWith("/api/invoke/list_compiled_grammars", expect.objectContaining({
    headers: expect.objectContaining({ authorization: "Bearer session-token" }),
  }));
});

test("rejected tokens keep the gate open and explain the failure", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 401 })));
  const connected = vi.fn();
  render(<ServerTokenGate onConnected={connected} />);
  await userEvent.type(screen.getByLabelText("Access token"), "bad-token");
  await userEvent.click(screen.getByRole("button", { name: "Connect" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/access token|rejected/i);
  expect(connected).not.toHaveBeenCalled();
});
