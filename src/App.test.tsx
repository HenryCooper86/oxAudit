import { render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

afterEach(() => {
  vi.unstubAllGlobals();
  delete window.OXAUDIT_SERVER;
  localStorage.clear();
});

it("returns to the token gate when the server rejects a saved token", async () => {
  vi.resetModules();
  window.OXAUDIT_SERVER = true;
  localStorage.setItem("oxaudit-server-token", "expired-token");
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("invalid access token", { status: 401 })));
  const { default: App } = await import("./App");
  render(<App />);
  expect(await screen.findByRole("dialog", { name: "Server access token" })).toBeInTheDocument();
  expect(screen.getByLabelText("Access token")).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("token was rejected");
});

it("shows the token gate before requesting settings when no token is saved", async () => {
  vi.resetModules();
  window.OXAUDIT_SERVER = true;
  const fetch = vi.fn().mockResolvedValue(new Response("missing access token", { status: 401 }));
  vi.stubGlobal("fetch", fetch);
  const { default: App } = await import("./App");
  render(<App />);
  expect(screen.getByRole("dialog", { name: "Server access token" })).toBeInTheDocument();
  expect(fetch).not.toHaveBeenCalled();
});
