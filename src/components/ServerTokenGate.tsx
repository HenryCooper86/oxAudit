import { ShieldCheck } from "lucide-react";
import type { FormEvent } from "react";
import { useEffect, useState, type JSX } from "react";
import { Button, Input } from "./ui";
import { onUnauthorized, serverToken, setServerToken } from "../lib/transport";

/**
 * The headless server refuses every API call without its access token.
 * When the browser has none (or presents an expired one), this gate is all
 * the UI shows until a working token is stored — the app behind it cannot
 * render anything meaningful without API access.
 */
export function ServerTokenGate(): JSX.Element | null {
  const [value, setValue] = useState("");
  const [rejected, setRejected] = useState(() => serverToken() !== "");

  useEffect(() => {
    const release = onUnauthorized(() => {
      setRejected(true);
    });
    return release;
  }, []);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!value.trim()) return;
    setServerToken(value);
    // The transport fires unauthorized again if the token is wrong; on
    // success the next API call simply works. Reload clears stale module
    // state cheaply and deterministically.
    window.location.reload();
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="server-token-title"
      className="flex min-h-screen items-center justify-center bg-surface-primary p-6"
    >
      <form
        onSubmit={submit}
        className="w-full max-w-sm space-y-4 rounded-sm border border-border bg-surface-secondary p-5"
      >
        <div className="flex items-center gap-2">
          <ShieldCheck size={16} aria-hidden="true" className="text-accent" />
          <h1 id="server-token-title" className="text-[15px] font-semibold text-text-primary">
            Server access token
          </h1>
        </div>
        <p className="text-[12px] leading-relaxed text-text-secondary">
          This oxAudit server refuses API calls without its access token. It is
          printed by <code className="font-mono text-[11px]">oxaudit-server</code> on
          startup and stored beside its data directory.
        </p>
        {rejected && serverToken() !== "" && (
          <p role="alert" className="text-[12px] text-error">
            That token was rejected. Paste the current one and try again.
          </p>
        )}
        <Input
          aria-label="Access token"
          type="password"
          autoFocus
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="Paste the access token"
        />
        <div className="flex justify-end">
          <Button type="submit" variant="primary" size="md" disabled={!value.trim()}>
            Connect
          </Button>
        </div>
      </form>
    </div>
  );
}
