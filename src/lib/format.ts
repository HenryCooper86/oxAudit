
export function severityColor(sev: string | null | undefined): string {
  switch (sev) {
    case "critical":
      return "text-sev-critical border-sev-critical-border bg-sev-critical-subtle";
    case "high":
      return "text-sev-high border-sev-high-border bg-sev-high-subtle";
    case "medium":
      return "text-sev-medium border-sev-medium-border bg-sev-medium-subtle";
    case "low":
      return "text-sev-low border-sev-low-border bg-sev-low-subtle";
    case "info":
      return "text-sev-info border-sev-info-border bg-sev-info-subtle";
    default:
      return "text-sev-unknown border-sev-unknown-border bg-sev-unknown-subtle";
  }
}

export function severityDot(sev: string | null | undefined): string {
  switch (sev) {
    case "critical":
      return "bg-sev-critical";
    case "high":
      return "bg-sev-high";
    case "medium":
      return "bg-sev-medium";
    case "low":
      return "bg-sev-low";
    case "info":
      return "bg-sev-info";
    default:
      return "bg-sev-unknown";
  }
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.round(s % 60)}s`;
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n) + "…";
}

export function basename(p: string): string {
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

export function dirname(p: string): string {
  const parts = p.split(/[\\/]/);
  parts.pop();
  return parts.join("/") || "/";
}

export function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}
