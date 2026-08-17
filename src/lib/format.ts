
export function severityColor(sev: string | null | undefined): string {
  switch (sev) {
    case "critical":
      return "text-red-400 border-red-500/40 bg-red-500/10";
    case "high":
      return "text-orange-400 border-orange-500/40 bg-orange-500/10";
    case "medium":
      return "text-amber-300 border-amber-400/40 bg-amber-400/10";
    case "low":
      return "text-yellow-200 border-yellow-300/40 bg-yellow-200/10";
    case "info":
      return "text-sky-300 border-sky-400/40 bg-sky-400/10";
    default:
      return "text-slate-400 border-slate-500/40 bg-slate-500/10";
  }
}

export function severityDot(sev: string | null | undefined): string {
  switch (sev) {
    case "critical":
      return "bg-red-500";
    case "high":
      return "bg-orange-500";
    case "medium":
      return "bg-amber-400";
    case "low":
      return "bg-yellow-200";
    case "info":
      return "bg-sky-400";
    default:
      return "bg-slate-500";
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
