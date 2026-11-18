import { CheckCircle2, FileCheck2, FileUp, FolderOpen, PackagePlus, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState, type JSX } from "react";
import { Button, Input, Select, Switch } from "../../components/ui";
import { Field } from "../../components/workbench/Field";
import { InlineState } from "../../components/workbench/InlineState";
import { ResultPagination } from "../../components/workbench/ResultPagination";
import { api } from "../../lib/api";
import { errorMessage } from "../../lib/commandError";
import { open } from "../../lib/dialog";
import { usePagination } from "../../lib/pagination";
import { useToastStore } from "../../lib/stores";
import { serverMode } from "../../lib/transport";
import type { InstalledSignaturePack, SignaturePackKind, SignaturePackPreview, SignaturePackProtocols, SignaturePackSkip } from "../../lib/types";

export const KIND_LABEL: Record<SignaturePackKind, string> = { yara: "YARA rules", nuclei: "Nuclei templates" };
const KIND_BADGE: Record<SignaturePackKind, string> = { yara: "YARA", nuclei: "Nuclei" };
const UNIT: Record<SignaturePackKind, [string, string]> = { yara: ["rule", "rules"], nuclei: ["template", "templates"] };
const PROTOCOLS: Array<keyof SignaturePackProtocols> = ["http", "dns", "tcp", "ssl", "file"];
const PACK_EXTENSIONS = ["yar", "yara", "yaml", "yml", "zip"];

export const COPYLEFT_NOTICE = "This pack stays in your local data directory; oxAudit does not redistribute it.";
/** GPL, AGPL and LGPL identifiers and their spelled-out names. */
export function looksCopyleft(license: string): boolean {
  return /(?:^|[^a-z])[al]?gpl|general public licen[cs]e/i.test(license);
}

const count = (value: number, kind: SignaturePackKind) => `${value.toLocaleString()} ${UNIT[kind][value === 1 ? 0 : 1]}`;
const formatBytes = (bytes: number) => bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KiB` : `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
const baseName = (path: string) => path.replace(/[\\/]+$/, "").split(/[\\/]/).pop()?.replace(/\.(zip|ya?ml|yara?)$/i, "") ?? "";

export function protocolSummary(protocols: SignaturePackProtocols | null): string | null {
  if (!protocols) return null;
  const parts = PROTOCOLS.filter(name => protocols[name] > 0).map(name => `${name} ${protocols[name].toLocaleString()}`);
  return parts.length ? parts.join(" · ") : "no supported protocol";
}

/** The DOM only ever holds one page of skipped files, however long the pack's list is. */
export function SkippedFiles({ skipped, label }: { skipped: SignaturePackSkip[]; label: string }): JSX.Element {
  const pagination = usePagination(skipped, 25);
  if (skipped.length === 0) return <p className="text-[11px] text-text-muted">No files or rules were skipped.</p>;
  return <div>
    <ul aria-label={label} className="divide-y divide-border rounded-md border border-border bg-surface-primary">
      {pagination.items.map((skip, index) => (
        <li key={`${pagination.start + index}`} className="px-3 py-2 text-[11px]">
          <span className="break-all font-mono text-text-primary">{skip.file}{skip.line ? `:${skip.line}` : ""}</span>
          <span className="mt-0.5 block text-text-muted">{skip.message}</span>
        </li>
      ))}
    </ul>
    {pagination.pageCount > 1 && <ResultPagination pagination={pagination} label={label} onPageChange={pagination.setPage} />}
  </div>;
}

function CopyleftNotice({ license }: { license: string }): JSX.Element | null {
  return looksCopyleft(license) ? <p role="note" className="mt-1 text-[11px] text-text-muted">{COPYLEFT_NOTICE}</p> : null;
}

/** Signature packs (YARA rules and Nuclei templates), separate from the declarative TOML packs. */
export function SignaturePacksSection(): JSX.Element {
  const push = useToastStore(state => state.push);
  const [kind, setKind] = useState<SignaturePackKind>("yara");
  const [path, setPath] = useState("");
  const [preview, setPreview] = useState<SignaturePackPreview | null>(null);
  const [previewKey, setPreviewKey] = useState<string | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [pickerError, setPickerError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [license, setLicense] = useState("");
  const [version, setVersion] = useState("");
  const [source, setSource] = useState("");
  const [authors, setAuthors] = useState("");
  const [attempted, setAttempted] = useState(false);
  const [packs, setPacks] = useState<InstalledSignaturePack[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      setPacks(await api.listSignaturePacks());
      setListError(null);
    } catch (cause) {
      setListError(errorMessage(cause));
    }
  };
  useEffect(() => { void refresh(); }, []);

  const invalidate = () => { setPreview(null); setPreviewKey(null); setImportError(null); setAttempted(false); };
  const changeKind = (next: SignaturePackKind) => { setKind(next); invalidate(); };
  const changePath = (next: string) => { setPath(next); setPickerError(null); invalidate(); };

  const choose = async (directory: boolean) => {
    setPickerError(null);
    try {
      const selected = await open(directory
        ? { directory: true, multiple: false, title: "Choose a signature pack folder" }
        : { directory: false, multiple: false, title: "Choose a signature pack file", filters: [{ name: "Signature pack", extensions: PACK_EXTENSIONS }] });
      if (typeof selected === "string" && selected) changePath(selected);
    } catch (cause) {
      setPickerError(errorMessage(cause));
    }
  };

  const inspect = async () => {
    const target = path.trim();
    if (!target || inspecting || installing) return;
    const key = `${kind}\n${target}`;
    setInspecting(true);
    invalidate();
    try {
      const result = await api.validateSignaturePack(kind, target);
      setPreview(result);
      setPreviewKey(key);
      setLicense(result.detectedLicense ?? "");
      setName(current => current || baseName(target));
    } catch (cause) {
      setImportError(errorMessage(cause));
    } finally {
      setInspecting(false);
    }
  };

  const current = preview !== null && previewKey === `${kind}\n${path.trim()}` ? preview : null;
  const nameError = attempted && !name.trim() ? "Enter a name for this pack." : undefined;
  const licenseError = attempted && !license.trim() ? "Enter the pack's licence before installing. oxAudit does not guess it." : undefined;

  const install = async () => {
    if (!current || installing) return;
    setAttempted(true);
    if (!name.trim() || !license.trim()) return;
    setInstalling(true);
    setImportError(null);
    try {
      const pack = await api.installSignaturePack({
        kind, path: path.trim(), name: name.trim(), license: license.trim(),
        ...(version.trim() ? { version: version.trim() } : {}),
        ...(source.trim() ? { source: source.trim() } : {}),
        ...(authors.trim() ? { authors: authors.trim() } : {}),
      });
      push("success", `Installed ${pack.name}. It is enabled for ${kind === "yara" ? "YARA Scan" : "Template Scan"}; past runs are unchanged.`);
      setPath(""); setName(""); setLicense(""); setVersion(""); setSource(""); setAuthors("");
      invalidate();
      await refresh();
    } catch (cause) {
      setImportError(errorMessage(cause));
    } finally {
      setInstalling(false);
    }
  };

  const toggle = async (pack: InstalledSignaturePack, enabled: boolean) => {
    try {
      await api.setSignaturePackEnabled(pack.id, enabled);
      await refresh();
    } catch (cause) {
      push("error", "The pack state could not be changed.");
      setListError(errorMessage(cause));
    }
  };

  const remove = async (pack: InstalledSignaturePack) => {
    try {
      await api.removeSignaturePack(pack.id);
      push("success", `Removed ${pack.name}. Past runs keep the results they already recorded.`);
      await refresh();
    } catch (cause) {
      push("error", "The pack could not be removed.");
      setListError(errorMessage(cause));
    }
  };

  const busy = inspecting || installing;
  const protocols = useMemo(() => current ? protocolSummary(current.protocols) : null, [current]);

  return <>
    <section aria-labelledby="signature-import-title" className="surface-card p-4">
      <h2 id="signature-import-title" className="text-[13px] font-semibold text-text-primary">Import signature rules</h2>
      <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-text-muted">
        Import YARA rules for YARA Scan or Nuclei templates for Template Scan, from a file, a folder, or a .zip. Inspecting reads the pack and shows what would run; nothing is installed until you confirm a licence. Compiled .yarc files cannot be imported.
      </p>
      <div className="mt-3 grid gap-3 sm:grid-cols-[12rem_minmax(0,1fr)]">
        <Field label="Pack kind" htmlFor="signature-kind">
          <Select id="signature-kind" value={kind} disabled={busy} onChange={event => changeKind(event.target.value as SignaturePackKind)}>
            <option value="yara">{KIND_LABEL.yara}</option>
            <option value="nuclei">{KIND_LABEL.nuclei}</option>
          </Select>
        </Field>
        <Field label={serverMode ? "Pack path on server" : "Pack file or folder"} htmlFor="signature-path"
          hint={serverMode ? "Paths refer to the server's filesystem. Type or paste a server path." : "Type a path, or choose a file or a folder."} error={pickerError ?? undefined}>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Input id="signature-path" value={path} disabled={busy} placeholder={serverMode ? "/data/rules" : "Path to rules"} className="min-w-0 flex-1 font-mono"
              onChange={event => changePath(event.target.value)} />
            {!serverMode && <>
              <Button variant="outline" disabled={busy} onClick={() => void choose(false)}><FileUp size={13} aria-hidden="true" />Choose file…</Button>
              <Button variant="outline" disabled={busy} onClick={() => void choose(true)}><FolderOpen size={13} aria-hidden="true" />Choose folder…</Button>
            </>}
          </div>
        </Field>
      </div>
      <div className="mt-3">
        <Button variant="outline" disabled={busy || !path.trim()} onClick={() => void inspect()}>
          <FileCheck2 size={13} aria-hidden="true" />{inspecting ? "Inspecting…" : "Inspect"}
        </Button>
      </div>
      {importError && <div className="mt-3"><InlineState compact tone="error" title="The pack could not be inspected or installed" description={importError} /></div>}
      {current && <div className="mt-3 space-y-3 rounded-md border border-border bg-surface-primary p-3" aria-label="Pack preview" role="group">
        <p className="inline-flex items-center gap-1 text-[12px] font-medium text-text-primary"><CheckCircle2 size={13} aria-hidden="true" className="text-success" />Inspected: {KIND_LABEL[current.kind]}</p>
        <dl className="grid gap-3 text-[12px] min-[700px]:grid-cols-4">
          <Fact label="Files" value={current.fileCount.toLocaleString()} />
          <Fact label={current.kind === "yara" ? "Rules that will run" : "Templates that will run"} value={current.ruleCount.toLocaleString()} />
          <Fact label="Ignored files" value={current.ignoredCount.toLocaleString()} />
          <Fact label="Total size" value={formatBytes(current.totalBytes)} />
          {protocols && <Fact label="Supported by protocol" value={protocols} />}
          {current.kind === "nuclei" && <Fact label="Not evaluated" value={`${current.notEvaluatedCount.toLocaleString()} (listed below; they will not run)`} />}
          <Fact label="Content SHA-256" value={current.contentSha256} mono wide />
        </dl>
        <details className="surface-card">
          <summary className="cursor-pointer px-3 py-2 text-[12px] font-medium text-text-primary">Skipped files and rules ({current.skipped.length.toLocaleString()})</summary>
          <div className="border-t border-border p-3"><SkippedFiles skipped={current.skipped} label="Skipped in this pack" /></div>
        </details>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name" htmlFor="signature-name" error={nameError}>
            <Input id="signature-name" value={name} disabled={installing} onChange={event => setName(event.target.value)} />
          </Field>
          <Field label="Licence" htmlFor="signature-license" error={licenseError}
            hint={current.detectedLicense ? `Detected from the pack's licence file: ${current.detectedLicense}. Confirm or correct it.` : "No licence file was recognised. Enter the licence the pack is distributed under (an SPDX identifier is best)."}>
            <Input id="signature-license" value={license} disabled={installing} onChange={event => setLicense(event.target.value)} />
          </Field>
          <Field label="Version (optional)" htmlFor="signature-version"><Input id="signature-version" value={version} disabled={installing} onChange={event => setVersion(event.target.value)} /></Field>
          <Field label="Source (optional)" htmlFor="signature-source"><Input id="signature-source" value={source} disabled={installing} placeholder="Where the pack came from" onChange={event => setSource(event.target.value)} /></Field>
          <Field label="Authors (optional)" htmlFor="signature-authors"><Input id="signature-authors" value={authors} disabled={installing} onChange={event => setAuthors(event.target.value)} /></Field>
        </div>
        <CopyleftNotice license={license} />
        <Button variant="primary" disabled={installing} onClick={() => void install()}>
          <PackagePlus size={13} aria-hidden="true" />{installing ? "Installing…" : "Install pack"}
        </Button>
      </div>}
    </section>

    <section aria-labelledby="signature-packs-title" className="overflow-hidden surface-card">
      <div className="border-b border-border px-4 py-3">
        <h2 id="signature-packs-title" className="text-[13px] font-semibold text-text-primary">Signature packs</h2>
        <p className="mt-1 text-[12px] text-text-muted">Enabled YARA packs apply to YARA Scan and enabled Nuclei packs to Template Scan. A pack whose stored files no longer match their recorded hashes is skipped with its reason. Packs stay in your local data directory.</p>
      </div>
      {listError && <div className="px-4 py-3"><InlineState compact tone="error" title="The signature pack store is unavailable" description={listError} /></div>}
      {packs && packs.length === 0 && <p className="px-4 py-4 text-[12px] text-text-muted">No signature packs installed. Inspect a rule file or folder above to install one.</p>}
      {packs && packs.length > 0 && <ul className="divide-y divide-border">
        {packs.map(pack => (
          <li key={pack.id} className="px-4 py-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="flex flex-wrap items-center gap-2 text-[13px] font-medium text-text-primary">
                  <span className="rounded-sm border border-border bg-surface-primary px-1.5 py-0.5 font-mono text-[10px] text-text-muted">{KIND_BADGE[pack.kind]}</span>
                  {pack.name}{pack.version && <span className="font-mono text-[10px] text-text-muted">v{pack.version}</span>}
                </p>
                <p className="mt-0.5 text-[11px] text-text-muted">
                  Licence {pack.license || "not recorded"} · {count(pack.ruleCount, pack.kind)} · {pack.fileCount.toLocaleString()} files
                  {pack.kind === "nuclei" && ` · ${pack.notEvaluatedCount.toLocaleString()} not evaluated`}
                  {pack.skipped.length > 0 && ` · ${pack.skipped.length.toLocaleString()} skipped`}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <Switch checked={pack.enabled} onChange={enabled => void toggle(pack, enabled)} label={`${pack.enabled ? "Applies to scans" : "Disabled"}: ${pack.name}`} />
                <Button variant="outline" aria-label={`Remove ${pack.name}`} onClick={() => void remove(pack)}><Trash2 size={13} aria-hidden="true" />Remove</Button>
              </div>
            </div>
            <CopyleftNotice license={pack.license} />
            <details className="mt-2 rounded-md border border-border bg-surface-primary">
              <summary className="cursor-pointer px-3 py-1.5 text-[12px] text-text-secondary">Details for {pack.name}</summary>
              <div className="space-y-2 border-t border-border p-3 text-[11px] text-text-muted">
                <p>Pack ID <span className="font-mono">{pack.id}</span> · installed {pack.installedAt}</p>
                {pack.source && <p>Source: <span className="break-all">{pack.source}</span></p>}
                {pack.authors && <p>Authors: {pack.authors}</p>}
                {pack.protocols && <p>Supported by protocol: {protocolSummary(pack.protocols)}</p>}
                <p className="break-all font-mono">SHA-256 {pack.contentSha256}</p>
                <SkippedFiles skipped={pack.skipped} label={`Skipped in ${pack.name}`} />
              </div>
            </details>
          </li>
        ))}
      </ul>}
    </section>
  </>;
}

function Fact({ label, value, mono = false, wide = false }: { label: string; value: string; mono?: boolean; wide?: boolean }): JSX.Element {
  return <div className={wide ? "min-[700px]:col-span-4" : undefined}>
    <dt className="text-[11px] font-semibold text-text-muted">{label}</dt>
    <dd className={`mt-1 break-all text-text-secondary ${mono ? "font-mono text-[11px]" : ""}`}>{value}</dd>
  </div>;
}
