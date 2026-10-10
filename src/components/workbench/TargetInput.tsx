import { open } from "@tauri-apps/plugin-dialog";
import { FileUp, FolderOpen } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { serverMode } from "../../lib/transport";
import { Button } from "../ui";

export type TargetPickerMode = "folder" | "file";

/** Choosing a target only updates the field; the containing page owns Start. */
export function TargetInput({
  value, onChange, label, inputLabel = label, placeholder, disabled = false,
  pickers = [], pickerLabels, hint, error,
}: {
  value: string;
  onChange(path: string): void;
  label: string;
  inputLabel?: string;
  placeholder?: string;
  disabled?: boolean;
  pickers?: readonly TargetPickerMode[];
  pickerLabels?: Partial<Record<TargetPickerMode, string>>;
  hint?: string;
  error?: string;
}) {
  const id = useId();
  const [pickerError, setPickerError] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);
  const available = useRef(!disabled);
  const mounted = useRef(true);
  const pickerGeneration = useRef(0);
  available.current = !disabled;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { pickerGeneration.current += 1; }, [disabled, value]);
  const description = [
    serverMode ? "Paths refer to the server's filesystem. Type or paste a server path." : "Type or paste a local path, or choose a target below.",
    hint,
  ].filter(Boolean).join(" ");
  const shownError = error || pickerError;

  const pick = async (mode: TargetPickerMode) => {
    if (disabled || picking) return;
    setPicking(true);
    setPickerError(null);
    const generation = pickerGeneration.current;
    try {
      const selected = await open({ directory: mode === "folder", multiple: false, title: `Select a ${mode}` });
      if (mounted.current && available.current && generation === pickerGeneration.current && typeof selected === "string" && selected) onChange(selected);
    } catch (cause) {
      if (mounted.current && available.current && generation === pickerGeneration.current) {
        const message = cause instanceof Error ? cause.message : String(cause);
        setPickerError(`Could not open the ${mode} picker. ${message} You can paste a path instead.`);
      }
    } finally {
      if (mounted.current) setPicking(false);
    }
  };

  return (
    <div className="min-w-0">
      <label htmlFor={id} className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">{label}</label>
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <input
          id={id}
          aria-label={inputLabel}
          aria-describedby={`${id}-hint${shownError ? ` ${id}-error` : ""}`}
          aria-invalid={error ? true : undefined}
          value={value}
          onChange={(event) => { pickerGeneration.current += 1; setPickerError(null); onChange(event.target.value); }}
          placeholder={placeholder}
          disabled={disabled}
          className="selectable min-w-0 basis-full rounded-sm border border-border bg-surface-secondary px-3 py-2 font-mono text-xs text-text-primary placeholder:text-text-muted disabled:cursor-not-allowed disabled:opacity-50 sm:basis-auto sm:flex-1"
        />
        {!serverMode && pickers.map((mode) => {
          const Icon = mode === "folder" ? FolderOpen : FileUp;
          return <Button key={mode} type="button" onClick={() => void pick(mode)} disabled={disabled || picking} variant="outline" size="md">
            <Icon size={14} aria-hidden="true" />{pickerLabels?.[mode] ?? `Choose ${mode}…`}
          </Button>;
        })}
      </div>
      <p id={`${id}-hint`} className="mt-1.5 text-[11px] leading-relaxed text-text-muted">{description}</p>
      {shownError && <p id={`${id}-error`} role="alert" className="mt-1.5 text-[12px] text-error">{shownError}</p>}
    </div>
  );
}
