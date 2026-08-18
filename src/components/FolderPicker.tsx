import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen } from "lucide-react";

export function FolderPicker({
  value,
  onChange,
  placeholder = "Choose a project folder…",
  disabled = false,
  buttonLabel = "Browse…",
  inputLabel = "Project folder",
}: {
  value: string;
  onChange: (path: string) => void;
  placeholder?: string;
  disabled?: boolean;
  buttonLabel?: string;
  inputLabel?: string;
}) {
  const pick = async () => {
    const dir = await open({
      directory: true,
      multiple: false,
      title: "Select a folder",
    });
    if (typeof dir === "string" && dir) {
      onChange(dir);
    }
  };
  return (
    <div className="flex items-center gap-2">
      <input
        aria-label={inputLabel}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className="selectable min-w-0 flex-1 rounded-md border border-ink-600 bg-ink-900 px-3 py-2 font-mono text-xs text-stone-200 placeholder:text-stone-600 disabled:cursor-not-allowed disabled:opacity-50"
      />
      <button
        type="button"
        onClick={pick}
        disabled={disabled}
        className="inline-flex shrink-0 items-center gap-2 rounded-md border border-ink-600 bg-ink-750 px-3 py-2 text-xs font-medium text-stone-200 transition-colors hover:border-ink-500 hover:bg-ink-700 disabled:cursor-not-allowed disabled:opacity-50"
      >
        <FolderOpen size={14} aria-hidden="true" />
        {buttonLabel}
      </button>
    </div>
  );
}
