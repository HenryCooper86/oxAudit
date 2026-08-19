import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen } from "lucide-react";
import { Button } from "./ui";

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
        className="selectable min-w-0 flex-1 rounded-sm border border-border bg-surface-secondary px-3 py-2 font-mono text-xs text-text-primary placeholder:text-text-muted disabled:cursor-not-allowed disabled:opacity-50"
      />
      <Button
        type="button"
        onClick={pick}
        disabled={disabled}
        variant="outline"
        size="md"
      >
        <FolderOpen size={14} aria-hidden="true" />
        {buttonLabel}
      </Button>
    </div>
  );
}
