import { open } from "@tauri-apps/plugin-dialog";
import { FileUp, FolderOpen } from "lucide-react";
import { Button } from "./ui";
import { serverMode } from "../lib/transport";

export function FolderPicker({
  value,
  onChange,
  placeholder = "Choose a project folder…",
  disabled = false,
  buttonLabel = "Browse…",
  inputLabel = "Project folder",
  allowFiles = false,
}: {
  value: string;
  onChange: (path: string) => void;
  placeholder?: string;
  disabled?: boolean;
  buttonLabel?: string;
  inputLabel?: string;
  /** Also offer a file picker — binary scans target single images, not just trees. */
  allowFiles?: boolean;
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
  const pickFile = async () => {
    const file = await open({
      directory: false,
      multiple: false,
      title: "Select a file",
    });
    if (typeof file === "string" && file) {
      onChange(file);
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
      {!serverMode && (
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
      )}
      {!serverMode && allowFiles && (
        <Button
          type="button"
          onClick={pickFile}
          disabled={disabled}
          variant="outline"
          size="md"
        >
          <FileUp size={14} aria-hidden="true" />
          File…
        </Button>
      )}
    </div>
  );
}
