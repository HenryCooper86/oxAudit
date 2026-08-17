import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen } from "lucide-react";

export function FolderPicker({
  value,
  onChange,
  placeholder = "Choose a project folder…",
}: {
  value: string;
  onChange: (path: string) => void;
  placeholder?: string;
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
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="selectable flex-1 rounded-lg border border-ink-600 bg-ink-900 px-3 py-2 font-mono text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-teal-500/60"
      />
      <button
        onClick={pick}
        className="inline-flex items-center gap-2 rounded-lg border border-ink-600 bg-ink-750 px-3 py-2 text-xs font-medium text-slate-200 transition-colors hover:border-ink-500 hover:bg-ink-700"
      >
        <FolderOpen size={14} />
        Browse…
      </button>
    </div>
  );
}
