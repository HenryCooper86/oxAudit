import { TargetInput } from "./workbench/TargetInput";

/** Compatibility wrapper for folder targets used outside the scan pages. */
export function FolderPicker({
  value, onChange, placeholder = "Choose a project folder…", disabled = false,
  buttonLabel, inputLabel = "Project folder", allowFiles = false,
}: {
  value: string;
  onChange(path: string): void;
  placeholder?: string;
  disabled?: boolean;
  buttonLabel?: string;
  inputLabel?: string;
  allowFiles?: boolean;
}) {
  return <TargetInput value={value} onChange={onChange} label={inputLabel} inputLabel={inputLabel}
    placeholder={placeholder} disabled={disabled} pickers={allowFiles ? ["file", "folder"] : ["folder"]}
    pickerLabels={buttonLabel ? { folder: buttonLabel } : undefined} />;
}
