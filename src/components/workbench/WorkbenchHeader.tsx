import { Menu } from "lucide-react";
import type { JSX } from "react";
import { useAppStore } from "../../lib/stores";
import { PAGE_META } from "../../lib/workbench";

export function WorkbenchHeader({
  onOpenNavigation,
}: {
  onOpenNavigation: () => void;
}): JSX.Element {
  const page = useAppStore((state) => state.page);
  const meta = PAGE_META[page];

  return (
    <header className="flex h-[52px] items-center gap-3 border-b border-ink-800 bg-ink-900 px-4">
      <button
        id="navigation-menu-button"
        type="button"
        aria-label="Open navigation"
        onClick={onOpenNavigation}
        className="hidden rounded p-1.5 text-stone-300 hover:bg-ink-800 hover:text-stone-100 max-[900px]:inline-flex"
      >
        <Menu aria-hidden="true" size={17} />
      </button>
      <div className="min-w-0 truncate text-[13px]">
        <span className="text-stone-400">{meta.group}</span>
        <span aria-hidden="true" className="px-2 text-stone-700">
          /
        </span>
        <span className="font-medium text-stone-200">{meta.title}</span>
      </div>
    </header>
  );
}
