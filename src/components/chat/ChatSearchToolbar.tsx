import { ChevronDown, ChevronUp, Search, X } from "lucide-react";
import { forwardRef, type KeyboardEvent } from "react";
import { Button, Input } from "../ui";

interface ChatSearchToolbarProps {
  query: string;
  current: number;
  total: number;
  onQueryChange: (query: string) => void;
  onNext: () => void;
  onPrevious: () => void;
  onClose: () => void;
}

export const ChatSearchToolbar = forwardRef<HTMLInputElement, ChatSearchToolbarProps>(
  function ChatSearchToolbar(
    { query, current, total, onQueryChange, onNext, onPrevious, onClose },
    ref,
  ) {
    const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      } else if (event.key === "Enter") {
        event.preventDefault();
        if (event.shiftKey) onPrevious();
        else onNext();
      }
    };

    return (
      <div
        role="search"
        aria-label="Search conversation"
        className="flex items-center gap-1.5 border-b border-border bg-surface-secondary px-3 py-2"
      >
        <Search size={14} aria-hidden="true" className="shrink-0 text-text-muted" />
        <Input
          ref={ref}
          type="search"
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Search this conversation"
          aria-label="Search this conversation"
          className="h-7 min-w-0 flex-1"
        />
        <span
          aria-live="polite"
          className="min-w-14 text-right font-mono text-[11px] tabular-nums text-text-muted"
        >
          {total > 0 ? `${current + 1} / ${total}` : "0 / 0"}
        </span>
        <Button
          variant="icon"
          size="sm"
          onClick={onPrevious}
          disabled={total === 0}
          aria-label="Previous match"
          title="Previous match (Shift+Enter)"
        >
          <ChevronUp size={14} aria-hidden="true" />
        </Button>
        <Button
          variant="icon"
          size="sm"
          onClick={onNext}
          disabled={total === 0}
          aria-label="Next match"
          title="Next match (Enter)"
        >
          <ChevronDown size={14} aria-hidden="true" />
        </Button>
        <Button
          variant="icon"
          size="sm"
          onClick={onClose}
          aria-label="Close conversation search"
        >
          <X size={14} aria-hidden="true" />
        </Button>
      </div>
    );
  },
);
