import { fireEvent, render, screen, within } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it } from "vitest";
import type { Finding } from "../../lib/types";
import { FindingList } from "./FindingList";
import { selectAll, selectRange, toggle, type Selection } from "./selectionModel";

function finding(index: number): Finding {
  return {
    id: `finding-${index}`, category: "vulnerability", ruleId: "test-rule", ruleName: `Rule ${index}`,
    severity: "high", title: "Finding", description: "Test finding", filePath: `src/file-${index}.ts`,
    line: 1, column: 1, matchText: "test", context: "test", language: "typescript", cwe: null,
    cweExploited: false, cweExploitedCount: 0, recommendation: "Review", entropy: null,
    verified: null, analysis: "text", analysisGates: [], observationRunId: "run", resolvedByRunId: null,
    fingerprintVersion: 1, fingerprint: `fp-${index}`, scope: "production", scopeReason: null,
    review: null, reviewHistory: [], diffStatus: "new",
  };
}

function Harness({ findings, initial = "fp-0" }: { findings: Finding[]; initial?: string | null }) {
  const [active, setActive] = useState<string | null>(initial);
  const [selection, setSelection] = useState<Selection>(new Set());
  const anchor = useRef<string | null>(null);
  return <>
    <button onClick={() => setSelection(selectAll(findings))}>Select all filtered findings</button>
    <output aria-label="Selected count">{selection.size}</output>
    <FindingList findings={findings} selectedFingerprint={active} onSelect={setActive}
      selection={selection} onToggleSelect={(fingerprint, extend) => {
        const from = anchor.current;
        setSelection(current => extend && from
          ? selectRange(current, findings, from, fingerprint) : toggle(current, fingerprint));
        anchor.current = fingerprint;
      }} />
  </>;
}

describe("bounded source findings", () => {
  it("renders a bounded page of 10,000 findings and reaches the last identity by keyboard", () => {
    const findings = Array.from({ length: 10_000 }, (_, index) => finding(index));
    const started = performance.now();
    render(<Harness findings={findings} />);
    const renderMs = performance.now() - started;
    const list = screen.getByRole("listbox", { name: "Findings" });
    expect(list.querySelectorAll('[role="option"]')).toHaveLength(50);
    const moved = performance.now();
    fireEvent.keyDown(list, { key: "End" });
    const endMs = performance.now() - moved;
    expect(list).toHaveAttribute("aria-activedescendant", "finding-fp-9999");
    expect(document.getElementById("finding-fp-9999")).toBeInTheDocument();
    expect(list.querySelectorAll('[role="option"]')).toHaveLength(50);
    fireEvent.keyDown(list, { key: "Home" });
    expect(document.getElementById("finding-fp-0")).toBeInTheDocument();
    console.info("result-list-measurement", JSON.stringify({ list: "source", records: 10_000, renderedRows: 50, renderMs, endMs, environment: "jsdom" }));
  });

  it("keeps keyboard range selection and select-all scoped to all filtered pages", () => {
    const findings = Array.from({ length: 120 }, (_, index) => finding(index));
    render(<Harness findings={findings} initial="fp-49" />);
    const list = screen.getByRole("listbox", { name: "Findings" });
    fireEvent.keyDown(list, { key: "x" });
    fireEvent.keyDown(list, { key: "j" });
    expect(document.getElementById("finding-fp-50")).toBeInTheDocument();
    fireEvent.keyDown(list, { key: "j" });
    fireEvent.keyDown(list, { key: "X", shiftKey: true });
    expect(screen.getByLabelText("Selected count")).toHaveTextContent("3");
    expect(screen.getByRole("checkbox", { name: "Select Rule 50 in src/file-50.ts" })).toBeChecked();
    fireEvent.keyDown(list, { key: "k" });
    fireEvent.keyDown(list, { key: "k" });
    expect(document.getElementById("finding-fp-49")).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "Select Rule 49 in src/file-49.ts" })).toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: "Select all filtered findings" }));
    expect(screen.getByLabelText("Selected count")).toHaveTextContent("120");
  });

  it("pages with accessible controls, preserves active descendants, and resets a changed filter", () => {
    const findings = Array.from({ length: 120 }, (_, index) => finding(index));
    const { rerender } = render(<Harness findings={findings} />);
    const list = screen.getByRole("listbox", { name: "Findings" });
    fireEvent.click(screen.getByRole("button", { name: "Next page of findings" }));
    expect(list).toHaveAttribute("aria-activedescendant", "finding-fp-50");
    expect(within(screen.getByRole("navigation")).getByRole("status")).toHaveTextContent("51–100 of 120");
    rerender(<Harness findings={findings.slice(0, 8)} />);
    expect(screen.getByRole("listbox").querySelectorAll('[role="option"]')).toHaveLength(8);
    expect(within(screen.getByRole("navigation")).getByRole("status")).toHaveTextContent("1–8 of 8");
    expect(list).not.toHaveAttribute("aria-activedescendant");
    expect(screen.getByRole("button", { name: "Next page of findings" })).toBeDisabled();
  });

  it("does not refer to an unmounted active row while a controlled selection waits for its caller", () => {
    const findings = Array.from({ length: 120 }, (_, index) => finding(index));
    render(<FindingList findings={findings} selectedFingerprint="fp-0" onSelect={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Next page of findings" }));
    const list = screen.getByRole("listbox");
    expect(document.getElementById("finding-fp-0")).not.toBeInTheDocument();
    expect(list).not.toHaveAttribute("aria-activedescendant");
  });
});
