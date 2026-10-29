import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { CveDossier } from "./CveDossier";
import type { CveDetail } from "../lib/types";

const detail: CveDetail = {
  item: {
    id: "CVE-2024-0002",
    severity: "LOW",
    cvssScore: 2.0,
    description: "desc",
    published: null,
    modified: null,
    affectedProducts: [],
    references: [],
    cwes: [],
    epss: null,
    epssPercentile: null,
    knownExploited: false,
    ransomware: false,
  },
  raw: {},
  osv: null,
};

test("unsupported AI points to the desktop app, not the CLI", () => {
  render(
    <CveDossier detail={detail} loading={false} aiReadiness="unsupported" onOpenUrl={vi.fn()} onGenerateBriefing={vi.fn()} />,
  );
  expect(screen.getByText(/desktop app/i)).toBeInTheDocument();
  expect(screen.queryByText(/CLI/)).not.toBeInTheDocument();
});

test("a structured briefing failure shows its message", async () => {
  const { default: userEvent } = await import("@testing-library/user-event");
  render(
    <CveDossier
      detail={detail}
      loading={false}
      aiReadiness="ready"
      onOpenUrl={vi.fn()}
      onGenerateBriefing={() => Promise.reject({ code: "scanFailed", message: "Model refused", detail: null, retryable: true })}
    />,
  );
  await userEvent.click(screen.getByRole("button", { name: "Generate briefing" }));
  expect(await screen.findByText("Model refused")).toBeInTheDocument();
});
