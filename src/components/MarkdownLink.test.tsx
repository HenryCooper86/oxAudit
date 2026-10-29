import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";

const opener = vi.hoisted(() => ({ openUrl: vi.fn(async (_url: string) => {}) }));
vi.mock("../lib/opener", () => opener);

import { SearchableMarkdown } from "./chat/SearchHighlight";
import { CveDossier } from "./CveDossier";
import { safeMarkdownHref } from "./MarkdownLink";
import type { CveDetail } from "../lib/types";

beforeEach(() => opener.openUrl.mockClear());

describe("safeMarkdownHref", () => {
  test.each([
    ["https://example.com/a", "https://example.com/a"],
    ["http://example.com", "http://example.com/"],
    ["mailto:sec@example.com", "mailto:sec@example.com"],
  ])("allows %s", (input, expected) => {
    expect(safeMarkdownHref(input)).toBe(expected);
  });

  test.each(["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,hi", "file:///etc/passwd", "/settings", "#top", "", undefined])(
    "rejects %s",
    (input) => {
      expect(safeMarkdownHref(input)).toBeNull();
    },
  );
});

describe("AI markdown links", () => {
  test("open externally instead of navigating the app window", () => {
    render(<SearchableMarkdown content="See [the advisory](https://example.com/adv)." query="" />);
    const link = screen.getByRole("link", { name: "the advisory" });
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAttribute("target", "_blank");
    const notCancelled = fireEvent.click(link);
    expect(notCancelled).toBe(false);
    expect(opener.openUrl).toHaveBeenCalledWith("https://example.com/adv");
  });

  test("disallowed schemes render as inert text", () => {
    render(<SearchableMarkdown content="[click me](javascript:alert(1))" query="" />);
    expect(screen.queryByRole("link")).toBeNull();
    const text = screen.getByText("click me");
    fireEvent.click(text);
    expect(opener.openUrl).not.toHaveBeenCalled();
  });

  test("links in a CVE AI briefing open externally", async () => {
    const detail: CveDetail = {
      item: {
        id: "CVE-2024-0001",
        severity: "HIGH",
        cvssScore: 8.1,
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
    render(
      <CveDossier
        detail={detail}
        loading={false}
        aiReadiness="ready"
        onOpenUrl={vi.fn()}
        onGenerateBriefing={async () => "Patch per [vendor](https://vendor.example/fix)."}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /briefing/i }));
    const link = await screen.findByRole("link", { name: "vendor" });
    expect(fireEvent.click(link)).toBe(false);
    expect(opener.openUrl).toHaveBeenCalledWith("https://vendor.example/fix");
  });
});
