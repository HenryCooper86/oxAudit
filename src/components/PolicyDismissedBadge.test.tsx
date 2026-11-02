import { render, screen } from "@testing-library/react";
import { describe, expect, test } from "vitest";
import { PolicyDismissedBadge } from "./PolicyDismissedBadge";

describe("PolicyDismissedBadge", () => {
  test("shows a dismissed-by-policy badge with the reason", () => {
    render(
      <PolicyDismissedBadge
        review={{ state: "acceptedRisk", reason: "Build tooling only", expiresAt: "2027-01-31T00:00:00Z" }}
      />,
    );
    const badge = screen.getByText("Dismissed by policy");
    expect(badge.getAttribute("title")).toBe(
      "Accepted risk until 2027-01-31T00:00:00Z: Build tooling only. Reported, but does not fail the build.",
    );
  });

  test("names false positives and suppressions", () => {
    render(<PolicyDismissedBadge review={{ state: "falsePositive", reason: "Not reachable" }} />);
    expect(screen.getByText("Dismissed by policy").getAttribute("title")).toBe(
      "False positive: Not reachable. Reported, but does not fail the build.",
    );
  });

  test("renders nothing for an undismissed advisory", () => {
    const { container } = render(<PolicyDismissedBadge review={undefined} />);
    expect(container.textContent).toBe("");
  });
});

describe("PolicyDismissedBadge accessibility", () => {
  test("exposes the reason to assistive technology", () => {
    render(<PolicyDismissedBadge review={{ state: "acceptedRisk", reason: "Build tooling only" }} />);
    const badge = screen.getByLabelText("Dismissed by policy: Accepted risk, Build tooling only");
    expect(badge.textContent).toContain("Build tooling only");
  });
});
