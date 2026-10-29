import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { CveDossier } from "./CveDossier";
import { useAppStore } from "../lib/stores";
import type { AiReadinessStatus } from "../lib/settingsRequests";
import type { CveDetail, CveItem } from "../lib/types";

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

function makeDetail(item: Partial<CveItem> = {}, rest: Partial<Omit<CveDetail, "item">> = {}): CveDetail {
  return {
    item: {
      id: "CVE-2024-3094",
      severity: "CRITICAL",
      cvssScore: 10,
      description: "Malicious code was discovered in the upstream tarballs of xz.",
      published: "2024-03-29T17:15:00Z",
      modified: "2024-04-01T00:00:00Z",
      affectedProducts: ["tukaani:xz:5.6.0"],
      references: ["https://www.openwall.com/lists/oss-security/2024/03/29/4"],
      cwes: ["CWE-506"],
      epss: 0.8512,
      epssPercentile: 0.99,
      knownExploited: true,
      ransomware: false,
      ...item,
    },
    raw: { id: item.id ?? "CVE-2024-3094" },
    osv: { id: item.id ?? "CVE-2024-3094" },
    ...rest,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function renderDossier(
  props: Partial<{
    detail: CveDetail | null;
    loading: boolean;
    aiReadiness: AiReadinessStatus;
    onOpenUrl: (url: string) => Promise<void>;
    onGenerateBriefing: () => Promise<string | null>;
  }> = {},
) {
  const onOpenUrl = props.onOpenUrl ?? vi.fn().mockResolvedValue(undefined);
  const onGenerateBriefing = props.onGenerateBriefing ?? vi.fn().mockResolvedValue("Briefing");
  const merged = {
    detail: props.detail === undefined ? makeDetail() : props.detail,
    loading: props.loading ?? false,
    aiReadiness: props.aiReadiness ?? ("ready" as AiReadinessStatus),
    onOpenUrl,
    onGenerateBriefing,
  };
  const user = userEvent.setup();
  const view = render(<CveDossier {...merged} />);
  const rerender = (next: Partial<typeof merged>) =>
    view.rerender(<CveDossier {...merged} {...next} />);
  return { ...view, rerender, user, onOpenUrl, onGenerateBriefing };
}

describe("CveDossier", () => {
  beforeEach(() => {
    useAppStore.setState({ page: "dashboard", assistantHandoff: null });
  });

  test("shows a loading state while the record is fetched", () => {
    renderDossier({ loading: true });
    expect(screen.getByRole("status")).toHaveTextContent("Loading CVE details");
    expect(screen.queryByRole("heading", { name: "CVE-2024-3094" })).not.toBeInTheDocument();
  });

  test("asks for a selection when there is no detail", () => {
    renderDossier({ detail: null });
    expect(screen.getByRole("status")).toHaveTextContent("Select a CVE result");
    expect(screen.queryByRole("button", { name: /Discuss in Assistant/ })).not.toBeInTheDocument();
  });

  test("shows CVSS, KEV exploitation and EPSS chips", () => {
    renderDossier();
    const overview = screen.getByRole("region", { name: "CVE-2024-3094" });
    expect(within(overview).getByText("CVSS 10.0")).toBeInTheDocument();
    const kev = within(overview).getByText("KEV · exploited");
    expect(kev).toHaveAttribute("title", expect.stringMatching(/exploited in the wild/));
    const epss = within(overview).getByText("EPSS 85.1%");
    expect(epss).toHaveAttribute("title", expect.stringMatching(/99th percentile/));
    expect(within(overview).getByText("CWE-506")).toBeInTheDocument();
    expect(within(overview).getByText("tukaani:xz:5.6.0")).toBeInTheDocument();
  });

  test("flags ransomware use in the KEV chip", () => {
    renderDossier({ detail: makeDetail({ ransomware: true }) });
    const kev = screen.getByText("KEV · ransomware");
    expect(kev).toHaveAttribute("title", expect.stringMatching(/ransomware campaigns/));
  });

  test("omits KEV, EPSS and CVSS chips when the data is absent", () => {
    renderDossier({
      detail: makeDetail({ knownExploited: false, epss: null, epssPercentile: null, cvssScore: null }),
    });
    expect(screen.queryByText(/^KEV/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^EPSS/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^CVSS/)).not.toBeInTheDocument();
  });

  test("Discuss in Assistant hands the dossier to the assistant page", async () => {
    const { user } = renderDossier();
    await user.click(screen.getByRole("button", { name: "Discuss in Assistant" }));

    const state = useAppStore.getState();
    expect(state.page).toBe("assistant");
    const handoff = state.assistantHandoff!;
    expect(handoff.label).toBe("CVE dossier: CVE-2024-3094");
    expect(handoff.projectPath).toBeNull();
    expect(handoff.id).toEqual(expect.any(String));
    expect(handoff.content).toContain("CVE: CVE-2024-3094");
    expect(handoff.content).toContain("Malicious code was discovered in the upstream tarballs of xz.");
    expect(handoff.content).toContain("In CISA KEV — exploited in the wild; EPSS 85.1%");
    expect(handoff.content).toContain("CVSS: 10.0");
    expect(handoff.content).toContain("https://www.openwall.com/lists/oss-security/2024/03/29/4");
  });

  test("Open NVD, references and Open OSV open the matching URLs", async () => {
    const { user, onOpenUrl } = renderDossier();
    await user.click(screen.getByRole("button", { name: "Open NVD" }));
    expect(onOpenUrl).toHaveBeenLastCalledWith("https://nvd.nist.gov/vuln/detail/CVE-2024-3094");

    // References are shown without the scheme but open the full URL.
    await user.click(
      screen.getByRole("button", { name: "www.openwall.com/lists/oss-security/2024/03/29/4" }),
    );
    expect(onOpenUrl).toHaveBeenLastCalledWith("https://www.openwall.com/lists/oss-security/2024/03/29/4");

    await user.click(screen.getByRole("button", { name: "Open OSV" }));
    expect(onOpenUrl).toHaveBeenLastCalledWith("https://osv.dev/vulnerability/CVE-2024-3094");
    expect(onOpenUrl).toHaveBeenCalledTimes(3);
  });

  test("disables Open OSV and explains why when no OSV record is loaded", async () => {
    const { user, onOpenUrl } = renderDossier({ detail: makeDetail({ references: [] }, { osv: null }) });
    const osv = screen.getByRole("button", { name: "Open OSV" });
    expect(osv).toBeDisabled();
    expect(screen.getByText(/No OSV record is loaded/)).toBeInTheDocument();
    expect(screen.getByText(/No external references were returned/)).toBeInTheDocument();
    await user.click(osv);
    expect(onOpenUrl).not.toHaveBeenCalled();
  });

  test("renders a generated briefing as markdown and offers to regenerate", async () => {
    const onGenerateBriefing = vi.fn().mockResolvedValue("## Impact\n\nA **backdoor** in liblzma.");
    const { user } = renderDossier({ onGenerateBriefing });
    await user.click(screen.getByRole("button", { name: "Generate briefing" }));

    expect(await screen.findByRole("heading", { name: "Impact" })).toBeInTheDocument();
    expect(screen.getByText("backdoor").tagName).toBe("STRONG");
    expect(screen.getByRole("button", { name: "Regenerate briefing" })).toBeEnabled();
    expect(onGenerateBriefing).toHaveBeenCalledOnce();
  });

  test("an empty briefing result is reported as a failure", async () => {
    const { user } = renderDossier({ onGenerateBriefing: vi.fn().mockResolvedValue(null) });
    await user.click(screen.getByRole("button", { name: "Generate briefing" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The AI briefing could not be generated.",
    );
    expect(screen.getByRole("button", { name: "Generate briefing" })).toBeEnabled();
  });

  test("shows progress and blocks repeat requests while generating", async () => {
    const pending = deferred<string | null>();
    const onGenerateBriefing = vi.fn(() => pending.promise);
    const { user } = renderDossier({ onGenerateBriefing });
    await user.click(screen.getByRole("button", { name: "Generate briefing" }));

    const button = screen.getByRole("button", { name: "Generating…" });
    expect(button).toBeDisabled();
    expect(screen.getByText("Generating an AI briefing…")).toBeInTheDocument();

    await act(async () => pending.resolve("Done."));
    expect(await screen.findByText("Done.")).toBeInTheDocument();
    expect(onGenerateBriefing).toHaveBeenCalledOnce();
  });

  test("discards a briefing that finishes after the selected CVE changed", async () => {
    const pending = deferred<string | null>();
    const { user, rerender } = renderDossier({ onGenerateBriefing: () => pending.promise });
    await user.click(screen.getByRole("button", { name: "Generate briefing" }));
    expect(screen.getByRole("button", { name: "Generating…" })).toBeDisabled();

    rerender({ detail: makeDetail({ id: "CVE-2021-44228", description: "Log4Shell" }) });
    expect(screen.getByRole("heading", { name: "CVE-2021-44228" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate briefing" })).toBeEnabled();

    await act(async () => pending.resolve("Briefing about xz, not Log4Shell."));
    expect(screen.queryByText("Briefing about xz, not Log4Shell.")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate briefing" })).toBeEnabled();
    expect(screen.queryByText("Generating an AI briefing…")).not.toBeInTheDocument();
  });

  test("discards a failure that arrives after the selected CVE changed", async () => {
    const pending = deferred<string | null>();
    const { user, rerender } = renderDossier({ onGenerateBriefing: () => pending.promise });
    await user.click(screen.getByRole("button", { name: "Generate briefing" }));

    rerender({ detail: makeDetail({ id: "CVE-2021-44228" }) });
    await act(async () => pending.reject(new Error("timeout for the old CVE")));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  test("clears a previous briefing when another CVE is selected", async () => {
    const { user, rerender } = renderDossier({
      onGenerateBriefing: vi.fn().mockResolvedValue("Old briefing"),
    });
    await user.click(screen.getByRole("button", { name: "Generate briefing" }));
    expect(await screen.findByText("Old briefing")).toBeInTheDocument();

    rerender({ detail: makeDetail({ id: "CVE-2021-44228" }) });
    expect(screen.queryByText("Old briefing")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate briefing" })).toBeInTheDocument();
  });

  test.each([
    ["loading", "Saved AI settings are still loading."],
    ["checking", "The newly persisted AI endpoint is still being checked."],
    ["unconfigured", "Configure an AI provider in Settings to generate a briefing."],
    ["offline", "The saved AI endpoint is offline. Review Settings before generating a briefing."],
    ["unavailable", "AI readiness could not be loaded. Review Settings before generating a briefing."],
    ["unsupported", "AI briefings are available in the oxAudit desktop app."],
  ] as const)("when AI readiness is %s, explains why and disables generation", async (status, message) => {
    const onGenerateBriefing = vi.fn();
    const { user } = renderDossier({ aiReadiness: status, onGenerateBriefing });
    expect(screen.getByText(message)).toBeInTheDocument();
    const button = screen.getByRole("button", { name: "Generate briefing" });
    expect(button).toBeDisabled();
    await user.click(button);
    expect(onGenerateBriefing).not.toHaveBeenCalled();
  });

  test("a ready AI shows no readiness message", () => {
    renderDossier({ aiReadiness: "ready" });
    expect(screen.queryByText(/Settings|still loading|desktop app/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate briefing" })).toBeEnabled();
  });
});
