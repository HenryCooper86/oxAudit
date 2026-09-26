import { lazy, Suspense, useEffect, useState } from "react";
import { ServerTokenGate } from "./components/ServerTokenGate";
import { serverMode, serverToken } from "./lib/transport";
import { Toasts } from "./components/Toasts";
import { CommandPalette } from "./components/workbench/CommandPalette";
import { ReadinessWizard } from "./components/onboarding/ReadinessWizard";
import { AppShell } from "./components/workbench/AppShell";
import { PageErrorBoundary } from "./components/workbench/PageErrorBoundary";
import { api } from "./lib/api";
import {
  loadingAiReadiness,
  persistedSettingsRequests,
  publishPersistedAiReadiness,
  unavailableAiReadiness,
} from "./lib/settingsRequests";
import { useAppStore } from "./lib/stores";
import { Dashboard } from "./pages/Dashboard";
import type { Page as PageName } from "./lib/workbench";

const SourceScanPage = lazy(() =>
  import("./pages/SourceScan").then((module) => ({ default: module.SourceScanPage })),
);
const HistoryScanPage = lazy(() =>
  import("./pages/HistoryScan").then((module) => ({ default: module.HistoryScanPage })),
);
const DepsScanPage = lazy(() =>
  import("./pages/DepsScan").then((module) => ({ default: module.DepsScanPage })),
);
const BinaryScanPage = lazy(() =>
  import("./pages/BinaryScan").then((module) => ({ default: module.BinaryScanPage })),
);
const ImageScanPage = lazy(() =>
  import("./pages/ImageScanPage").then((module) => ({ default: module.ImageScanPage })),
);

const AdvisoryDatabasePage = lazy(() =>
  import("./pages/AdvisoryDatabase").then((module) => ({ default: module.AdvisoryDatabasePage })),
);

const VexTrustPage = lazy(() =>
  import("./pages/VexTrust").then((module) => ({ default: module.VexTrustPage })),
);

const InventoryPage = lazy(() =>
  import("./pages/Inventory").then((module) => ({ default: module.InventoryPage })),
);
const RuleLibraryPage = lazy(() =>
  import("./pages/RuleLibrary").then((module) => ({ default: module.RuleLibraryPage })),
);
const QualityLabPage = lazy(() =>
  import("./pages/QualityLab").then((module) => ({ default: module.QualityLabPage })),
);
const DataSourcesPage = lazy(() =>
  import("./pages/DataSources").then((module) => ({ default: module.DataSourcesPage })),
);
const ExportCenterPage = lazy(() =>
  import("./pages/ExportCenter").then((module) => ({ default: module.ExportCenterPage })),
);
const VerificationPage = lazy(() =>
  import("./pages/Verification").then((module) => ({ default: module.VerificationPage })),
);
const ComplianceCenterPage = lazy(() =>
  import("./pages/ComplianceCenter").then((module) => ({ default: module.ComplianceCenterPage })),
);
const ReportStudioPage = lazy(() =>
  import("./pages/ReportStudio").then((module) => ({ default: module.ReportStudioPage })),
);
const CveResearchPage = lazy(() =>
  import("./pages/CveResearch").then((module) => ({ default: module.CveResearchPage })),
);
const AssistantPage = lazy(() =>
  import("./pages/Assistant").then((module) => ({ default: module.AssistantPage })),
);
const SettingsPage = lazy(() =>
  import("./pages/SettingsPage").then((module) => ({ default: module.SettingsPage })),
);

const PortfolioPage = lazy(() =>
  import("./pages/Portfolio").then((module) => ({ default: module.PortfolioPage })),
);

function Page({ page }: { page: PageName }) {
  switch (page) {
    case "dashboard":
      return <Dashboard />;
    case "portfolio":
      return <PortfolioPage />;
    case "source-scan":
      return <SourceScanPage />;
    case "history-scan":
      return <HistoryScanPage />;
    case "deps-scan":
      return <DepsScanPage />;
    case "binary-scan":
      return <BinaryScanPage />;
    case "image-scan":
      return <ImageScanPage />;
    case "advisory-database":
      return <AdvisoryDatabasePage />;
    case "vex-trust":
      return <VexTrustPage />;
    case "inventory":
      return <InventoryPage />;
    case "rule-library":
      return <RuleLibraryPage />;
    case "quality-lab":
      return <QualityLabPage />;
    case "data-sources":
      return <DataSourcesPage />;
    case "export-center":
      return <ExportCenterPage />;
    case "verification":
      return <VerificationPage />;
    case "compliance-center":
      return <ComplianceCenterPage />;
    case "report-studio":
      return <ReportStudioPage />;
    case "cve-research":
      return <CveResearchPage />;
    case "assistant":
      return <AssistantPage />;
    case "settings":
      return <SettingsPage />;
  }
}

export default function App() {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const page = useAppStore((s) => s.page);
  const setPage = useAppStore((s) => s.setPage);
  const setSettings = useAppStore((s) => s.setSettings);
  const setAiReadiness = useAppStore((s) => s.setAiReadiness);
  const setSettingsLoadError = useAppStore((s) => s.setSettingsLoadError);

  useEffect(() => {
    let mounted = true;
    const token = persistedSettingsRequests.begin();
    setAiReadiness(loadingAiReadiness(token));

    void (async () => {
      try {
        const settings = await api.loadSettings();
        if (!mounted || !persistedSettingsRequests.isCurrent(token)) return;
        setSettingsLoadError(false);
        const readiness = publishPersistedAiReadiness(
          settings,
          token,
          setAiReadiness,
        );
        setSettings(settings);
        await readiness;
      } catch {
        if (!mounted || !persistedSettingsRequests.isCurrent(token)) return;
        setSettingsLoadError(true);
        setAiReadiness(unavailableAiReadiness(token));
      }
    })();

    return () => {
      mounted = false;
      if (persistedSettingsRequests.isCurrent(token)) {
        persistedSettingsRequests.invalidate();
      }
    };
  }, [setSettings, setAiReadiness, setSettingsLoadError]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      // Cmd on macOS, Ctrl elsewhere — matching the platform rather than
      // picking one and making half the users learn the other.
      if (event.key.toLowerCase() === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  if (serverMode && serverToken() === "") {
    // Nothing behind the gate can load without API access anyway.
    return <ServerTokenGate />;
  }

  return (
    <AppShell>
      <PageErrorBoundary
        resetKey={page}
        onReturnHome={() => setPage("dashboard")}
      >
        <Suspense
          fallback={
            <div className="p-6 text-[12px] text-text-muted" role="status">
              Loading workspace…
            </div>
          }
        >
          <Page page={page} />
        </Suspense>
      </PageErrorBoundary>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      <ReadinessWizard />
      <Toasts />
    </AppShell>
  );
}
