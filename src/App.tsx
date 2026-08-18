import { useEffect } from "react";
import { Toasts } from "./components/Toasts";
import { AppShell } from "./components/workbench/AppShell";
import { api } from "./lib/api";
import {
  persistedAiReadiness,
  persistedSettingsRequests,
} from "./lib/settingsRequests";
import { useAppStore } from "./lib/stores";
import { Dashboard } from "./pages/Dashboard";
import { SourceScanPage } from "./pages/SourceScan";
import { DepsScanPage } from "./pages/DepsScan";
import { CveResearchPage } from "./pages/CveResearch";
import { AssistantPage } from "./pages/Assistant";
import { SettingsPage } from "./pages/SettingsPage";

function Page() {
  const page = useAppStore((s) => s.page);
  switch (page) {
    case "dashboard":
      return <Dashboard />;
    case "source-scan":
      return <SourceScanPage />;
    case "deps-scan":
      return <DepsScanPage />;
    case "cve-research":
      return <CveResearchPage />;
    case "assistant":
      return <AssistantPage />;
    case "settings":
      return <SettingsPage />;
  }
}

export default function App() {
  const setSettings = useAppStore((s) => s.setSettings);
  const setAiReady = useAppStore((s) => s.setAiReady);
  const setSettingsLoadError = useAppStore((s) => s.setSettingsLoadError);

  useEffect(() => {
    let mounted = true;
    const token = persistedSettingsRequests.begin();

    void (async () => {
      try {
        const settings = await api.loadSettings();
        if (!mounted || !persistedSettingsRequests.isCurrent(token)) return;
        setSettingsLoadError(false);
        setSettings(settings);
        const ready = await persistedAiReadiness(settings);
        if (!mounted || !persistedSettingsRequests.isCurrent(token)) return;
        setAiReady(ready);
      } catch {
        if (!mounted || !persistedSettingsRequests.isCurrent(token)) return;
        setSettingsLoadError(true);
        setAiReady(null);
      }
    })();

    return () => {
      mounted = false;
      if (persistedSettingsRequests.isCurrent(token)) {
        persistedSettingsRequests.invalidate();
      }
    };
  }, [setSettings, setAiReady, setSettingsLoadError]);

  return (
    <AppShell>
      <Page />
      <Toasts />
    </AppShell>
  );
}
