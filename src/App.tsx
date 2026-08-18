import { useEffect } from "react";
import { Toasts } from "./components/Toasts";
import { AppShell } from "./components/workbench/AppShell";
import { api } from "./lib/api";
import {
  loadingAiReadiness,
  persistedSettingsRequests,
  publishPersistedAiReadiness,
  unavailableAiReadiness,
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

  return (
    <AppShell>
      <Page />
      <Toasts />
    </AppShell>
  );
}
