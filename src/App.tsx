import { useEffect } from "react";
import { Toasts } from "./components/Toasts";
import { AppShell } from "./components/workbench/AppShell";
import { api } from "./lib/api";
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
    api
      .loadSettings()
      .then((s) => {
        setSettingsLoadError(false);
        setSettings(s);
        if (s.ai.enabled && s.ai.baseUrl) {
          return api
            .testAi()
            .then((status) => setAiReady(status.ok))
            .catch(() => setAiReady(false));
        }
        setAiReady(null);
      })
      .catch(() => {
        setSettingsLoadError(true);
        setAiReady(null);
      });
  }, [setSettings, setAiReady, setSettingsLoadError]);

  return (
    <AppShell>
      <Page />
      <Toasts />
    </AppShell>
  );
}
