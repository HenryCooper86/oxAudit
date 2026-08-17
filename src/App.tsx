import { useEffect } from "react";
import { Sidebar } from "./components/Sidebar";
import { Toasts } from "./components/Toasts";
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

  useEffect(() => {
    api
      .loadSettings()
      .then((s) => {
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
        setAiReady(null);
      });
  }, [setSettings, setAiReady]);

  return (
    <div className="flex h-full overflow-hidden bg-ink-950">
      <Sidebar />
      <main className="min-w-0 flex-1 overflow-y-auto">
        <Page />
      </main>
      <Toasts />
    </div>
  );
}
