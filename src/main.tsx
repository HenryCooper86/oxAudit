import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import {
  applyResolvedTheme,
  readCachedThemePreference,
  resolveTheme,
  systemPrefersDark,
} from "./lib/theme";

// Paint with the last known theme before React mounts, so a light-theme user
// never sees a dark flash while settings load from disk.
applyResolvedTheme(resolveTheme(readCachedThemePreference(), systemPrefersDark()));

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
