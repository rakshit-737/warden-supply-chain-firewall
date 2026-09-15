// Self-hosted fonts (OFL-1.1, bundled from npm) so the app makes no third-party requests.
import "@fontsource/barlow/latin-400.css";
import "@fontsource/barlow/latin-500.css";
import "@fontsource/barlow/latin-600.css";
import "@fontsource/barlow-semi-condensed/latin-500.css";
import "@fontsource/barlow-semi-condensed/latin-600.css";
import "@fontsource-variable/jetbrains-mono/wght.css";
import "./index.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import App from "./App";
import { AuthProvider } from "./auth/AuthProvider";

const container = document.getElementById("root");
if (!container) throw new Error("Missing #root element.");

createRoot(container).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
