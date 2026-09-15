import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

/**
 * Content-Security-Policy for the built app, injected as the first <meta> in <head> at build
 * time only: the dev server relies on inline scripts for React Fast Refresh, so it is not
 * applied there.
 *
 * The production bundle loads scripts, styles and fonts from its own origin and calls the API
 * on the same origin (the web server proxies /api). React and Recharts set styles through the
 * CSSOM, which `style-src 'self'` permits. A <meta> policy cannot express frame-ancestors or
 * reporting, so the serving layer should also send a CSP header.
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-src 'none'",
  "worker-src 'self'",
].join("; ");

function contentSecurityPolicyMeta(): Plugin {
  return {
    name: "warden:csp-meta",
    apply: "build",
    transformIndexHtml() {
      return [
        {
          tag: "meta",
          attrs: { "http-equiv": "Content-Security-Policy", content: CONTENT_SECURITY_POLICY },
          injectTo: "head-prepend",
        },
      ];
    },
  };
}

// Recharts and its private dependencies are only needed by chart views, so they get their own
// chunk that is fetched with the first route that renders a chart.
const CHART_PACKAGES =
  /[\\/]node_modules[\\/](recharts|recharts-scale|react-smooth|victory-vendor|d3-[a-z-]+|internmap|decimal\.js-light|eventemitter3|fast-equals|tiny-invariant|lodash|react-transition-group|dom-helpers|prop-types|react-is|clsx)[\\/]/;
const REACT_PACKAGES = /[\\/]node_modules[\\/](react|react-dom|scheduler|react-router|cookie|set-cookie-parser)[\\/]/;

// The dev server proxies /api to the backend so the browser sees a same-origin API, which keeps
// the httpOnly refresh cookie working without CORS in development.
export default defineConfig({
  plugins: [react(), contentSecurityPolicyMeta()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET || "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    // Keep fonts as files (never data: URIs) so the CSP can stay at font-src 'self'.
    assetsInlineLimit: (filePath) => (/\.(woff2?|ttf|otf)$/i.test(filePath) ? false : undefined),
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (CHART_PACKAGES.test(id)) return "charts";
          if (REACT_PACKAGES.test(id)) return "react-vendor";
          return undefined;
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
    restoreMocks: true,
    unstubGlobals: true,
  },
});
