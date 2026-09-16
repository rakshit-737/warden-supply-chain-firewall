import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach } from "vitest";

// Route components are lazy-loaded, so app-level tests wait for a dynamic import to resolve.
// Testing Library's own async timeout (1s by default) is what bounds findBy*/waitFor - not
// vitest's testTimeout - and 1s is not enough on a loaded machine or a small CI runner.
configure({ asyncUtilTimeout: 30000 });

// Vitest runs without globals, so Testing Library cannot register its automatic cleanup.
afterEach(() => {
  cleanup();
});
