/**
 * Warm the lazily-imported route modules before an app-level test renders.
 *
 * App.tsx code-splits every page with React.lazy, so a test that renders the whole shell has
 * to wait for a dynamic import to resolve. On a loaded machine that resolution is slow and
 * variable, which made app-level suites flaky. Importing the modules first puts them in the
 * module cache, so React.lazy resolves on the first microtask and the tests assert behaviour
 * rather than timing. The lazy boundaries themselves are still exercised by the app.
 */
export async function preloadRoutes(): Promise<void> {
  await Promise.all([
    import("../pages/Dashboard"),
    import("../pages/Scans"),
    import("../pages/ScanDetail"),
    import("../pages/NewScan"),
    import("../pages/Policies"),
    import("../pages/Events"),
    import("../pages/Audit"),
    import("../pages/Exceptions"),
    import("../pages/Users"),
    import("../pages/System"),
  ]);
}
