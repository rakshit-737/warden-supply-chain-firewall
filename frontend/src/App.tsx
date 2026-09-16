import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router";
import type { ApiError } from "./api/client";
import { PLANNED_SECTIONS } from "./app/navigation";
import { useAuth } from "./auth/useAuth";
import { AppShell } from "./components/AppShell";
import { BrandMark } from "./components/BrandMark";
import { ErrorState } from "./components/ErrorState";
import { RequirePermission } from "./components/RequirePermission";
import { RouteErrorBoundary } from "./components/RouteErrorBoundary";
import { LoadingBlock } from "./components/Skeleton";

// Route-level code splitting: each page is its own chunk, fetched on first visit.
const Audit = lazy(() => import("./pages/Audit"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Events = lazy(() => import("./pages/Events"));
const Exceptions = lazy(() => import("./pages/Exceptions"));
const Login = lazy(() => import("./pages/Login"));
const NewScan = lazy(() => import("./pages/NewScan"));
const NotFound = lazy(() => import("./pages/NotFound"));
const Policies = lazy(() => import("./pages/Policies"));
const ScanDetail = lazy(() => import("./pages/ScanDetail"));
const Scans = lazy(() => import("./pages/Scans"));
const SectionUnavailable = lazy(() => import("./pages/SectionUnavailable"));
const SystemPage = lazy(() => import("./pages/System"));
const Users = lazy(() => import("./pages/Users"));

function FullScreenStatus({ label }: { label: string }) {
  return (
    <div className="mx-auto flex min-h-full max-w-sm flex-col justify-center px-4">
      <LoadingBlock label={label} rows={3} />
    </div>
  );
}

/** The session could not be checked at all; showing the sign-in form would wrongly suggest it ended. */
function SessionCheckFailed({ error, onRetry }: { error: ApiError; onRetry: () => void }) {
  const wait = error.retryAfterSeconds ?? null;
  return (
    <main className="mx-auto flex min-h-full max-w-md flex-col justify-center gap-6 px-4 py-10">
      <BrandMark size="lg" />
      <ErrorState
        title="Your session could not be checked"
        error={{
          ...error,
          message: wait ? `${error.message} The server asked to wait about ${wait} seconds.` : error.message,
        }}
        onRetry={onRetry}
      />
      <p className="text-ink-secondary">
        This is usually temporary: the Warden API could not be reached, or it asked for fewer requests.
      </p>
    </main>
  );
}

export default function App() {
  const { user, loading, restoreError, retryRestore } = useAuth();

  if (loading) return <FullScreenStatus label="Restoring your session" />;

  if (!user && restoreError) return <SessionCheckFailed error={restoreError} onRetry={retryRestore} />;

  if (!user) {
    return (
      <RouteErrorBoundary>
        <Suspense fallback={<FullScreenStatus label="Loading sign-in" />}>
          <Login />
        </Suspense>
      </RouteErrorBoundary>
    );
  }

  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Dashboard />} />
        <Route path="scans" element={<Scans />} />
        <Route path="scans/new" element={<NewScan />} />
        <Route path="scans/:id" element={<ScanDetail />} />
        {/* v1 address of the scan form. */}
        <Route path="scan" element={<Navigate to="/scans/new" replace />} />
        <Route path="policies" element={<Policies />} />
        <Route
          path="exceptions"
          element={
            <RequirePermission permission="policy:read">
              <Exceptions />
            </RequirePermission>
          }
        />
        {/* Both pages check their permission themselves (user:manage, system:read). */}
        <Route path="users" element={<Users />} />
        <Route path="system" element={<SystemPage />} />
        {/* Both pages check their permission themselves (event:read, audit:read). */}
        <Route path="events" element={<Events />} />
        <Route path="audit" element={<Audit />} />
        {PLANNED_SECTIONS.map((section) => (
          <Route
            key={section.path}
            path={section.path}
            element={
              <RequirePermission permission={section.permission}>
                <SectionUnavailable title={section.title} summary={section.summary} />
              </RequirePermission>
            }
          />
        ))}
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
