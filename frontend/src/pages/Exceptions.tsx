import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { listExceptions, type ExceptionAction } from "../api/exceptions";
import { listPolicies } from "../api/policies";
import { ENVIRONMENTS, type ExceptionStatus, type ListExceptionsParams, type PolicyException } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { useAuth } from "../auth/useAuth";
import { usePermission } from "../auth/usePermission";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { SelectField } from "../components/SelectField";
import { Tabs } from "../components/Tabs";
import { ExceptionDetails } from "../features/exceptions/ExceptionDetails";
import { ExceptionRequestForm } from "../features/exceptions/ExceptionRequestForm";
import { exceptionColumns } from "../features/exceptions/exceptionColumns";
import { TransitionDialog, type TransitionRequest } from "../features/exceptions/TransitionDialog";
import { useNow } from "../features/exceptions/useNow";
import { isValidPackageName } from "../features/exceptions/validation";
import { useApiQuery } from "../hooks/useApiQuery";
import { humanize } from "../lib/format";
import { pickOption } from "../lib/values";

const PAGE_SIZE = 25;

interface StatusTab {
  id: string;
  label: string;
  status: ExceptionStatus | undefined;
  empty: string;
}

/**
 * The server's effective "approved" status already excludes expired exceptions, so an approved exception is
 * exactly an active one: a single tab covers both (and `?status=active` opens it).
 */
const STATUS_TABS = [
  { id: "pending", label: "Pending", status: "pending", empty: "No requests are waiting for a decision." },
  { id: "approved", label: "Approved (active)", status: "approved", empty: "No approved exceptions are in force." },
  { id: "expired", label: "Expired", status: "expired", empty: "No exceptions have expired." },
  { id: "rejected", label: "Rejected", status: "rejected", empty: "No requests have been rejected." },
  { id: "revoked", label: "Revoked", status: "revoked", empty: "No exceptions have been revoked or withdrawn." },
  { id: "all", label: "All", status: undefined, empty: "No exceptions have been requested yet." },
] as const satisfies readonly StatusTab[];

type TabId = (typeof STATUS_TABS)[number]["id"];
const TAB_IDS: readonly TabId[] = STATUS_TABS.map((tab) => tab.id);

function tabFromParam(value: string | null): TabId {
  if (value === "active") return "approved";
  return pickOption(TAB_IDS, value) ?? "pending";
}

function parseOffset(value: string | null): number {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : 0;
}

const NOTICES: Record<ExceptionAction, (pkg: string) => string> = {
  approve: (pkg) => `Approved the exception for ${pkg}. It applies until it expires or is revoked.`,
  reject: (pkg) => `Rejected the exception request for ${pkg}.`,
  revoke: (pkg) => `Revoked the exception for ${pkg}. It no longer applies.`,
};

export default function Exceptions() {
  const { user } = useAuth();
  const currentUserId = user?.id ?? null;
  const canRequest = usePermission(PERMISSIONS.EXCEPTION_REQUEST);
  const canApprove = usePermission(PERMISSIONS.EXCEPTION_APPROVE);
  const now = useNow();

  const [searchParams, setSearchParams] = useSearchParams();
  const tabId = tabFromParam(searchParams.get("status"));
  const tab = STATUS_TABS.find((candidate) => candidate.id === tabId) ?? STATUS_TABS[0];
  const packageParam = searchParams.get("package") ?? "";
  const environment = pickOption(ENVIRONMENTS, searchParams.get("environment"));
  const offset = parseOffset(searchParams.get("offset"));

  // The server rejects an invalid package name with 422, so only a valid name is sent as a filter.
  const packageFilter = packageParam.trim() && isValidPackageName(packageParam) ? packageParam.trim() : undefined;

  // The text box follows the URL unless the user has typed since the URL last changed.
  const [typed, setTyped] = useState({ basedOn: packageParam, value: packageParam });
  const packageText = typed.basedOn === packageParam ? typed.value : packageParam;
  const packageTextError =
    packageText.trim() && !isValidPackageName(packageText)
      ? "Enter a complete, valid package name. This filter matches exact names only."
      : null;

  const updateParams = useCallback(
    (changes: Record<string, string | null>) => {
      setSearchParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          for (const [name, value] of Object.entries(changes)) {
            if (value === null || value === "") next.delete(name);
            else next.set(name, value);
          }
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  // Apply a typed package name to the URL after a short pause, once it is valid (or cleared).
  useEffect(() => {
    if (typed.basedOn !== packageParam || typed.value === packageParam) return;
    if (typed.value.trim() && !isValidPackageName(typed.value)) return;
    const timer = window.setTimeout(() => updateParams({ package: typed.value, offset: null }), 300);
    return () => window.clearTimeout(timer);
  }, [typed, packageParam, updateParams]);

  const params: ListExceptionsParams = {
    limit: PAGE_SIZE,
    offset,
    status: tab.status,
    package: packageFilter,
    environment,
  };
  const query = useApiQuery(`exceptions:${JSON.stringify(params)}`, (signal) => listExceptions(params, { signal }));
  const page = query.data ?? query.previousData;
  const filtered = Boolean(packageParam.trim() || environment);

  // An offset past the last row (an old link, or rows that changed status) moves to the last page.
  const current = query.data;
  const pastEnd = current !== undefined && current.total > 0 && current.items.length === 0 && offset > 0;
  const pageSize = current?.limit || PAGE_SIZE;
  const lastPageOffset = current ? Math.floor(Math.max(current.total - 1, 0) / pageSize) * pageSize : 0;
  useEffect(() => {
    if (!pastEnd || lastPageOffset === offset) return;
    updateParams({ offset: lastPageOffset > 0 ? String(lastPageOffset) : null });
  }, [pastEnd, lastPageOffset, offset, updateParams]);

  const policies = useApiQuery("exception-policies", (signal) => listPolicies({}, { signal }));
  const policyLabel = (policyId: string): string | null => {
    const policy = policies.data?.find((candidate) => candidate.id === policyId);
    return policy ? `${policy.name} (${humanize(policy.environment ?? "production")})` : null;
  };

  const [selected, setSelected] = useState<PolicyException | null>(null);
  // While the list reloads (for example after a decision) the selected snapshot is newer than the list.
  const listed = selected && !query.loading ? query.data?.items.find((item) => item.id === selected.id) : undefined;
  const shownException = listed ?? selected;

  const [transition, setTransition] = useState<TransitionRequest | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const noticeRef = useRef<HTMLParagraphElement>(null);
  const requestButtonRef = useRef<HTMLButtonElement>(null);
  // Focus moves after the render that shows the notice or the request button again. These effects run after
  // the dialog's own focus restore, whose opener may be gone once the exception's status changed.
  const [noticeFocusRequest, setNoticeFocusRequest] = useState(0);
  const [requestButtonFocusRequest, setRequestButtonFocusRequest] = useState(0);

  useEffect(() => {
    if (noticeFocusRequest > 0) noticeRef.current?.focus();
  }, [noticeFocusRequest]);

  useEffect(() => {
    if (requestButtonFocusRequest > 0) requestButtonRef.current?.focus();
  }, [requestButtonFocusRequest]);

  function announce(message: string) {
    setNotice(message);
    setNoticeFocusRequest((n) => n + 1);
  }

  function onTransitionDone(updated: PolicyException, action: ExceptionAction) {
    setTransition(null);
    setSelected(updated);
    announce(NOTICES[action](updated.package));
    query.reload();
  }

  function onCreated(created: PolicyException) {
    setFormOpen(false);
    setSelected(created);
    announce(`Requested an exception for ${created.package}. It applies only after someone else approves it.`);
    updateParams({ status: null, offset: null });
    query.reload();
  }

  const columns = exceptionColumns({
    now,
    currentUserId,
    selectedId: shownException?.id ?? null,
    onSelect: setSelected,
  });

  const panel = (
    <div className="flex flex-col gap-3">
      <div role="search" aria-label="Filter exceptions" className="flex flex-wrap items-start gap-3">
        <div className="w-full sm:w-64">
          <label htmlFor="exc-filter-package" className="label">
            Package (exact name)
          </label>
          <input
            id="exc-filter-package"
            type="search"
            className="input font-mono"
            maxLength={214}
            autoComplete="off"
            spellCheck={false}
            value={packageText}
            aria-invalid={packageTextError ? true : undefined}
            aria-describedby="exc-filter-package-error"
            onChange={(event) => setTyped({ basedOn: packageParam, value: event.target.value })}
          />
          <p id="exc-filter-package-error" aria-live="polite" className="mt-1 text-xs text-sev-critical empty:hidden">
            {packageTextError}
          </p>
        </div>
        <SelectField
          id="exc-filter-environment"
          label="Environment"
          className="w-40"
          value={environment ?? ""}
          options={[{ value: "", label: "Any" }, ...ENVIRONMENTS.map((env) => ({ value: env, label: humanize(env) }))]}
          onChange={(value) => updateParams({ environment: value, offset: null })}
        />
        {filtered && (
          <button
            type="button"
            className="btn-ghost mt-5"
            onClick={() => {
              setTyped({ basedOn: "", value: "" });
              updateParams({ package: null, environment: null, offset: null });
            }}
          >
            Clear filters
          </button>
        )}
      </div>
      {tab.id === "approved" && (
        <p className="text-xs text-ink-muted">Approved exceptions that have not expired. Once expired they are listed under Expired.</p>
      )}
      {environment && (
        <p className="text-xs text-ink-muted">Exceptions that apply to every environment are not included in this filter.</p>
      )}
      <Card flush>
        <DataTable
          caption={`${tab.label} exceptions`}
          columns={columns}
          rows={page?.items}
          rowKey={(exception) => exception.id}
          loading={query.loading}
          error={query.error}
          onRetry={query.reload}
          empty={
            pastEnd ? (
              <EmptyState
                compact
                title="This page is past the end of the list."
                action={
                  <button type="button" className="btn-secondary" onClick={() => updateParams({ offset: null })}>
                    Go to the first page
                  </button>
                }
              />
            ) : (
              <EmptyState
                compact
                title={filtered ? "No exceptions match these filters." : tab.empty}
                description={filtered ? "Change or clear the filters." : undefined}
              />
            )
          }
          pagination={
            page && page.total > 0
              ? {
                  total: page.total,
                  limit: page.limit || PAGE_SIZE,
                  offset: page.offset,
                  onOffsetChange: (next) => updateParams({ offset: next > 0 ? String(next) : null }),
                }
              : undefined
          }
          footnote="Newest requests first."
        />
      </Card>
    </div>
  );

  return (
    <>
      <PageHeader
        title="Policy exceptions"
        description="Time-boxed risk acceptances that let specific findings for a package pass policy. A request applies only after a different person approves it."
        actions={
          canRequest && !formOpen ? (
            <button
              ref={requestButtonRef}
              type="button"
              className="btn-primary"
              onClick={() => {
                setNotice(null);
                setFormOpen(true);
              }}
            >
              Request exception
            </button>
          ) : undefined
        }
      />
      {!canRequest && (
        <p className="mb-4 text-ink-secondary">
          Your role can review exceptions. Requesting one needs the exception:request permission (admin, security analyst or
          developer roles).
        </p>
      )}
      {notice && (
        <p
          ref={noticeRef}
          role="status"
          tabIndex={-1}
          className="mb-4 rounded-r-md border-l-2 border-verdict-allow bg-panel px-4 py-2 text-ink"
        >
          {notice}
        </p>
      )}
      {formOpen && (
        <div className="mb-4">
          <ExceptionRequestForm
            policies={policies.data}
            policiesError={policies.error}
            onRetryPolicies={policies.reload}
            onCreated={onCreated}
            onCancel={() => {
              setFormOpen(false);
              setRequestButtonFocusRequest((n) => n + 1);
            }}
          />
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="min-w-0">
          <Tabs
            label="Exception status"
            value={tabId}
            onChange={(id) => {
              const next = tabFromParam(id);
              updateParams({ status: next === "pending" ? null : next, offset: null });
            }}
            tabs={STATUS_TABS.map((candidate) => ({ id: candidate.id, label: candidate.label, content: panel }))}
          />
        </div>
        <div className="min-w-0">
          {shownException ? (
            <ExceptionDetails
              exception={shownException}
              now={now}
              currentUserId={currentUserId}
              canApprove={canApprove}
              canRequest={canRequest}
              policyLabel={policyLabel}
              onAction={(action) => setTransition({ exception: shownException, action })}
            />
          ) : (
            <EmptyState
              title="Select an exception"
              description="Choose a package in the list to read its justification and scope, and to approve, reject or revoke it."
            />
          )}
        </div>
      </div>

      <TransitionDialog
        request={transition}
        currentUserId={currentUserId}
        onDone={onTransitionDone}
        onCancel={() => setTransition(null)}
        onStale={query.reload}
      />
    </>
  );
}
