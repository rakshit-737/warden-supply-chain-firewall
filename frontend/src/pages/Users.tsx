import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { USER_ROLES, type ListUsersParams, type User } from "../api/types";
import { USER_SEARCH_MAX_LENGTH, listUsers } from "../api/users";
import { PERMISSIONS } from "../auth/permissions";
import { useAuth } from "../auth/useAuth";
import { Card } from "../components/Card";
import { DataTable, type Column } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { SelectField } from "../components/SelectField";
import { RegisterUserForm } from "../features/users/RegisterUserForm";
import { ROLE_OPTIONS, describeRole } from "../features/users/roles";
import { UserChangeDialog, type UserChange, type UserChangeResult } from "../features/users/UserChangeDialog";
import { useApiQuery } from "../hooks/useApiQuery";
import { formatDateTime } from "../lib/format";
import { revealInvisible } from "../lib/text";
import { pickOption } from "../lib/values";

const PAGE_SIZE = 25;
const STATUS_FILTERS = ["active", "inactive"] as const;
const REGISTER_PANEL_ID = "register-user-panel";

function parseOffset(value: string | null): number {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : 0;
}

function RoleCell({ role }: { role: unknown }) {
  const shown = describeRole(role);
  return (
    <span className="flex flex-col">
      <span className={shown.role ? "text-ink" : "text-ink-secondary"}>{shown.label}</span>
      {shown.reportedAs && (
        <span className="text-xs text-ink-muted">
          reported as <code className="font-mono">{revealInvisible(shown.reportedAs)}</code>
          {shown.role ? " (v1 name)" : ""}
        </span>
      )}
    </span>
  );
}

function StatusCell({ active }: { active: boolean }) {
  return active ? (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-semibold text-ink">
      <span aria-hidden="true" className="h-2 w-2 rounded-full bg-verdict-allow" />
      Active
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs text-ink-secondary">
      <span aria-hidden="true" className="h-2 w-2 rounded-full border border-ink-muted" />
      Inactive
    </span>
  );
}

type FocusTarget = "notice" | "register";

function UsersView() {
  const { user: me, retryRestore } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const q = (searchParams.get("q") ?? "").slice(0, USER_SEARCH_MAX_LENGTH);
  const role = pickOption(USER_ROLES, searchParams.get("role"));
  const status = pickOption(STATUS_FILTERS, searchParams.get("status"));
  const offset = parseOffset(searchParams.get("offset"));

  // The search box follows the URL unless the user has typed since the URL last changed.
  const [typed, setTyped] = useState({ basedOn: q, value: q });
  const searchText = typed.basedOn === q ? typed.value : q;

  const [registering, setRegistering] = useState(false);
  const [change, setChange] = useState<UserChange | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [focusRequest, setFocusRequest] = useState<{ target: FocusTarget; attempt: number } | null>(null);
  const noticeRef = useRef<HTMLParagraphElement>(null);
  const registerButtonRef = useRef<HTMLButtonElement>(null);

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

  // Apply typed text to the URL after a short pause.
  useEffect(() => {
    if (typed.basedOn !== q || typed.value === q) return;
    const timer = window.setTimeout(() => updateParams({ q: typed.value, offset: null }), 300);
    return () => window.clearTimeout(timer);
  }, [typed, q, updateParams]);

  // Focus moves after the commit that renders its target. A closing dialog restores focus to its
  // opener first (unmount effects run before this one), and that opener can vanish when the list
  // reloads, so a completed change sends focus to the confirmation instead.
  useEffect(() => {
    if (!focusRequest) return;
    (focusRequest.target === "notice" ? noticeRef : registerButtonRef).current?.focus();
  }, [focusRequest]);

  function requestFocus(target: FocusTarget) {
    setFocusRequest((previous) => ({ target, attempt: (previous?.attempt ?? 0) + 1 }));
  }

  const params: ListUsersParams = {
    limit: PAGE_SIZE,
    offset,
    q: q.trim() || undefined,
    role,
    is_active: status === undefined ? undefined : status === "active",
  };
  const query = useApiQuery(`users:${JSON.stringify(params)}`, (signal) => listUsers(params, { signal }));
  const page = query.data ?? query.previousData;
  const filtered = Boolean(q.trim() || role || status);

  // An offset past the last user (an old link, or users filtered away) returns no rows although users
  // exist. Move to the last page rather than showing an empty list.
  const current = query.data;
  const currentLimit = current?.limit || PAGE_SIZE;
  const pastEnd = current !== undefined && current.total > 0 && current.items.length === 0 && offset > 0;
  const lastPageOffset = current ? Math.floor(Math.max(current.total - 1, 0) / currentLimit) * currentLimit : 0;
  useEffect(() => {
    if (!pastEnd || lastPageOffset === offset) return;
    updateParams({ offset: lastPageOffset > 0 ? String(lastPageOffset) : null });
  }, [pastEnd, lastPageOffset, offset, updateParams]);

  function handleChanged(result: UserChangeResult) {
    setChange(null);
    setNotice(result.message);
    requestFocus("notice");
    query.reload();
    // A change to one's own account alters what this session may do (or ends it): check it again so
    // the console stops offering what the server will now refuse.
    if (me && result.user.id === me.id) retryRestore();
  }

  function handleRegistered(created: User) {
    setRegistering(false);
    setNotice(`Registered ${created.email} with the ${describeRole(created.role).label} role.`);
    requestFocus("notice");
    query.reload();
  }

  const columns: Column<User>[] = [
    {
      id: "email",
      header: "Email",
      sortValue: (user) => user.email,
      cell: (user) => (
        <span className="inline-flex flex-wrap items-center gap-x-2">
          <span className="break-all text-ink">{revealInvisible(user.email)}</span>
          {me?.id === user.id && (
            <span className="rounded border border-line-strong px-1 text-2xs text-ink-secondary">You</span>
          )}
        </span>
      ),
    },
    {
      id: "role",
      header: "Role",
      sortValue: (user) => describeRole(user.role).label,
      cell: (user) => <RoleCell role={user.role} />,
    },
    {
      id: "status",
      header: "Status",
      sortValue: (user) => user.is_active,
      cell: (user) => <StatusCell active={user.is_active} />,
    },
    {
      id: "created",
      header: "Created",
      sortValue: (user) => user.created_at,
      cell: (user) => <span className="whitespace-nowrap text-ink-secondary">{formatDateTime(user.created_at)}</span>,
    },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      cell: (user) => (
        <span className="inline-flex flex-wrap justify-end gap-2">
          {/* The accessible names start with the visible text and add whose account the button acts on. */}
          <button
            type="button"
            className="btn-secondary h-7 px-2"
            aria-label={`Change role for ${user.email}`}
            onClick={() => {
              setNotice(null);
              setChange({ kind: "role", user });
            }}
          >
            Change role
          </button>
          <button
            type="button"
            className="btn-secondary h-7 px-2"
            aria-label={`${user.is_active ? "Deactivate" : "Reactivate"} ${user.email}`}
            onClick={() => {
              setNotice(null);
              setChange({ kind: "status", user, activate: !user.is_active });
            }}
          >
            {user.is_active ? "Deactivate" : "Reactivate"}
          </button>
        </span>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Users"
        description="Accounts that can sign in to this console, and the role that decides what each one may do. Passwords and tokens are never shown."
        actions={
          <button
            ref={registerButtonRef}
            type="button"
            className="btn-primary"
            aria-expanded={registering}
            aria-controls={registering ? REGISTER_PANEL_ID : undefined}
            onClick={() => {
              if (registering) {
                setRegistering(false);
              } else {
                setNotice(null);
                setRegistering(true);
              }
            }}
          >
            Register user
          </button>
        }
      />

      {notice && (
        <p
          ref={noticeRef}
          role="status"
          tabIndex={-1}
          className="mb-4 break-words rounded-r-md border-l-2 border-verdict-allow bg-panel px-4 py-2 text-ink"
        >
          {notice}
        </p>
      )}

      {registering && (
        <div id={REGISTER_PANEL_ID} className="mb-4">
          <Card title="Register a user" description="The account can sign in as soon as it is created.">
            <RegisterUserForm
              onRegistered={handleRegistered}
              onCancel={() => {
                setRegistering(false);
                requestFocus("register");
              }}
            />
          </Card>
        </div>
      )}

      <div role="search" aria-label="Filter users" className="mb-3 flex flex-wrap items-end gap-3">
        <div className="w-full sm:w-64">
          <label htmlFor="users-filter-q" className="label">
            Email contains
          </label>
          <input
            id="users-filter-q"
            type="search"
            className="input"
            maxLength={USER_SEARCH_MAX_LENGTH}
            spellCheck={false}
            autoCapitalize="none"
            value={searchText}
            onChange={(event) => setTyped({ basedOn: q, value: event.target.value })}
          />
        </div>
        <SelectField
          id="users-filter-role"
          label="Role"
          className="w-44"
          value={role ?? ""}
          options={[{ value: "", label: "Any" }, ...ROLE_OPTIONS]}
          onChange={(value) => updateParams({ role: value, offset: null })}
        />
        <SelectField
          id="users-filter-status"
          label="Status"
          className="w-32"
          value={status ?? ""}
          options={[
            { value: "", label: "Any" },
            { value: "active", label: "Active" },
            { value: "inactive", label: "Inactive" },
          ]}
          onChange={(value) => updateParams({ status: value, offset: null })}
        />
        {filtered && (
          <button
            type="button"
            className="btn-ghost"
            onClick={() => {
              setTyped({ basedOn: "", value: "" });
              updateParams({ q: null, role: null, status: null, offset: null });
            }}
          >
            Clear filters
          </button>
        )}
      </div>

      <Card flush>
        <DataTable
          caption="Users"
          columns={columns}
          rows={page?.items}
          rowKey={(user) => user.id}
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
                title={filtered ? "No users match these filters." : "No users to show."}
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
          footnote="Listed oldest first. Sorting a column reorders this page only."
        />
      </Card>

      {change && (
        <UserChangeDialog
          key={`${change.kind}:${change.user.id}`}
          change={change}
          isSelf={me?.id === change.user.id}
          onCancel={() => setChange(null)}
          onChanged={handleChanged}
        />
      )}
    </>
  );
}

/** User administration (user:manage: admin only). The server enforces the same permission. */
export default function UsersPage() {
  return (
    <RequirePermission permission={PERMISSIONS.USER_MANAGE}>
      <UsersView />
    </RequirePermission>
  );
}
