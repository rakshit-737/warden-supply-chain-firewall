import { Suspense, useEffect, useLayoutEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import { NAV_SECTIONS } from "../app/navigation";
import { ROLE_LABELS, hasPermission, normalizeRole } from "../auth/permissions";
import { useAuth } from "../auth/useAuth";
import { BrandMark } from "./BrandMark";
import { RouteErrorBoundary } from "./RouteErrorBoundary";
import { LoadingBlock } from "./Skeleton";

/** Tailwind's `lg` breakpoint: from here on the sidebar is always shown and the menu button is hidden. */
const WIDE_LAYOUT_QUERY = "(min-width: 1024px)";

/**
 * Application frame: sectioned sidebar navigation (collapsible below the lg breakpoint), the
 * signed-in identity, and the routed page. Navigation items the role cannot use are hidden; the
 * server still enforces every permission.
 */
export function AppShell() {
  const { user, logout } = useAuth();
  const { pathname } = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const sidebarRef = useRef<HTMLElement>(null);
  const mainRef = useRef<HTMLElement>(null);
  /** Where focus goes once the menu has closed (null: leave it where it is). */
  const focusAfterClose = useRef<HTMLElement | null>(null);
  const role = normalizeRole(user?.role);

  const sections = NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) => !item.permission || hasPermission(user?.role, item.permission)),
  })).filter((section) => section.items.length > 0);

  function closeMenu(focusTarget: HTMLElement | null) {
    focusAfterClose.current = focusTarget;
    setMenuOpen(false);
  }

  // The open small-screen menu covers the page, so the page is inert meanwhile: nothing behind the
  // menu can take keyboard focus or be reached by assistive technology. A layout effect applies and
  // lifts it during the commit, before focus is moved back into the page below.
  useLayoutEffect(() => {
    mainRef.current?.toggleAttribute("inert", menuOpen);
  }, [menuOpen]);

  useEffect(() => {
    if (!menuOpen) {
      focusAfterClose.current?.focus();
      focusAfterClose.current = null;
      return;
    }
    sidebarRef.current?.querySelector<HTMLElement>("a[href]")?.focus();
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      focusAfterClose.current = toggleRef.current;
      setMenuOpen(false);
    }
    const wideLayout = typeof window.matchMedia === "function" ? window.matchMedia(WIDE_LAYOUT_QUERY) : null;
    function onLayoutChange(event: MediaQueryListEvent) {
      if (event.matches) setMenuOpen(false);
    }
    document.addEventListener("keydown", onKeyDown);
    wideLayout?.addEventListener("change", onLayoutChange);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      wideLayout?.removeEventListener("change", onLayoutChange);
    };
  }, [menuOpen]);

  return (
    <div className="min-h-full lg:grid lg:grid-cols-[13.5rem_minmax(0,1fr)]">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-page"
      >
        Skip to main content
      </a>

      <div className="sticky top-0 z-30 flex h-12 items-center justify-between border-b border-line bg-panel px-4 lg:hidden">
        <BrandMark />
        <button
          ref={toggleRef}
          type="button"
          className="btn-ghost"
          aria-expanded={menuOpen}
          aria-controls="primary-sidebar"
          onClick={() => (menuOpen ? closeMenu(null) : setMenuOpen(true))}
        >
          {menuOpen ? "Close menu" : "Menu"}
        </button>
      </div>

      <aside
        ref={sidebarRef}
        id="primary-sidebar"
        className={`${
          menuOpen ? "flex" : "hidden"
        } fixed inset-x-0 bottom-0 top-12 z-20 flex-col overflow-y-auto border-line bg-panel px-3 py-4 lg:sticky lg:top-0 lg:flex lg:h-screen lg:border-r`}
        onBlur={(event) => {
          // Focus left the open menu for something other than the menu button: close it.
          const next = event.relatedTarget;
          if (menuOpen && next instanceof Node && !event.currentTarget.contains(next) && next !== toggleRef.current) {
            closeMenu(null);
          }
        }}
      >
        <div className="mb-6 hidden px-2 lg:block">
          <BrandMark />
        </div>
        <nav aria-label="Main" className="flex flex-col gap-4">
          {sections.map((section) => {
            const [only] = section.items;
            const showHeading = !(section.items.length === 1 && only?.label === section.label);
            const headingId = `nav-heading-${section.id}`;
            return (
              <div key={section.id}>
                {showHeading && (
                  <h2 id={headingId} className="px-2 pb-1 text-2xs font-medium text-ink-muted">
                    {section.label}
                  </h2>
                )}
                <ul aria-labelledby={showHeading ? headingId : undefined} className="flex flex-col">
                  {section.items.map((item) => (
                    <li key={item.to}>
                      <NavLink
                        to={item.to}
                        end={item.end}
                        onClick={() => {
                          if (menuOpen) closeMenu(mainRef.current);
                        }}
                        className={({ isActive }) =>
                          `relative flex h-8 items-center rounded px-2.5 text-[0.8125rem] ${
                            isActive
                              ? "bg-raised font-medium text-ink before:absolute before:inset-y-1.5 before:left-0 before:w-0.5 before:rounded-full before:bg-accent"
                              : "text-ink-secondary hover:bg-raised/60 hover:text-ink"
                          }`
                        }
                      >
                        {item.label}
                      </NavLink>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </nav>
        <div className="mt-auto border-t border-line px-2 pt-3">
          <div className="truncate text-[0.8125rem] text-ink">{user?.email}</div>
          <div className="text-xs text-ink-muted">{role ? ROLE_LABELS[role] : "Unrecognised role"}</div>
          <button type="button" className="btn-secondary mt-3 w-full" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </aside>

      <main ref={mainRef} id="main-content" tabIndex={-1} className="min-w-0 px-4 py-5 focus:outline-none sm:px-6 lg:px-8">
        <div className="mx-auto max-w-[96rem]">
          <RouteErrorBoundary resetKey={pathname}>
            <Suspense fallback={<LoadingBlock label="Loading view" rows={6} />}>
              <Outlet />
            </Suspense>
          </RouteErrorBoundary>
        </div>
      </main>
    </div>
  );
}
