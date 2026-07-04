import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

const nav = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/scan", label: "New Scan" },
  { to: "/scans", label: "History" },
  { to: "/policies", label: "Policies" },
];

export default function Layout() {
  const { user, logout } = useAuth();
  return (
    <div className="flex min-h-full">
      <aside className="hidden w-60 flex-col border-r border-edge bg-panel p-4 md:flex">
        <div className="mb-8 flex items-center gap-2 px-2">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-accent font-bold text-white">W</div>
          <div>
            <div className="text-sm font-semibold leading-tight">Warden</div>
            <div className="text-[10px] uppercase tracking-wider text-muted">Supply-Chain Firewall</div>
          </div>
        </div>
        <nav className="flex flex-col gap-1">
          {nav.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) =>
                `rounded-lg px-3 py-2 text-sm ${isActive ? "bg-panel2 text-white" : "text-muted hover:bg-panel2 hover:text-slate-200"}`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto border-t border-edge pt-4">
          <div className="px-2 text-xs text-muted">{user?.email}</div>
          <div className="px-2 text-[10px] uppercase tracking-wide text-muted">{user?.role}</div>
          <button onClick={logout} className="btn-ghost mt-3 w-full">Sign out</button>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <div className="mx-auto max-w-6xl p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
