import { NavLink, Navigate, Outlet, useLocation } from "react-router";

import { useAuth } from "../auth/AuthContext";
import { roleLabel } from "../format";
import { Loading } from "./StatusMessage";

export function Layout() {
  const { user, restoring, signOut } = useAuth();
  const location = useLocation();

  if (restoring) {
    return <Loading label="Restoring session…" />;
  }
  if (user === null) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  // Navigation hides irrelevant areas for usability only; the API authorizes every request.
  const isAnalyst = user.role === "lab_analyst";
  return (
    <>
      <header className="app-header">
        <span className="brand">Security Monitoring Lab</span>
        <nav aria-label="Main">
          {isAnalyst ? <NavLink to="/alerts">Alerts</NavLink> : <NavLink to="/documents">Documents</NavLink>}
        </nav>
        <div className="session">
          <span>
            {user.display_name} · {roleLabel(user.role)}
            {user.organization_id && ` · ${user.organization_id}`}
          </span>
          <button type="button" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      </header>
      <main>
        <Outlet />
      </main>
    </>
  );
}
