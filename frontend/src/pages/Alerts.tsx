import { useSearchParams } from "react-router";

import { listAlerts } from "../api/security";
import { AlertFilters } from "../components/AlertFilters";
import type { AlertFilterValues } from "../components/AlertFilters";
import { Pagination } from "../components/Pagination";
import { AlertTable } from "../components/AlertTable";
import { EmptyState, ErrorNotice, Loading } from "../components/StatusMessage";
import { useApi } from "../hooks/useApi";

export function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const includeSuperseded = params.get("history") === "true";
  const filters: AlertFilterValues = {
    rule: params.get("rule") ?? "",
    status: params.get("status") ?? "",
    entity: params.get("entity") ?? "",
    organization: params.get("organization") ?? "",
  };

  const offset = Math.max(0, Number(params.get("offset")) || 0);
  const query = new URLSearchParams();
  if (includeSuperseded) query.set("include_superseded", "true");
  for (const [key, value] of Object.entries(filters)) if (value) query.set(key, value);
  if (offset) query.set("offset", String(offset));
  const { data: page, error, loading } = useApi(
    (token) => listAlerts(token, query.toString()), `alerts:${query}`,
  );
  const alerts = page?.items;

  function updateFilters(values: AlertFilterValues) {
    const next: Record<string, string> = {};
    for (const [field, value] of Object.entries(values)) {
      if (value !== "") next[field] = value;
    }
    if (includeSuperseded) next.history = "true";
    setParams(next, { replace: true });
  }

  const visible = alerts ?? [];

  return (
    <>
      <h1>Security alerts</h1>
      <label>
        <input
          type="checkbox"
          checked={includeSuperseded}
          onChange={(event) => {
            const next = new URLSearchParams(params);
            next.delete("offset");
            if (event.target.checked) {
              next.set("history", "true");
            } else {
              next.delete("history");
            }
            setParams(next);
          }}
        />{" "}
        Include superseded alerts
      </label>
      <AlertFilters values={filters} onChange={updateFilters} />
      {loading && <Loading />}
      {error && <ErrorNotice error={error} />}
      {alerts && (
        <>
          <p className="muted" aria-live="polite">
            Showing {visible.length} of {page?.total} alerts
          </p>
          <Pagination label="alerts" offset={offset} total={page?.total ?? 0} onChange={(value) => {
            const next = new URLSearchParams(params);
            next.set("offset", String(value)); setParams(next);
          }} />
          {visible.length > 0 ? (
            <AlertTable alerts={visible} />
          ) : (
            <EmptyState>
              No alerts on this page. Clear the filters or return to the previous page.
            </EmptyState>
          )}
        </>
      )}
    </>
  );
}
