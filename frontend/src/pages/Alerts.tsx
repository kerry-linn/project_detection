import { useSearchParams } from "react-router";

import { listAlerts } from "../api/security";
import { AlertFilters, filterAlerts } from "../components/AlertFilters";
import type { AlertFilterValues } from "../components/AlertFilters";
import { AlertTable } from "../components/AlertTable";
import { EmptyState, ErrorNotice, Loading } from "../components/StatusMessage";
import { useApi } from "../hooks/useApi";

export function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const includeSuperseded = params.get("history") === "true";
  const { data: alerts, error, loading } = useApi(
    (token) => listAlerts(token, includeSuperseded),
    `alerts:${includeSuperseded}`,
  );

  const filters: AlertFilterValues = {
    rule: params.get("rule") ?? "",
    status: params.get("status") ?? "",
    entity: params.get("entity") ?? "",
    organization: params.get("organization") ?? "",
  };

  function updateFilters(values: AlertFilterValues) {
    const next: Record<string, string> = {};
    for (const [field, value] of Object.entries(values)) {
      if (value !== "") next[field] = value;
    }
    if (includeSuperseded) next.history = "true";
    setParams(next, { replace: true });
  }

  const visible = alerts ? filterAlerts(alerts, filters) : [];

  return (
    <>
      <h1>Security alerts</h1>
      <label>
        <input
          type="checkbox"
          checked={includeSuperseded}
          onChange={(event) => {
            const next = new URLSearchParams(params);
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
      {loading && <Loading />}
      {error && <ErrorNotice error={error} />}
      {alerts && (
        <>
          <AlertFilters alerts={alerts} values={filters} onChange={updateFilters} />
          <p className="muted" aria-live="polite">
            Showing {visible.length} of {alerts.length} alerts
          </p>
          {visible.length > 0 ? (
            <AlertTable alerts={visible} />
          ) : (
            <EmptyState>
              {alerts.length === 0
                ? "No alerts yet. Run the detector after generating activity."
                : "No alerts match these filters."}
            </EmptyState>
          )}
        </>
      )}
    </>
  );
}
