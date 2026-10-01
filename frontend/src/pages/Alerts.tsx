import { useSearchParams } from "react-router";

import { listAlerts } from "../api/security";
import { AlertFilters, EMPTY_FILTERS, filterAlerts } from "../components/AlertFilters";
import type { AlertFilterValues } from "../components/AlertFilters";
import { AlertTable } from "../components/AlertTable";
import { EmptyState, ErrorNotice, Loading } from "../components/StatusMessage";
import { useApi } from "../hooks/useApi";

const FILTER_FIELDS = Object.keys(EMPTY_FILTERS) as (keyof AlertFilterValues)[];

export function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const includeSuperseded = params.get("history") === "true";
  const { data: alerts, error, loading } = useApi(
    (token) => listAlerts(token, includeSuperseded),
    `alerts:${includeSuperseded}`,
  );

  const filters = Object.fromEntries(
    FILTER_FIELDS.map((field) => [field, params.get(field) ?? ""]),
  ) as unknown as AlertFilterValues;

  function updateFilters(values: AlertFilterValues) {
    const next = Object.fromEntries(Object.entries(values).filter(([, value]) => value !== ""));
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
            if (event.target.checked) next.set("history", "true");
            else next.delete("history");
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
