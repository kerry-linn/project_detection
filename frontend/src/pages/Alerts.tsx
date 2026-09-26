import { useSearchParams } from "react-router";

import { listAlerts } from "../api/security";
import { AlertFilters, EMPTY_FILTERS, filterAlerts } from "../components/AlertFilters";
import type { AlertFilterValues } from "../components/AlertFilters";
import { AlertTable } from "../components/AlertTable";
import { EmptyState, ErrorNotice, Loading } from "../components/StatusMessage";
import { useApi } from "../hooks/useApi";

const FILTER_FIELDS = Object.keys(EMPTY_FILTERS) as (keyof AlertFilterValues)[];

export function AlertsPage() {
  const { data: alerts, error, loading } = useApi(listAlerts, "alerts");
  const [params, setParams] = useSearchParams();

  const filters = Object.fromEntries(
    FILTER_FIELDS.map((field) => [field, params.get(field) ?? ""]),
  ) as unknown as AlertFilterValues;

  function updateFilters(values: AlertFilterValues) {
    setParams(
      Object.fromEntries(Object.entries(values).filter(([, value]) => value !== "")),
      { replace: true },
    );
  }

  const visible = alerts ? filterAlerts(alerts, filters) : [];

  return (
    <>
      <h1>Security alerts</h1>
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
