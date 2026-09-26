import type { AlertSummary } from "../types/alert";
import { ruleInfo } from "../format";

export interface AlertFilterValues {
  rule: string;
  status: string;
  entity: string;
  organization: string;
}

export const EMPTY_FILTERS: AlertFilterValues = { rule: "", status: "", entity: "", organization: "" };

const STATUSES = ["new", "investigating", "closed"];

export function filterAlerts(alerts: AlertSummary[], filters: AlertFilterValues): AlertSummary[] {
  const entity = filters.entity.trim().toLowerCase();
  return alerts.filter(
    (alert) =>
      (!filters.rule || alert.rule_id === filters.rule) &&
      (!filters.status || alert.status === filters.status) &&
      (!filters.organization || alert.organization_id === filters.organization) &&
      (!entity ||
        [alert.attempted_account, alert.actor_id].some((value) =>
          value?.toLowerCase().includes(entity),
        )),
  );
}

interface Props {
  alerts: AlertSummary[];
  values: AlertFilterValues;
  onChange: (values: AlertFilterValues) => void;
}

export function AlertFilters({ alerts, values, onChange }: Props) {
  const rules = distinct(alerts.map((alert) => alert.rule_id));
  const organizations = distinct(alerts.map((alert) => alert.organization_id));
  const update = (field: keyof AlertFilterValues, value: string) =>
    onChange({ ...values, [field]: value });

  return (
    <form className="filters" role="search" onSubmit={(event) => event.preventDefault()}>
      <label className="field">
        Rule
        <select value={values.rule} onChange={(event) => update("rule", event.target.value)}>
          <option value="">All rules</option>
          {rules.map((ruleId) => (
            <option key={ruleId} value={ruleId}>
              {ruleInfo(ruleId).label} · {ruleInfo(ruleId).title}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        Status
        <select value={values.status} onChange={(event) => update("status", event.target.value)}>
          <option value="">All statuses</option>
          {STATUSES.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        Organization
        <select
          value={values.organization}
          onChange={(event) => update("organization", event.target.value)}
        >
          <option value="">All organizations</option>
          {organizations.map((organization) => (
            <option key={organization} value={organization}>
              {organization}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        Actor or account
        <input
          type="search"
          value={values.entity}
          placeholder="user-bob, alice@…"
          onChange={(event) => update("entity", event.target.value)}
        />
      </label>
      <button type="button" onClick={() => onChange(EMPTY_FILTERS)}>
        Clear
      </button>
    </form>
  );
}

function distinct(values: (string | null)[]): string[] {
  return [...new Set(values.filter((value): value is string => value !== null))].sort();
}
