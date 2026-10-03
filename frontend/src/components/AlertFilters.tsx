import { ruleInfo } from "../format";

export interface AlertFilterValues {
  rule: string;
  status: string;
  entity: string;
  organization: string;
}

export const EMPTY_FILTERS: AlertFilterValues = { rule: "", status: "", entity: "", organization: "" };

const STATUSES = ["new", "investigating", "closed"];

interface Props {
  values: AlertFilterValues;
  onChange: (values: AlertFilterValues) => void;
}

export function AlertFilters({ values, onChange }: Props) {
  const rules = ["R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS", "R2_REPEATED_DENIED_DOCUMENT_ACCESS"];
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
        <input value={values.organization} maxLength={256}
          onChange={(event) => update("organization", event.target.value)} />
      </label>
      <label className="field">
        Actor or account
        <input
          type="search"
          maxLength={256}
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
