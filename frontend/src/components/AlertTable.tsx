import { Link } from "react-router";

import { alertEntity, formatUtc, ruleInfo } from "../format";
import type { AlertSummary } from "../types/alert";

export function AlertTable({ alerts }: { alerts: AlertSummary[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">Rule</th>
            <th scope="col">Actor / account</th>
            <th scope="col">Organization</th>
            <th scope="col">Window</th>
            <th scope="col">Count</th>
            <th scope="col">Severity</th>
            <th scope="col">Status</th>
            <th scope="col">Reason</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.alert_key}>
              <td className="nowrap">
                <Link to={`/alerts/${encodeURIComponent(alert.alert_key)}`}>
                  {ruleInfo(alert.rule_id).label} · {ruleInfo(alert.rule_id).title}
                </Link>
              </td>
              <td className="mono">{alertEntity(alert)}</td>
              <td className="mono">{alert.organization_id ?? "—"}</td>
              <td className="nowrap">
                {formatUtc(alert.window_start)}
                <br />
                {formatUtc(alert.window_end)}
              </td>
              <td>
                {alert.match_count} / {alert.threshold}
              </td>
              <td>{alert.severity}</td>
              <td>
                {alert.status}
                {alert.detection_state === "superseded" && " · superseded"}
                {alert.needs_review && " · needs review"}
              </td>
              <td>{alert.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
