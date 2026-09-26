import { Link, useParams } from "react-router";

import { getAlert } from "../api/security";
import { EventTable } from "../components/EventTable";
import { EmptyState, ErrorNotice, Loading } from "../components/StatusMessage";
import { formatDuration, formatUtc, ruleInfo } from "../format";
import { useApi } from "../hooks/useApi";

export function AlertDetailPage() {
  const alertKey = useParams().alertKey ?? "";
  const { data: alert, error, loading } = useApi(
    (token) => getAlert(token, alertKey),
    `alert:${alertKey}`,
  );

  if (loading) return <Loading />;
  if (error) {
    return (
      <>
        <BackLink />
        <ErrorNotice error={error} />
      </>
    );
  }
  if (alert === null) return null;

  const rule = ruleInfo(alert.rule_id);
  return (
    <>
      <BackLink />
      <h1>
        {rule.label} · {rule.title}
      </h1>
      <p className="reason">{alert.reason}</p>

      <dl className="facts">
        <dt>Rule</dt>
        <dd className="mono">
          {alert.rule_id} v{alert.rule_version}
        </dd>
        <dt>Severity / status</dt>
        <dd>
          {alert.severity} / {alert.status}
        </dd>
        <dt>Organization</dt>
        <dd className="mono">{alert.organization_id ?? "—"}</dd>
        {alert.attempted_account && (
          <>
            <dt>Account</dt>
            <dd className="mono">{alert.attempted_account}</dd>
          </>
        )}
        {alert.actor_id && (
          <>
            <dt>Actor</dt>
            <dd className="mono">{alert.actor_id}</dd>
          </>
        )}
        {alert.session_id && (
          <>
            <dt>Session</dt>
            <dd className="mono">{alert.session_id}</dd>
          </>
        )}
        <dt>Threshold check</dt>
        <dd>
          {rule.countLabel}: {alert.match_count} (threshold {alert.threshold}, window{" "}
          {formatDuration(alert.window_microseconds)})
        </dd>
        <dt>Window</dt>
        <dd>
          {formatUtc(alert.window_start)} → {formatUtc(alert.window_end)}
        </dd>
        {alert.cooldown_microseconds !== null && (
          <>
            <dt>Cooldown</dt>
            <dd>
              {formatDuration(alert.cooldown_microseconds)}; suppressed until{" "}
              {formatUtc(alert.suppression_until)}
            </dd>
          </>
        )}
        <dt>Source IPs</dt>
        <dd className="mono">{alert.source_ips.join(", ") || "—"}</dd>
        {alert.resource_ids.length > 0 && (
          <>
            <dt>Requested resources</dt>
            <dd className="mono">{alert.resource_ids.join(", ")}</dd>
          </>
        )}
        <dt>First detected / updated</dt>
        <dd>
          {formatUtc(alert.created_at)} / {formatUtc(alert.updated_at)}
        </dd>
        <dt>Alert key</dt>
        <dd className="mono">{alert.alert_key}</dd>
      </dl>

      <h2>Evidence ({alert.evidence.length} events, oldest first)</h2>
      {alert.evidence.length > 0 ? (
        <EventTable events={alert.evidence} />
      ) : (
        <EmptyState>This alert has no linked evidence events.</EmptyState>
      )}
    </>
  );
}

function BackLink() {
  return (
    <p>
      <Link to="/alerts">← All alerts</Link>
    </p>
  );
}
