import { useState } from "react";
import { CaseWorkflow } from "../components/CaseWorkflow";
import { Pagination } from "../components/Pagination";
import { Link, useParams } from "react-router";

import { getAlert } from "../api/security";
import { EventTable } from "../components/EventTable";
import { EmptyState, ErrorNotice, Loading } from "../components/StatusMessage";
import { formatDuration, formatUtc, ruleInfo } from "../format";
import { useApi } from "../hooks/useApi";

export function AlertDetailPage() {
  const alertKey = useParams().alertKey ?? "";
  const [offset, setOffset] = useState(0);
  const [replacementOffset, setReplacementOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const { data: alert, error, loading } = useApi(
    (token) => getAlert(token, alertKey, offset, replacementOffset),
    `alert:${alertKey}:${offset}:${replacementOffset}:${refresh}`,
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
      <BackLink includeHistory={alert.detection_state === "superseded"} />
      <h1>
        {rule.label} · {rule.title}
      </h1>
      <p className="reason">{alert.reason}</p>
      {alert.detection_state === "superseded" && (
        <p role="status">
          This detection was superseded. Its evidence and analyst status remain available.
        </p>
      )}
      {alert.needs_review && <p role="status">New evidence or prior case work requires review for this result.</p>}
      {alert.replaced_by.length > 0 && (
        <div>
          <h2>Replaced by</h2>
          <ul>
            {alert.replaced_by.map((key) => (
              <li key={key}><Link to={`/alerts/${encodeURIComponent(key)}`}>{key}</Link></li>
            ))}
          </ul>
        </div>
      )}
      {alert.replaces.length > 0 && (
        <div>
          <h2>Replaces</h2>
          <ul>
            {alert.replaces.map((key) => (
              <li key={key}><Link to={`/alerts/${encodeURIComponent(key)}`}>{key}</Link></li>
            ))}
          </ul>
        </div>
      )}

      {(alert.replaces_total > 100 || alert.replaced_by_total > 100) && <>
        <p>Replacement links: {alert.replaces_total} predecessors, {alert.replaced_by_total} successors; 100 per page.</p>
        <Pagination label="replacements" offset={replacementOffset} limit={100}
          total={Math.max(alert.replaces_total, alert.replaced_by_total)} onChange={setReplacementOffset} />
      </>}
      <dl className="facts">
        <dt>Rule</dt>
        <dd className="mono">
          {alert.rule_id} v{alert.rule_version}
        </dd>
        <dt>Severity / status</dt>
        <dd>
          {alert.severity} / {alert.status}
        </dd>
        <dt>Detection state</dt>
        <dd>{alert.detection_state}</dd>
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
        <dt>Source IPs on this evidence page</dt>
        <dd className="mono">{alert.source_ips.join(", ") || "—"}</dd>
        {alert.resource_ids.length > 0 && (
          <>
            <dt>Requested resources on this evidence page</dt>
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

      {alert.cooldown_microseconds !== null && <p>
        R2 opens when {alert.threshold} distinct documents are denied within {formatDuration(alert.window_microseconds)}.
        The episode-wide count is {alert.match_count}; continued denials can extend the episode beyond that opening window.
      </p>}
      <h2>Evidence ({alert.evidence_total} events total, oldest first)</h2>
      <p>Showing {alert.evidence.length} events from offset {alert.evidence_offset}.</p>
      <Pagination label="evidence" offset={offset} total={alert.evidence_total}
        limit={alert.evidence_limit} onChange={setOffset} />
      {alert.evidence.length > 0 ? (
        <EventTable events={alert.evidence} />
      ) : (
        <EmptyState>No evidence on this page.</EmptyState>
      )}
      <CaseWorkflow key={`${alertKey}:${alert.revision}`} alert={alert} onSaved={() => setRefresh(refresh + 1)} />
    </>
  );
}

function BackLink({ includeHistory = false }: { includeHistory?: boolean }) {
  return (
    <p>
      <Link to={includeHistory ? "/alerts?history=true" : "/alerts"}>← All alerts</Link>
    </p>
  );
}
