import { useState } from "react";

import { formatUtc } from "../format";
import type { EvidenceEvent } from "../types/event";

const COLUMNS = [
  "Occurred",
  "Evidence role",
  "Event type",
  "Outcome",
  "Actor / account",
  "Resource",
  "Source IP",
  "Context",
  "Raw",
];

export function EventTable({ events }: { events: EvidenceEvent[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {COLUMNS.map((column) => (
              <th key={column} scope="col">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <EventRow key={event.event_id} event={event} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EventRow({ event }: { event: EvidenceEvent }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <>
      <tr>
        <td className="nowrap">{formatUtc(event.occurred_at, { milliseconds: true })}</td>
        <td>{event.evidence_role}</td>
        <td>{event.event_type}</td>
        <td>{event.outcome}</td>
        <td className="mono">{event.actor_id ?? event.attempted_account ?? "—"}</td>
        <td className="mono">{event.resource_id ?? "—"}</td>
        <td className="mono">{event.source_ip ?? "—"}</td>
        <td className="mono">
          <Metadata values={event.metadata} />
        </td>
        <td>
          <button
            type="button"
            aria-expanded={expanded}
            aria-label={`Raw event ${event.event_id}`}
            onClick={() => setExpanded(!expanded)}
          >
            JSON
          </button>
        </td>
      </tr>
      {expanded && (
        <tr className="raw-event">
          <td colSpan={COLUMNS.length}>
            <pre>{JSON.stringify(event, null, 2)}</pre>
          </td>
        </tr>
      )}
    </>
  );
}

function Metadata({ values }: { values: Record<string, unknown> }) {
  const entries = Object.entries(values);
  if (entries.length === 0) return <>—</>;
  return (
    <>
      {entries.map(([key, value]) => (
        <div key={key}>
          {key}={typeof value === "string" ? value : JSON.stringify(value)}
        </div>
      ))}
    </>
  );
}
