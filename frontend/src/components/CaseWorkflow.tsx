import { useState } from "react";
import { addNote, listActivity, updateCase } from "../api/security";
import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { useApi } from "../hooks/useApi";
import { formatUtc } from "../format";
import type { AlertDetail, AlertStatus, Disposition } from "../types/alert";
import { ErrorNotice, Loading } from "./StatusMessage";
import { Pagination } from "./Pagination";

export function CaseWorkflow({ alert, onSaved }: { alert: AlertDetail; onSaved: () => void }) {
  const { token, expire } = useAuth();
  const [status, setStatus] = useState<AlertStatus>(alert.status);
  const [disposition, setDisposition] = useState<Disposition | "">(alert.disposition ?? "");
  const [rationale, setRationale] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  const [saving, setSaving] = useState(false);
  const [offset, setOffset] = useState(0);
  const activity = useApi((value) => listActivity(value, alert.alert_key, offset),
    `activity:${alert.alert_key}:${alert.revision}:${offset}`);

  async function save(kind: "decision" | "note") {
    if (!token) return;
    setSaving(true); setError(null);
    try {
      if (kind === "note") await addNote(token, alert.alert_key, alert.revision, note);
      else await updateCase(token, alert.alert_key, {
        revision: alert.revision, status,
        disposition: status === "closed" && disposition ? disposition : null, rationale,
      });
      onSaved();
    } catch (failure) {
      const problem = failure instanceof ApiError ? failure : new ApiError(0, "Unable to save case.");
      if (problem.status === 401) expire();
      else setError(problem);
    } finally { setSaving(false); }
  }

  return (
    <section aria-label="Case workflow">
      <h2>Case decision</h2>
      <p>Disposition: {alert.disposition ?? "undecided"}. {alert.rationale}</p>
      <p className="muted">Reopening clears the current disposition. Previous decisions remain in history.
        Saving a decision acknowledges the current evidence and clears the review flag.</p>
      {error && <><ErrorNotice error={error} /><button onClick={onSaved}>Reload case</button></>}
      <form className="case-form" onSubmit={(event) => { event.preventDefault(); void save("decision"); }}>
        <label className="field">Case status
          <select value={status} onChange={(event) => setStatus(event.target.value as AlertStatus)}>
            <option value="new">new</option><option value="investigating">investigating</option>
            <option value="closed">closed</option>
          </select>
        </label>
        {status === "closed" && <label className="field">Disposition
          <select required value={disposition} onChange={(event) => setDisposition(event.target.value as Disposition)}>
            <option value="">Choose a conclusion</option>
            <option value="benign">benign</option><option value="suspicious">suspicious</option>
            <option value="inconclusive">inconclusive</option>
          </select>
        </label>}
        <label className="field">Rationale
          <textarea required maxLength={2000} value={rationale} onChange={(event) => setRationale(event.target.value)} />
        </label>
        <button disabled={saving || !rationale.trim() || (status === "closed" && !disposition)}>Save decision</button>
      </form>
      <form className="case-form" onSubmit={(event) => { event.preventDefault(); void save("note"); }}>
        <label className="field">Investigation note
          <textarea required maxLength={2000} value={note} onChange={(event) => setNote(event.target.value)} />
        </label>
        <button disabled={saving || !note.trim()}>Add note</button>
      </form>
      <h2>Case history</h2>
      {activity.loading && <Loading />}
      {activity.error && <ErrorNotice error={activity.error} />}
      {activity.data && <>
        <p>Showing {activity.data.items.length} of {activity.data.total} entries, newest first</p>
        <Pagination label="history" offset={offset} total={activity.data.total} onChange={setOffset} />
        <ol>{activity.data.items.map((item) => <li key={item.activity_id}>
          <p>{formatUtc(item.created_at)} · {item.author_id} · {item.kind} · {item.status}
            {item.disposition ? ` / ${item.disposition}` : ""} · revision {item.revision}</p>
          <p className="case-text">{item.body}</p>
        </li>)}</ol>
      </>}
    </section>
  );
}
