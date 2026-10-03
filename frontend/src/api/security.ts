import type { AlertDetail, AlertSummary, CaseActivity, CaseDecision } from "../types/alert";
import { request, requestPage } from "./client";

export function listAlerts(token: string, query = "") {
  return requestPage<AlertSummary>(`/security/alerts${query ? `?${query}` : ""}`, token);
}

export function getAlert(token: string, alertKey: string, offset = 0, replacementOffset = 0): Promise<AlertDetail> {
  const query = new URLSearchParams();
  if (offset) query.set("evidence_offset", String(offset));
  if (replacementOffset) query.set("replacement_offset", String(replacementOffset));
  return request<AlertDetail>(`${alertPath(alertKey)}${query.size ? `?${query}` : ""}`, { token });
}

export function updateCase(token: string, key: string, body: CaseDecision) {
  return request(`${alertPath(key)}`, { token, method: "PATCH", body });
}

export function addNote(token: string, key: string, revision: number, body: string) {
  return request(`${alertPath(key)}/notes`, { token, method: "POST", body: { revision, body } });
}

export function listActivity(token: string, key: string, offset: number) {
  return requestPage<CaseActivity>(`${alertPath(key)}/activity?offset=${offset}`, token);
}

function alertPath(key: string) { return `/security/alerts/${encodeURIComponent(key)}`; }
