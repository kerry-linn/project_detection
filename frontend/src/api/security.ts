import type { AlertDetail, AlertSummary } from "../types/alert";
import { request } from "./client";

export function listAlerts(token: string, includeSuperseded = false): Promise<AlertSummary[]> {
  const query = includeSuperseded ? "?include_superseded=true" : "";
  return request<AlertSummary[]>(`/security/alerts${query}`, { token });
}

export function getAlert(token: string, alertKey: string): Promise<AlertDetail> {
  return request<AlertDetail>(`/security/alerts/${encodeURIComponent(alertKey)}`, { token });
}
