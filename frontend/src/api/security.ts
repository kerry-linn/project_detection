import type { AlertDetail, AlertSummary } from "../types/alert";
import { request } from "./client";

export function listAlerts(token: string): Promise<AlertSummary[]> {
  return request<AlertSummary[]>("/security/alerts", { token });
}

export function getAlert(token: string, alertKey: string): Promise<AlertDetail> {
  return request<AlertDetail>(`/security/alerts/${encodeURIComponent(alertKey)}`, { token });
}
