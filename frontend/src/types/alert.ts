import type { EvidenceEvent } from "./event";

export type AlertStatus = "new" | "investigating" | "closed";

export interface AlertSummary {
  alert_key: string;
  rule_id: string;
  rule_version: string;
  severity: string;
  status: AlertStatus;
  organization_id: string | null;
  attempted_account: string | null;
  actor_id: string | null;
  window_start: string;
  window_end: string;
  threshold: number;
  match_count: number;
  reason: string;
  created_at: string;
  updated_at: string;
}

export interface AlertDetail extends AlertSummary {
  session_id: string | null;
  window_microseconds: number;
  cooldown_microseconds: number | null;
  suppression_until: string | null;
  source_ips: string[];
  resource_ids: string[];
  evidence: EvidenceEvent[];
}
