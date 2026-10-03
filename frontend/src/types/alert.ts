import type { EvidenceEvent } from "./event";

export type AlertStatus = "new" | "investigating" | "closed";

export interface AlertSummary {
  alert_key: string;
  rule_id: string;
  rule_version: string;
  severity: string;
  status: AlertStatus;
  detection_state: "active" | "superseded";
  needs_review: boolean;
  disposition: Disposition | null;
  rationale: string | null;
  revision: number;
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
  evidence_total: number;
  evidence_offset: number;
  evidence_limit: number;
  replaces_total: number;
  replaced_by_total: number;
  replaces: string[];
  replaced_by: string[];
}


export type Disposition = "benign" | "suspicious" | "inconclusive";
export interface CaseDecision {
  revision: number;
  status: AlertStatus;
  disposition: Disposition | null;
  rationale: string;
}
export interface CaseActivity {
  activity_id: number;
  author_id: string;
  created_at: string;
  revision: number;
  kind: "decision" | "note";
  status: AlertStatus;
  disposition: Disposition | null;
  body: string;
}
