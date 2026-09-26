export interface SecurityEvent {
  event_id: string;
  occurred_at: string;
  ingested_at: string;
  source: string;
  event_type: string;
  organization_id: string | null;
  actor_id: string | null;
  attempted_account: string | null;
  target_actor_id: string | null;
  previous_role: string | null;
  new_role: string | null;
  session_id: string | null;
  source_ip: string | null;
  resource_type: string | null;
  resource_id: string | null;
  outcome: string;
  request_id: string;
  schema_version: string;
  metadata: Record<string, unknown>;
}

export interface EvidenceEvent extends SecurityEvent {
  evidence_role: string;
}
