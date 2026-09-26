import type { AlertSummary } from "./types/alert";
import type { Role } from "./types/user";

interface RuleInfo {
  label: string;
  title: string;
  countLabel: string;
}

const RULES: Record<string, RuleInfo> = {
  R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS: {
    label: "R1",
    title: "Failed logins followed by success",
    countLabel: "Failed logins",
  },
  R2_REPEATED_DENIED_DOCUMENT_ACCESS: {
    label: "R2",
    title: "Repeated denied document access",
    countLabel: "Distinct denied documents",
  },
};

export function ruleInfo(ruleId: string): RuleInfo {
  return RULES[ruleId] ?? { label: ruleId, title: ruleId, countLabel: "Matches" };
}

export function alertEntity(alert: AlertSummary): string {
  return alert.attempted_account ?? alert.actor_id ?? "—";
}

export function formatUtc(value: string | null, { milliseconds = false } = {}): string {
  if (value === null) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${date.toISOString().slice(0, milliseconds ? 23 : 19).replace("T", " ")} UTC`;
}

export function formatDuration(microseconds: number): string {
  const seconds = Math.round(microseconds / 1_000_000);
  if (seconds % 60 !== 0) return `${seconds} seconds`;
  const minutes = seconds / 60;
  return minutes === 1 ? "1 minute" : `${minutes} minutes`;
}

export function roleLabel(role: Role): string {
  return {
    member: "Member",
    organization_admin: "Organization admin",
    lab_analyst: "Lab analyst",
  }[role];
}

export function homePath(role: Role): string {
  return role === "lab_analyst" ? "/alerts" : "/documents";
}
