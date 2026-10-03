import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { AuthProvider, TOKEN_STORAGE_KEY } from "./auth/AuthContext";
import type { AlertDetail, AlertSummary } from "./types/alert";
import type { UserProfile } from "./types/user";

const ANALYST: UserProfile = {
  user_id: "user-analyst",
  login: "analyst@lab.example.test",
  display_name: "Lab Analyst",
  organization_id: null,
  role: "lab_analyst",
};

const BOB: UserProfile = {
  user_id: "user-bob",
  login: "bob@alpha.example.test",
  display_name: "Bob",
  organization_id: "org-alpha",
  role: "member",
};

const R1_ALERT: AlertSummary = {
  alert_key: "R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS:1.0:threshold=5:window_us=600000000:app-1",
  rule_id: "R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS",
  rule_version: "1.0",
  severity: "medium",
  status: "new",
  detection_state: "active",
  needs_review: false,
  disposition: null,
  rationale: null,
  revision: 0,
  organization_id: "org-alpha",
  attempted_account: "alice@alpha.example.test",
  actor_id: "user-alice",
  window_start: "2026-09-25T10:25:00Z",
  window_end: "2026-09-25T10:35:00Z",
  threshold: 5,
  match_count: 5,
  reason: "5 failed logins for alice@alpha.example.test were followed by a success",
  created_at: "2026-09-25T10:40:00Z",
  updated_at: "2026-09-25T10:40:00Z",
};

const R2_ALERT: AlertSummary = {
  ...R1_ALERT,
  alert_key: "R2_REPEATED_DENIED_DOCUMENT_ACCESS:1.0:threshold=5:org-alpha:user-bob:app-9",
  rule_id: "R2_REPEATED_DENIED_DOCUMENT_ACCESS",
  attempted_account: null,
  actor_id: "user-bob",
  window_start: "2026-09-25T12:00:00Z",
  window_end: "2026-09-25T12:04:00Z",
  reason: "user-bob in org-alpha was denied access to 5 distinct documents",
};

function denial(index: number, documentId: string, reason: string) {
  return {
    evidence_role: "denied_document_access",
    event_id: `app-${index}`,
    occurred_at: `2026-09-25T12:0${index}:00Z`,
    ingested_at: `2026-09-25T12:0${index}:00Z`,
    source: "application",
    event_type: "access_denied",
    organization_id: "org-alpha",
    actor_id: "user-bob",
    attempted_account: null,
    target_actor_id: null,
    previous_role: null,
    new_role: null,
    session_id: "sess-bob",
    source_ip: "127.0.0.1",
    resource_type: "document",
    resource_id: documentId,
    outcome: "denied",
    request_id: `req-${index}`,
    schema_version: "1.0",
    metadata: { action: "read", reason },
  };
}

const R2_DETAIL: AlertDetail = {
  ...R2_ALERT,
  session_id: null,
  window_microseconds: 300_000_000,
  cooldown_microseconds: 900_000_000,
  suppression_until: "2026-09-25T12:19:00Z",
  source_ips: ["127.0.0.1"],
  resource_ids: ["doc-alpha-001", "doc-alpha-002", "doc-alpha-003", "doc-alpha-005", "doc-beta-001"],
  evidence: [
    denial(0, "doc-alpha-001", "not_owner"),
    denial(1, "doc-alpha-002", "not_owner"),
    denial(2, "doc-alpha-003", "not_owner"),
    denial(3, "doc-alpha-005", "not_owner"),
    denial(4, "doc-beta-001", "cross_organization"),
  ],
  evidence_total: 5,
  evidence_offset: 0,
  evidence_limit: 50,
  replaces_total: 0,
  replaced_by_total: 0,
  replaces: [],
  replaced_by: [],
};

type Reply = [status: number, body?: unknown];

function mockApi(routes: Record<string, Reply>) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    let reply = routes[`${init?.method ?? "GET"} ${url}`];
    let total: number | undefined;
    if (!reply && url.startsWith("/api/security/alerts?")) {
      const query = new URL(url, "http://localhost").searchParams;
      const base = query.get("include_superseded") === "true"
        ? "/api/security/alerts?include_superseded=true" : "/api/security/alerts";
      const source = routes[`GET ${base}`];
      if (source && Array.isArray(source[1])) {
        const items = (source[1] as AlertSummary[]).filter((alert) =>
          (!query.get("rule") || alert.rule_id === query.get("rule")) &&
          (!query.get("status") || alert.status === query.get("status")) &&
          (!query.get("organization") || alert.organization_id === query.get("organization")) &&
          (!query.get("entity") || `${alert.actor_id} ${alert.attempted_account}`.toLowerCase().includes(query.get("entity")!.toLowerCase())));
        total = items.length;
        const offset = Number(query.get("offset") ?? 0);
        reply = [200, items.slice(offset, offset + 50)];
      }
    }
    if (!reply && url.includes("/activity?")) reply = [200, []];
    if (!reply) throw new Error(`unexpected request ${init?.method ?? "GET"} ${url}`);
    const [status, body] = reply;
    return new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json", ...(total === undefined ? {} : { "X-Total-Count": String(total) }) },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderApp(path: string, token?: string) {
  if (token) sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

function authorizationOf(fetchMock: ReturnType<typeof mockApi>, url: string) {
  const call = fetchMock.mock.calls.find(([calledUrl]) => calledUrl === url);
  return (call?.[1]?.headers as Record<string, string> | undefined)?.Authorization;
}

describe("authentication", () => {
  it("signs in and sends the opaque token on later requests", async () => {
    const fetchMock = mockApi({
      "POST /api/auth/login": [
        200,
        { access_token: "tok-analyst", token_type: "bearer", expires_at: "2026-09-25T20:00:00Z", user: ANALYST },
      ],
      "GET /api/security/alerts": [200, [R1_ALERT]],
    });
    renderApp("/login");

    await userEvent.type(screen.getByLabelText("Login"), ANALYST.login);
    await userEvent.type(screen.getByLabelText("Password"), "lab-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("heading", { name: "Security alerts" })).toBeInTheDocument();
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBe("tok-analyst");
    expect(authorizationOf(fetchMock, "/api/security/alerts")).toBe("Bearer tok-analyst");
  });

  it("shows the server's generic error for bad credentials", async () => {
    mockApi({ "POST /api/auth/login": [401, { detail: "invalid login or password" }] });
    renderApp("/login");

    await userEvent.type(screen.getByLabelText("Login"), "bob@alpha.example.test");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("invalid login or password");
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it("returns to login and discards the token when the API answers 401", async () => {
    mockApi({
      "GET /api/auth/me": [200, BOB],
      "GET /api/documents": [401, { detail: "authentication required" }],
    });
    renderApp("/documents", "tok-expired");

    expect(await screen.findByText(/session has expired/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it("renders a 403 as not authorized without ending the session", async () => {
    mockApi({
      "GET /api/auth/me": [200, BOB],
      "GET /api/security/alerts": [403, { detail: "lab analyst role required" }],
    });
    renderApp("/alerts", "tok-bob");

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent("Not authorized");
    expect(notice).toHaveTextContent("lab analyst role required");
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBe("tok-bob");
    expect(screen.queryByRole("link", { name: "Alerts" })).not.toBeInTheDocument();
  });
});

describe("documents", () => {
  it("shows the API's uniform 404 for another tenant's document", async () => {
    mockApi({
      "GET /api/auth/me": [200, BOB],
      "GET /api/documents/doc-beta-001": [404, { detail: "document not found" }],
    });
    renderApp("/documents/doc-beta-001", "tok-bob");

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent("Not found");
    expect(notice).toHaveTextContent("document not found");
  });
});

describe("analyst investigation", () => {
  it("shows superseded results only when history is requested", async () => {
    const superseded = {
      ...R2_ALERT,
      alert_key: `${R2_ALERT.alert_key}-old`,
      detection_state: "superseded" as const,
    };
    const fetchMock = mockApi({
      "GET /api/auth/me": [200, ANALYST],
      "GET /api/security/alerts": [200, [R2_ALERT]],
      "GET /api/security/alerts?include_superseded=true": [200, [R2_ALERT, superseded]],
    });
    renderApp("/alerts", "tok-analyst");

    expect(await screen.findByText("Showing 1 of 1 alerts")).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText("Include superseded alerts"));
    expect(await screen.findByText("Showing 2 of 2 alerts")).toBeInTheDocument();
    expect(screen.getByText("new · superseded")).toBeInTheDocument();
    expect(authorizationOf(fetchMock, "/api/security/alerts?include_superseded=true")).toBe(
      "Bearer tok-analyst",
    );
  });

  it("filters alerts by rule and by actor or account", async () => {
    mockApi({
      "GET /api/auth/me": [200, ANALYST],
      "GET /api/security/alerts": [200, [R1_ALERT, R2_ALERT]],
    });
    renderApp("/alerts", "tok-analyst");
    await screen.findByText("Showing 2 of 2 alerts");

    await userEvent.selectOptions(screen.getByLabelText("Rule"), R2_ALERT.rule_id);
    expect(await screen.findByText("Showing 1 of 1 alerts")).toBeInTheDocument();
    expect(screen.getByText("user-bob")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Clear" }));
    await userEvent.type(screen.getByLabelText("Actor or account"), "ALICE@");
    expect(screen.getByLabelText("Actor or account")).toHaveValue("ALICE@");
    expect(await screen.findByText("Showing 1 of 1 alerts")).toBeInTheDocument();
    expect(screen.getByText("alice@alpha.example.test")).toBeInTheDocument();
  });

  it("restores URL filters and preserves history when filters are cleared", async () => {
    mockApi({
      "GET /api/auth/me": [200, ANALYST],
      "GET /api/security/alerts": [200, [R1_ALERT, R2_ALERT]],
      "GET /api/security/alerts?include_superseded=true": [200, [R1_ALERT, R2_ALERT]],
    });
    renderApp(
      `/alerts?history=true&rule=${R2_ALERT.rule_id}&status=new&organization=org-alpha&entity=BOB`,
      "tok-analyst",
    );

    await screen.findByText("Showing 1 of 1 alerts");
    expect(screen.getByLabelText("Rule")).toHaveValue(R2_ALERT.rule_id);
    expect(screen.getByLabelText("Status")).toHaveValue("new");
    expect(screen.getByLabelText("Organization")).toHaveValue("org-alpha");
    expect(screen.getByLabelText("Actor or account")).toHaveValue("BOB");

    await userEvent.click(screen.getByLabelText("Include superseded alerts"));
    await screen.findByText("Showing 1 of 1 alerts");
    expect(screen.getByLabelText("Rule")).toHaveValue(R2_ALERT.rule_id);
    expect(screen.getByLabelText("Actor or account")).toHaveValue("BOB");

    await userEvent.click(screen.getByLabelText("Include superseded alerts"));
    await screen.findByText("Showing 1 of 1 alerts");
    await userEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(await screen.findByText("Showing 2 of 2 alerts")).toBeInTheDocument();
    expect(screen.getByLabelText("Include superseded alerts")).toBeChecked();
    expect(screen.getByLabelText("Rule")).toHaveValue("");
    expect(screen.getByLabelText("Status")).toHaveValue("");
    expect(screen.getByLabelText("Organization")).toHaveValue("");
    expect(screen.getByLabelText("Actor or account")).toHaveValue("");
  });

  it("follows an alert to its reason and time-ordered raw evidence", async () => {
    mockApi({
      "GET /api/auth/me": [200, ANALYST],
      [`GET /api/security/alerts/${encodeURIComponent(R2_ALERT.alert_key)}`]: [200, R2_DETAIL],
    });
    renderApp(`/alerts/${encodeURIComponent(R2_ALERT.alert_key)}`, "tok-analyst");

    expect(
      await screen.findByRole("heading", { name: "R2 · Repeated denied document access" }),
    ).toBeInTheDocument();
    expect(screen.getByText(R2_ALERT.reason)).toBeInTheDocument();
    expect(screen.getByText(/Distinct denied documents: 5 \(threshold 5, window 5 minutes\)/)).toBeInTheDocument();

    const rows = within(screen.getAllByRole("table")[0]).getAllByRole("row").slice(1);
    expect(rows.map((row) => within(row).getAllByRole("cell")[5].textContent)).toEqual([
      "doc-alpha-001",
      "doc-alpha-002",
      "doc-alpha-003",
      "doc-alpha-005",
      "doc-beta-001",
    ]);
    expect(rows[4]).toHaveTextContent("reason=cross_organization");
    expect(rows[0]).toHaveTextContent("2026-09-25 12:00:00.000 UTC");

    await userEvent.click(screen.getByRole("button", { name: "Raw event app-4" }));
    expect(screen.getByText(/"request_id": "req-4"/)).toBeInTheDocument();
  });
});

describe("case changes and bounded evidence", () => {
  it("submits a disposition with the displayed revision and handles conflicts", async () => {
    const path = `/api/security/alerts/${encodeURIComponent(R2_ALERT.alert_key)}`;
    const fetchMock = mockApi({
      "GET /api/auth/me": [200, ANALYST],
      [`GET ${path}`]: [200, R2_DETAIL],
      [`PATCH ${path}`]: [409, { detail: "case changed; reload before saving" }],
    });
    renderApp(`/alerts/${encodeURIComponent(R2_ALERT.alert_key)}`, "tok-analyst");
    await screen.findByLabelText("Case status");
    await userEvent.selectOptions(screen.getByLabelText("Case status"), "closed");
    expect(screen.getByRole("button", { name: "Save decision" })).toBeDisabled();
    await userEvent.selectOptions(screen.getByLabelText("Disposition"), "benign");
    await userEvent.type(screen.getByLabelText("Rationale"), "Approved stale bookmark test.");
    await userEvent.click(screen.getByRole("button", { name: "Save decision" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("case changed; reload before saving");
    expect(screen.getByLabelText("Rationale")).toHaveValue("Approved stale bookmark test.");
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH");
    expect(JSON.parse(call![1]!.body as string)).toEqual({
      revision: 0, status: "closed", disposition: "benign", rationale: "Approved stale bookmark test.",
    });
  });

  it("paginates evidence without presenting one page as the complete case", async () => {
    const path = `/api/security/alerts/${encodeURIComponent(R2_ALERT.alert_key)}`;
    mockApi({
      "GET /api/auth/me": [200, ANALYST],
      [`GET ${path}`]: [200, { ...R2_DETAIL, evidence: [R2_DETAIL.evidence[0]], evidence_limit: 1 }],
      [`GET ${path}?evidence_offset=1`]: [200, {
        ...R2_DETAIL, evidence: [R2_DETAIL.evidence[1]], evidence_limit: 1, evidence_offset: 1,
      }],
    });
    renderApp(`/alerts/${encodeURIComponent(R2_ALERT.alert_key)}`, "tok-analyst");
    expect(await screen.findByText("Evidence (5 events total, oldest first)")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Next evidence" }));
    expect(await screen.findByText("Showing 1 events from offset 1.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Raw event app-1" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Raw event app-0" })).not.toBeInTheDocument();
  });

  it("expires the session when a case write returns 401", async () => {
    const path = `/api/security/alerts/${encodeURIComponent(R2_ALERT.alert_key)}`;
    mockApi({
      "GET /api/auth/me": [200, ANALYST], [`GET ${path}`]: [200, R2_DETAIL],
      [`POST ${path}/notes`]: [401, { detail: "invalid or expired session" }],
    });
    renderApp(`/alerts/${encodeURIComponent(R2_ALERT.alert_key)}`, "tok-analyst");
    await userEvent.type(await screen.findByLabelText("Investigation note"), "Review evidence.");
    await userEvent.click(screen.getByRole("button", { name: "Add note" }));
    expect(await screen.findByText(/session has expired/)).toBeInTheDocument();
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });
});
