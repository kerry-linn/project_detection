import type { ApiError } from "../api/client";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p className="muted" role="status">
      {label}
    </p>
  );
}

export function EmptyState({ children }: { children: string }) {
  return <p className="muted">{children}</p>;
}

export function ErrorNotice({ error }: { error: ApiError }) {
  const heading =
    error.status === 403
      ? "Not authorized"
      : error.status === 404
        ? "Not found"
        : "Something went wrong";
  return (
    <div className="notice notice-error" role="alert">
      <strong>{heading}</strong>
      <p>{error.message}</p>
      {error.status === 403 && (
        <p className="muted">The API refused this request for your account's role.</p>
      )}
    </div>
  );
}
