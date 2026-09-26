import { useState } from "react";
import type { FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";

import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { homePath } from "../format";

export function LoginPage() {
  const { user, restoring, notice, signIn } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from;

  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!restoring && user !== null) {
    return <Navigate to={homePath(user.role)} replace />;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const profile = await signIn(login, password);
      navigate(from ?? homePath(profile.role), { replace: true });
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Unexpected error.");
      setSubmitting(false);
    }
  }

  return (
    <div className="login">
      <h1>Sign in</h1>
      {notice && !error && (
        <div className="notice" role="status">
          {notice}
        </div>
      )}
      {error && (
        <div className="notice notice-error" role="alert">
          {error}
        </div>
      )}
      <form onSubmit={handleSubmit}>
        <label className="field">
          Login
          <input
            name="login"
            autoComplete="username"
            value={login}
            onChange={(event) => setLogin(event.target.value)}
            required
          />
        </label>
        <label className="field">
          Password
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </label>
        <button type="submit" className="primary" disabled={submitting}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
