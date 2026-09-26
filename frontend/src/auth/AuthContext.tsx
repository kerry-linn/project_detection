import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import * as authApi from "../api/auth";
import { ApiError } from "../api/client";
import type { UserProfile } from "../types/user";

export const TOKEN_STORAGE_KEY = "security-lab.session-token";

interface AuthState {
  token: string | null;
  user: UserProfile | null;
  restoring: boolean;
  notice: string | null;
  signIn: (login: string, password: string) => Promise<UserProfile>;
  signOut: () => Promise<void>;
  expire: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() =>
    sessionStorage.getItem(TOKEN_STORAGE_KEY),
  );
  const [user, setUser] = useState<UserProfile | null>(null);
  const [restoring, setRestoring] = useState(token !== null);
  const [notice, setNotice] = useState<string | null>(null);

  const clearSession = useCallback((message: string | null) => {
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    setToken(null);
    setUser(null);
    setNotice(message);
  }, []);

  useEffect(() => {
    if (!restoring || token === null) {
      return;
    }
    let active = true;
    authApi
      .getCurrentUser(token)
      .then(
        (profile) => active && setUser(profile),
        (error: unknown) => {
          if (!active) return;
          const expired = error instanceof ApiError && error.status === 401;
          clearSession(
            expired ? "Your session has expired. Sign in again." : errorText(error),
          );
        },
      )
      .finally(() => active && setRestoring(false));
    return () => {
      active = false;
    };
  }, [restoring, token, clearSession]);

  const signIn = useCallback(async (login: string, password: string) => {
    const response = await authApi.login(login, password);
    sessionStorage.setItem(TOKEN_STORAGE_KEY, response.access_token);
    setToken(response.access_token);
    setUser(response.user);
    setNotice(null);
    return response.user;
  }, []);

  const signOut = useCallback(async () => {
    if (token !== null) {
      await authApi.logout(token).catch(() => undefined);
    }
    clearSession(null);
  }, [token, clearSession]);

  const expire = useCallback(
    () => clearSession("Your session has expired. Sign in again."),
    [clearSession],
  );

  const value = useMemo(
    () => ({ token, user, restoring, notice, signIn, signOut, expire }),
    [token, user, restoring, notice, signIn, signOut, expire],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return context;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error.";
}
