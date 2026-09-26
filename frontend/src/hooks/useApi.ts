import { useEffect, useState } from "react";

import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";

interface ApiState<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
}

/** Loads data with the current session; `key` identifies the resource so a
 * change (for example a new route parameter) triggers a fresh request. */
export function useApi<T>(load: (token: string) => Promise<T>, key: string): ApiState<T> {
  const { token, expire } = useAuth();
  const [state, setState] = useState<ApiState<T>>({ data: null, error: null, loading: true });

  useEffect(() => {
    if (token === null) {
      return;
    }
    let active = true;
    setState({ data: null, error: null, loading: true });
    load(token).then(
      (data) => active && setState({ data, error: null, loading: false }),
      (error: unknown) => {
        if (!active) return;
        const apiError =
          error instanceof ApiError ? error : new ApiError(0, "Unexpected error.");
        if (apiError.status === 401) {
          expire();
          return;
        }
        setState({ data: null, error: apiError, loading: false });
      },
    );
    return () => {
      active = false;
    };
  }, [token, key, expire]);

  return state;
}
