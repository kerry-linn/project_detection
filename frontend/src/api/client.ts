export const API_BASE = "/api";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

interface RequestOptions {
  token?: string | null;
  method?: "GET" | "POST" | "PATCH";
  body?: unknown;
}

async function send(path: string, options: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method: options.method ?? "GET",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch {
    throw new ApiError(0, "The API is unreachable. Is the backend running?");
  }

  if (!response.ok) {
    throw new ApiError(response.status, await errorMessage(response));
  }
  return response;
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string") {
      return body.detail;
    }
    if (response.status === 422) {
      return "The request was rejected as invalid.";
    }
  } catch {
    // Non-JSON error bodies fall through to the generic message.
  }
  return `Request failed with status ${response.status}.`;
}


export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await send(path, options);
  return response.status === 204 ? undefined as T : await response.json() as T;
}

export interface Page<T> { items: T[]; total: number }

export async function requestPage<T>(path: string, token: string): Promise<Page<T>> {
  const response = await send(path, { token });
  const items = await response.json() as T[];
  return { items, total: Number(response.headers.get("X-Total-Count") ?? items.length) };
}
