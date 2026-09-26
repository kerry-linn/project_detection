import type { LoginResponse, UserProfile } from "../types/user";
import { request } from "./client";

export function login(loginName: string, password: string): Promise<LoginResponse> {
  return request<LoginResponse>("/auth/login", {
    method: "POST",
    body: { login: loginName, password },
  });
}

export function getCurrentUser(token: string): Promise<UserProfile> {
  return request<UserProfile>("/auth/me", { token });
}

export function logout(token: string): Promise<void> {
  return request<void>("/auth/logout", { method: "POST", token });
}
