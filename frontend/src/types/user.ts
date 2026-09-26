export type Role = "member" | "organization_admin" | "lab_analyst";

export interface UserProfile {
  user_id: string;
  login: string;
  display_name: string;
  organization_id: string | null;
  role: Role;
}

export interface LoginResponse {
  access_token: string;
  token_type: "bearer";
  expires_at: string;
  user: UserProfile;
}
