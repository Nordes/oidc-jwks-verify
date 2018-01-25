export interface Oidc {
  id_token: string;
  session_state: string;
  access_token: string;
  token_type: string;
  scope: string;
  profile: Profile;
  expires_at: number;
}
export interface Profile {
  sid: string;
  sub: string;
  auth_time: number;
  idp: string;
  amr?: (string)[] | null;
  name: string;
  website: string;
}
