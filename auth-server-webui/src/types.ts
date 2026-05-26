export interface User {
  id: number
  email: string
  display_name: string
  last_login_at?: string
}

export interface AuthClient {
  id: number
  display_name: string
  secret: string
  domain: string
  scopes: string[]
  token_type: number
  created_at?: string
}

export interface AdminEntry {
  id: number
  user_id: number
  email: string
}

export interface SessionInfo {
  user_id: number
  email: string
  display_name: string
}

export interface TokenResponse {
  access_token: string
  refresh_token?: string
  expires_in: number
  token_type: string
  scope: string
}

export interface ApiResponse<T> {
  code: number
  data: T
}
