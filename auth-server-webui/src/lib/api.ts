import type { User, AuthClient, AdminEntry, SessionInfo, ApiResponse } from '../types'

class ApiClient {
  private token: string | null = null

  setToken(token: string | null) {
    this.token = token
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    }
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
    }
    const resp = await fetch(path, { ...options, headers })
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${await resp.text()}`)
    }
    const json: ApiResponse<T> = await resp.json()
    if (json.code !== 0) {
      throw new Error(`API error: ${JSON.stringify(json)}`)
    }
    return json.data
  }

  // Users
  async getUsers(): Promise<User[]> {
    return this.request<User[]>('/api/admin/users')
  }
  async createUser(email: string, displayName: string, password: string): Promise<void> {
    return this.request<void>('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify({ email, display_name: displayName, password }),
    })
  }
  async deleteUser(id: number): Promise<void> {
    return this.request<void>(`/api/admin/users/${id}`, { method: 'DELETE' })
  }

  // Clients
  async getClients(): Promise<AuthClient[]> {
    return this.request<AuthClient[]>('/api/admin/clients')
  }
  async createClient(data: {
    display_name: string
    domain: string
    secret: string
    scopes: string[]
    token_type: number
  }): Promise<{ secret: string }> {
    return this.request<{ secret: string }>('/api/admin/clients', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }
  async deleteClient(id: number): Promise<void> {
    return this.request<void>(`/api/admin/clients/${id}`, { method: 'DELETE' })
  }

  // Admins
  async getAdmins(): Promise<AdminEntry[]> {
    return this.request<AdminEntry[]>('/api/admin/admins')
  }
  async addAdmin(userId: number): Promise<void> {
    return this.request<void>('/api/admin/admins', {
      method: 'POST',
      body: JSON.stringify({ user_id: userId }),
    })
  }
  async removeAdmin(userId: number): Promise<void> {
    return this.request<void>(`/api/admin/admins/${userId}`, { method: 'DELETE' })
  }

  // Sessions
  async getSessions(): Promise<SessionInfo[]> {
    return this.request<SessionInfo[]>('/api/admin/sessions')
  }
  async revokeSession(userId: number): Promise<void> {
    return this.request<void>(`/api/admin/sessions/${userId}`, { method: 'DELETE' })
  }
}

export const api = new ApiClient()
