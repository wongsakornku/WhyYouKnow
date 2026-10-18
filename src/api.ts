import type {
  AdminDashboardStats,
  AdminUserDetails,
  AdminUserListItem,
  AppInvite,
  AppUser,
  AttackProtectionConfig,
  AuditLog,
  ClientInfo,
  OAuthClient,
  UserDashboardData,
  UserProfile,
} from './types/auth'

async function request<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const errorData = await res.json().catch(() => null)
    throw new Error(errorData?.detail || String(res.status))
  }
  return res.json() as Promise<T>
}

export const api = {
  me: () => request<UserProfile>('/api/me'),
  userDashboard: () => request<UserDashboardData>('/api/me/dashboard'),
  userDisconnectApp: (clientId: string) =>
    request<{ ok: boolean }>(`/api/me/apps/${encodeURIComponent(clientId)}`, 'DELETE'),
  login: (credential: string) => request<UserProfile>('/api/auth/google', 'POST', { credential }),
  logout: () => request<{ ok: boolean }>('/api/auth/logout', 'POST'),
  deleteAccount: () => request<{ ok: boolean }>('/api/me', 'DELETE'),
  adminDashboardStats: () => request<AdminDashboardStats>('/api/admin/dashboard-stats'),
  adminUsers: () => request<AdminUserListItem[]>('/api/admin/users'),

  // OAuth 2.0
  getClientInfo: (clientId: string) =>
    request<ClientInfo>(`/api/oauth/client-info?client_id=${encodeURIComponent(clientId)}`),
  authorizeOAuth: (data: {
    client_id: string
    redirect_uri: string
    code_challenge?: string
    code_challenge_method?: string
    bot_token?: string
  }) => request<{ code: string; redirect_uri: string }>('/api/oauth/authorize', 'POST', data),

  // Admin OAuth Clients
  adminClients: () => request<OAuthClient[]>('/api/admin/clients'),
  adminCreateClient: (data: {
    client_name: string
    redirect_uris: string[]
    is_confidential: boolean
  }) =>
    request<{
      client_id: string
      client_secret: string | null
      client_name: string
      redirect_uris: string[]
      is_confidential: boolean
    }>('/api/admin/clients', 'POST', data),
  adminUpdateClient: (
    clientId: string,
    data: {
      client_name?: string
      redirect_uris?: string[]
      is_active?: boolean
      access_mode?: 'open' | 'invite_only'
    }
  ) =>
    request<{
      client_id: string
      client_name: string
      redirect_uris: string[]
      is_active: boolean
      access_mode: string
    }>(`/api/admin/clients/${encodeURIComponent(clientId)}`, 'PATCH', data),
  adminRotateClientSecret: (clientId: string) =>
    request<{
      client_id: string
      client_secret: string
      message: string
    }>(`/api/admin/clients/${encodeURIComponent(clientId)}/rotate-secret`, 'POST'),
  adminDeleteClient: (clientId: string) =>
    request<{ ok: boolean }>(`/api/admin/clients/${encodeURIComponent(clientId)}`, 'DELETE'),
  adminUpdateAttackProtection: (
    clientId: string,
    data: Partial<AttackProtectionConfig>
  ) =>
    request<{ client_id: string; attack_protection: AttackProtectionConfig }>(
      `/api/admin/clients/${encodeURIComponent(clientId)}/attack-protection`,
      'PATCH',
      data
    ),

  // Admin App Invites
  adminGetAppInvites: (clientId: string) =>
    request<AppInvite[]>(`/api/admin/clients/${encodeURIComponent(clientId)}/invites`),
  adminAddAppInvite: (
    clientId: string,
    data: { email: string; initial_role?: 'admin' | 'member' | 'viewer' }
  ) =>
    request<AppInvite>(`/api/admin/clients/${encodeURIComponent(clientId)}/invites`, 'POST', data),
  adminDeleteAppInvite: (clientId: string, inviteId: number) =>
    request<{ ok: boolean }>(
      `/api/admin/clients/${encodeURIComponent(clientId)}/invites/${inviteId}`,
      'DELETE'
    ),

  // Admin Users by App
  adminGetAppUsers: (clientId: string) =>
    request<AppUser[]>(`/api/admin/clients/${encodeURIComponent(clientId)}/users`),
  adminUpdateAppUserRole: (clientId: string, userId: number, role: string) =>
    request<{ ok: boolean; role: string }>(
      `/api/admin/clients/${encodeURIComponent(clientId)}/users/${userId}/role`,
      'POST',
      { role }
    ),
  adminUpdateAppUserStatus: (clientId: string, userId: number, status: string) =>
    request<{ ok: boolean; status: string }>(
      `/api/admin/clients/${encodeURIComponent(clientId)}/users/${userId}/status`,
      'POST',
      { status }
    ),

  // Admin User Details & Global Actions
  adminGetUserDetails: (userId: number) =>
    request<AdminUserDetails>(`/api/admin/users/${userId}`),
  adminForceLogoutUser: (userId: number) =>
    request<{ ok: boolean; revoked_sessions: number; revoked_tokens: number }>(
      `/api/admin/users/${userId}/force-logout`,
      'POST'
    ),
  adminSuspendUser: (userId: number) =>
    request<{ ok: boolean; status: string }>(`/api/admin/users/${userId}/suspend`, 'POST'),
  adminUnsuspendUser: (userId: number) =>
    request<{ ok: boolean; status: string }>(`/api/admin/users/${userId}/unsuspend`, 'POST'),
  adminSetUserAdmin: (userId: number, is_admin: boolean) =>
    request<{ ok: boolean; is_admin: boolean }>(
      `/api/admin/users/${userId}/admin`,
      'POST',
      { is_admin }
    ),

  // Admin Audit Logs
  adminGetAuditLogs: (params?: {
    q?: string
    event_type?: string
    client_id?: string
    limit?: number
    offset?: number
  }) => {
    const search = new URLSearchParams()
    if (params?.q) search.set('q', params.q)
    if (params?.event_type) search.set('event_type', params.event_type)
    if (params?.client_id) search.set('client_id', params.client_id)
    if (params?.limit) search.set('limit', String(params.limit))
    if (params?.offset) search.set('offset', String(params.offset))
    const qs = search.toString() ? `?${search.toString()}` : ''
    return request<{ logs: AuditLog[]; total: number }>(`/api/admin/audit-logs${qs}`)
  },
  adminExportAuditLogsUrl: (params?: {
    q?: string
    event_type?: string
    client_id?: string
    format?: 'csv' | 'json'
  }) => {
    const search = new URLSearchParams()
    if (params?.q) search.set('q', params.q)
    if (params?.event_type) search.set('event_type', params.event_type)
    if (params?.client_id) search.set('client_id', params.client_id)
    if (params?.format) search.set('format', params.format)
    return `/api/admin/audit-logs/export?${search.toString()}`
  },
}
