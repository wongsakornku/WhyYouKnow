export interface UserProfile {
  id: number
  email: string
  name: string
  picture: string | null
  is_admin?: boolean
  is_super_admin?: boolean
  status?: 'active' | 'suspended'
}

export interface AttackProtectionConfig {
  bot_detection: boolean
  suspicious_ip_throttling: boolean
  brute_force_protection: boolean
  suspicious_account_shield: boolean
}

export interface OAuthClient {
  id: number
  client_id: string
  client_name: string
  redirect_uris: string[]
  is_confidential: boolean
  is_active: boolean
  access_mode: 'open' | 'invite_only'
  attack_protection?: AttackProtectionConfig
  created_at: string
  user_count?: number
}

export interface AppInvite {
  id: number
  client_id: string
  email: string
  initial_role: 'admin' | 'member' | 'viewer'
  created_at: string
}

export interface AdminUserListItem {
  id: number
  email: string
  name: string
  picture: string | null
  status: 'active' | 'suspended'
  is_admin: boolean
  is_super_admin: boolean
  created_at: string
  last_login_at: string
}

export interface AdminUserDetails {
  user: AdminUserListItem
  apps: {
    client_id: string
    client_name: string
    role: string
    status: string
    created_at: string
    last_accessed_at: string
  }[]
  active_sessions_count: number
  active_oauth_tokens_count: number
}

export interface AppUser {
  user_id: number
  email: string
  name: string
  picture: string | null
  role: 'admin' | 'member' | 'viewer'
  status: 'active' | 'revoked'
  created_at: string
  last_accessed_at: string
}

export interface ClientInfo {
  client_id: string
  client_name: string
  redirect_uris: string[]
  is_confidential: boolean
  attack_protection?: AttackProtectionConfig
}

export interface AuditLog {
  id: number
  event_type: string
  user_id: number | null
  user_email: string | null
  client_id: string | null
  client_name: string | null
  action_by: string
  details: string | null
  ip_hmac: string
  ua_short: string | null
  created_at: string
}

export interface AdminDashboardStats {
  total_apps: number
  active_apps: number
  total_users: number
  active_sessions: number
  active_tokens: number
  recent_logs: {
    id: number
    event_type: string
    user_email: string | null
    client_name: string | null
    action_by: string
    details: string | null
    created_at: string
  }[]
}

export interface UserDashboardData {
  profile: UserProfile
  apps: {
    client_id: string
    client_name: string
    role: string
    status: string
    created_at: string
    last_accessed_at: string
  }[]
  recent_activity: {
    id: number
    event_type: string
    client_name: string | null
    details: string | null
    created_at: string
  }[]
}
