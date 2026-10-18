import { Hono } from 'hono'
import { handle } from 'hono/netlify'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { query, queryOne } from './db'
import {
  verifyGoogleToken,
  newToken,
  hashToken,
  hashIp,
  verifyPkce,
  nowIso,
  expiryIso,
  daysExpiryIso,
  isSuperAdmin,
} from './auth'

const app = new Hono().basePath('/api')

const DEFAULT_ATTACK_PROTECTION = {
  bot_detection: false,
  suspicious_ip_throttling: true,
  brute_force_protection: true,
  suspicious_account_shield: false,
}

function parseAttackProtection(raw: any) {
  const cfg = { ...DEFAULT_ATTACK_PROTECTION }
  if (typeof raw === 'string' && raw) {
    try {
      const parsed = JSON.parse(raw)
      if (parsed && typeof parsed === 'object') {
        Object.assign(cfg, parsed)
      }
    } catch {
      // ignore parse error
    }
  } else if (raw && typeof raw === 'object') {
    Object.assign(cfg, raw)
  }
  return cfg
}

function clientIp(c: any): string {
  const forwarded = c.req.header('x-forwarded-for')
  if (forwarded) {
    return forwarded.split(',')[0].trim()
  }
  return c.req.header('client-ip') || 'unknown'
}

function shortUa(ua: string | undefined): string {
  if (!ua) return 'unknown'
  return ua.slice(0, 128)
}

function sanitizeCsvCell(val: any): string {
  if (val === null || val === undefined) return ''
  const s = typeof val === 'object' ? JSON.stringify(val) : String(val)
  if (s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0])) {
    return `'${s}`
  }
  return s
}

function validateRedirectUri(uri: string): void {
  try {
    const parsed = new URL(uri)
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Only http and https allowed')
    }
    if (parsed.protocol === 'http:') {
      const host = parsed.hostname.toLowerCase()
      if (!['localhost', '127.0.0.1', '::1'].includes(host)) {
        throw new Error('http redirect_uri only allowed for localhost')
      }
    }
    if (parsed.hash) {
      throw new Error('redirect_uri must not contain fragment identifier')
    }
  } catch (err: any) {
    throw new Error(`invalid redirect_uri: ${err.message || uri}`)
  }
}

async function logAudit(
  event_type: string,
  user_id: number | null,
  user_email: string | null,
  client_id: string | null,
  client_name: string | null,
  action_by: string,
  details: any,
  ip: string,
  ua: string
) {
  try {
    await query(
      `INSERT INTO audit_logs (event_type, user_id, user_email, client_id, client_name, action_by, details, ip_hmac, ua_short, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        event_type,
        user_id,
        user_email,
        client_id,
        client_name,
        action_by,
        details ? JSON.stringify(details) : null,
        hashIp(ip),
        shortUa(ua),
        nowIso(),
      ]
    )
  } catch (err) {
    console.error('[AUDIT_LOG_ERROR]', err)
  }
}

// In-memory rate limiting and brute-force tracking
const attemptsMap = new Map<string, number[]>()
const failedExchanges = new Map<string, number[]>()
const blockedEntities = new Map<string, number>()

function rateLimit(key: string, maxAttempts = 30, windowSecs = 60) {
  const now = Date.now() / 1000
  let timestamps = attemptsMap.get(key) || []
  timestamps = timestamps.filter((t) => now - t <= windowSecs)
  if (timestamps.length >= maxAttempts) {
    return false
  }
  timestamps.push(now)
  attemptsMap.set(key, timestamps)
  return true
}

function checkBruteForceBlock(clientId: string, ip: string, attackCfg: any): number | null {
  if (!attackCfg.brute_force_protection) return null
  const key = `${clientId}:${ip}`
  const now = Date.now() / 1000
  const blockedUntil = blockedEntities.get(key) || 0
  if (now < blockedUntil) {
    return Math.ceil(blockedUntil - now)
  }
  return null
}

function recordFailedExchange(clientId: string, ip: string, attackCfg: any) {
  if (!attackCfg.brute_force_protection) return
  const key = `${clientId}:${ip}`
  const now = Date.now() / 1000
  let q = failedExchanges.get(key) || []
  q = q.filter((t) => now - t <= 900)
  q.push(now)
  failedExchanges.set(key, q)
  if (q.length >= 5) {
    blockedEntities.set(key, now + 900)
  }
}

function clearFailedExchange(clientId: string, ip: string) {
  const key = `${clientId}:${ip}`
  failedExchanges.delete(key)
  blockedEntities.delete(key)
}

// User authentication helper
interface CurrentUser {
  id: number
  email: string
  name: string
  picture: string | null
  status: string
  is_admin: boolean
  is_super_admin: boolean
}

async function getCurrentUser(c: any): Promise<CurrentUser | null> {
  const sessionToken = getCookie(c, 'session')
  if (!sessionToken) return null

  const sessionHash = hashToken(sessionToken)
  const now = nowIso()

  const row = await queryOne<{
    id: number
    email: string
    name: string
    picture: string | null
    status: string
    is_admin: boolean
  }>(
    `SELECT u.id, u.email, u.name, u.picture, u.status, u.is_admin
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > $2`,
    [sessionHash, now]
  )

  if (!row) return null

  const isSuper = isSuperAdmin(row.email)
  const isAdmin = Boolean(row.is_admin) || isSuper

  return {
    id: row.id,
    email: row.email,
    name: row.name,
    picture: row.picture,
    status: row.status || 'active',
    is_admin: isAdmin,
    is_super_admin: isSuper,
  }
}

// CORS & Security headers middleware
app.use('*', async (c, next) => {
  const origin = c.req.header('origin')
  const path = c.req.path

  if (c.req.method === 'OPTIONS') {
    return c.body(null, 204, {
      'Access-Control-Allow-Origin': origin || '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
    })
  }

  await next()

  // Add security headers to response
  c.res.headers.set('X-Content-Type-Options', 'nosniff')
  c.res.headers.set('X-Frame-Options', 'DENY')
  c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  c.res.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')

  if (path.startsWith('/api/oauth/token') || path.startsWith('/api/oauth/userinfo') || path.startsWith('/api/oauth/revoke')) {
    c.res.headers.set('Access-Control-Allow-Origin', '*')
  } else if (origin) {
    c.res.headers.set('Access-Control-Allow-Origin', origin)
    c.res.headers.set('Access-Control-Allow-Credentials', 'true')
  }
})

// --- Health Check ---
app.get('/health', (c) => c.json({ status: 'ok' }))

// --- Auth Endpoints ---

app.post('/auth/google', async (c) => {
  const ip = clientIp(c)
  if (!rateLimit(`google:${ip}`, 10, 60)) {
    return c.json({ detail: 'too many attempts' }, 429)
  }

  let body: { credential?: string }
  try {
    body = await c.req.json()
  } catch {
    return c.json({ detail: 'invalid json' }, 400)
  }

  if (!body.credential) {
    return c.json({ detail: 'credential required' }, 400)
  }

  let googleUser
  try {
    googleUser = await verifyGoogleToken(body.credential)
  } catch (err: any) {
    console.error('Google verification failed:', err)
    return c.json({ detail: 'invalid token' }, 401)
  }

  const existing = await queryOne<{ id: number; status: string }>(
    'SELECT id, status FROM users WHERE google_sub = $1',
    [googleUser.sub]
  )

  if (existing && existing.status === 'suspended') {
    return c.json({ detail: 'account_suspended: your account has been suspended by an administrator' }, 403)
  }

  const isSuper = isSuperAdmin(googleUser.email)
  const now = nowIso()

  const user = await queryOne<{
    id: number
    email: string
    name: string
    picture: string | null
    is_admin: boolean
    status: string
  }>(
    `INSERT INTO users (google_sub, email, name, picture, status, is_admin, created_at, last_login_at)
     VALUES ($1, $2, $3, $4, 'active', $5, $6, $7)
     ON CONFLICT (google_sub) DO UPDATE SET
       email = EXCLUDED.email,
       name = EXCLUDED.name,
       picture = EXCLUDED.picture,
       last_login_at = EXCLUDED.last_login_at
       ${isSuper ? ', is_admin = TRUE' : ''}
     RETURNING id, email, name, picture, is_admin, status`,
    [googleUser.sub, googleUser.email, googleUser.name, googleUser.picture, isSuper, now, now]
  )

  if (!user) {
    return c.json({ detail: 'failed to persist user' }, 500)
  }

  const sessionToken = newToken()
  const sessionHash = hashToken(sessionToken)
  const sessionExp = daysExpiryIso(30)

  await query('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)', [
    sessionHash,
    user.id,
    sessionExp,
  ])

  await query(
    'INSERT INTO login_logs (user_id, at, ip_hmac, ua_short) VALUES ($1, $2, $3, $4)',
    [user.id, now, hashIp(ip), shortUa(c.req.header('user-agent'))]
  )

  await logAudit(
    'LOGIN',
    user.id,
    user.email,
    null,
    null,
    user.email,
    { method: 'google' },
    ip,
    c.req.header('user-agent') || ''
  )

  const isCookieSecure = process.env.COOKIE_SECURE !== 'false'
  setCookie(c, 'session', sessionToken, {
    httpOnly: true,
    secure: isCookieSecure,
    sameSite: 'Lax',
    path: '/',
    maxAge: 30 * 86400,
  })

  const userIsAdmin = Boolean(user.is_admin) || isSuper

  return c.json({
    id: user.id,
    email: user.email,
    name: user.name,
    picture: user.picture,
    status: user.status || 'active',
    is_admin: userIsAdmin,
    is_super_admin: isSuper,
  })
})

app.get('/me', async (c) => {
  const user = await getCurrentUser(c)
  if (!user) {
    return c.json({ detail: 'not authenticated' }, 401)
  }
  if (user.status === 'suspended') {
    return c.json({ detail: 'account_suspended: your account has been suspended by an administrator' }, 403)
  }
  return c.json(user)
})

app.post('/auth/logout', async (c) => {
  const sessionToken = getCookie(c, 'session')
  const ip = clientIp(c)

  if (sessionToken) {
    const sessionHash = hashToken(sessionToken)
    const user = await queryOne<{ id: number; email: string }>(
      'SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1',
      [sessionHash]
    )
    if (user) {
      await logAudit('LOGOUT', user.id, user.email, null, null, user.email, null, ip, c.req.header('user-agent') || '')
    }
    await query('DELETE FROM sessions WHERE token_hash = $1', [sessionHash])
  }

  deleteCookie(c, 'session', { path: '/' })
  return c.json({ ok: true })
})

app.delete('/me', async (c) => {
  const user = await getCurrentUser(c)
  if (!user) return c.json({ detail: 'not authenticated' }, 401)

  const ip = clientIp(c)
  await logAudit('ACCOUNT_DELETED', user.id, user.email, null, null, user.email, null, ip, c.req.header('user-agent') || '')
  await query('DELETE FROM users WHERE id = $1', [user.id])

  deleteCookie(c, 'session', { path: '/' })
  return c.json({ ok: true })
})

app.get('/me/dashboard', async (c) => {
  const user = await getCurrentUser(c)
  if (!user) return c.json({ detail: 'not authenticated' }, 401)

  const apps = await query(
    `SELECT c.client_id, c.client_name, au.role, au.status, au.created_at, au.last_accessed_at
     FROM app_users au
     JOIN oauth_clients c ON c.client_id = au.client_id
     WHERE au.user_id = $1 ORDER BY au.last_accessed_at DESC`,
    [user.id]
  )

  const recentActivity = await query(
    `SELECT id, event_type, client_name, created_at, details
     FROM audit_logs WHERE user_id = $1
     ORDER BY id DESC LIMIT 5`,
    [user.id]
  )

  return c.json({
    profile: user,
    apps,
    recent_activity: recentActivity,
  })
})

app.delete('/me/apps/:clientId', async (c) => {
  const user = await getCurrentUser(c)
  if (!user) return c.json({ detail: 'not authenticated' }, 401)

  const clientId = c.req.param('clientId')
  const client = await queryOne<{ client_name: string }>('SELECT client_name FROM oauth_clients WHERE client_id = $1', [
    clientId,
  ])
  if (!client) return c.json({ detail: 'client not found' }, 404)

  await query('DELETE FROM app_users WHERE client_id = $1 AND user_id = $2', [clientId, user.id])
  await query('DELETE FROM oauth_tokens WHERE client_id = $1 AND user_id = $2', [clientId, user.id])
  await query('DELETE FROM oauth_refresh_tokens WHERE client_id = $1 AND user_id = $2', [clientId, user.id])

  const ip = clientIp(c)
  await logAudit(
    'USER_APP_DISCONNECTED',
    user.id,
    user.email,
    clientId,
    client.client_name,
    user.email,
    `User self-disconnected ${client.client_name}`,
    ip,
    c.req.header('user-agent') || ''
  )

  return c.json({ ok: true })
})

// --- Admin Endpoints ---

async function checkAdmin(c: any): Promise<CurrentUser | Response> {
  const user = await getCurrentUser(c)
  if (!user) return c.json({ detail: 'not authenticated' }, 401)
  if (!user.is_admin) return c.json({ detail: 'forbidden' }, 403)
  return user
}

async function checkSuperAdmin(c: any): Promise<CurrentUser | Response> {
  const user = await getCurrentUser(c)
  if (!user) return c.json({ detail: 'not authenticated' }, 401)
  if (!user.is_super_admin) return c.json({ detail: 'forbidden: super admin required' }, 403)
  return user
}

app.get('/admin/dashboard-stats', async (c) => {
  const adminOrRes = await checkAdmin(c)
  if (adminOrRes instanceof Response) return adminOrRes

  const now = nowIso()
  const totalAppsRow = await queryOne<{ c: string }>('SELECT COUNT(*) AS c FROM oauth_clients')
  const activeAppsRow = await queryOne<{ c: string }>('SELECT COUNT(*) AS c FROM oauth_clients WHERE is_active = TRUE')
  const totalUsersRow = await queryOne<{ c: string }>('SELECT COUNT(*) AS c FROM users')
  const activeSessionsRow = await queryOne<{ c: string }>('SELECT COUNT(*) AS c FROM sessions WHERE expires_at > $1', [now])
  const activeTokensRow = await queryOne<{ c: string }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE expires_at > $1', [now])

  const recentLogs = await query(
    `SELECT id, event_type, user_email, client_name, action_by, details, created_at
     FROM audit_logs ORDER BY id DESC LIMIT 5`
  )

  return c.json({
    total_apps: parseInt(totalAppsRow?.c || '0', 10),
    active_apps: parseInt(activeAppsRow?.c || '0', 10),
    total_users: parseInt(totalUsersRow?.c || '0', 10),
    active_sessions: parseInt(activeSessionsRow?.c || '0', 10),
    active_tokens: parseInt(activeTokensRow?.c || '0', 10),
    recent_logs: recentLogs,
  })
})

app.get('/admin/users', async (c) => {
  const adminOrRes = await checkAdmin(c)
  if (adminOrRes instanceof Response) return adminOrRes

  const rows = await query<{
    id: number
    email: string
    name: string
    status: string
    is_admin: boolean
    created_at: string
    last_login_at: string
  }>('SELECT id, email, name, status, is_admin, created_at, last_login_at FROM users ORDER BY id DESC')

  return c.json(
    rows.map((r) => {
      const isSuper = isSuperAdmin(r.email)
      return {
        id: r.id,
        email: r.email,
        name: r.name,
        status: r.status || 'active',
        is_admin: Boolean(r.is_admin) || isSuper,
        is_super_admin: isSuper,
        created_at: r.created_at,
        last_login_at: r.last_login_at,
      }
    })
  )
})

app.get('/admin/users/:userId', async (c) => {
  const adminOrRes = await checkAdmin(c)
  if (adminOrRes instanceof Response) return adminOrRes

  const userId = parseInt(c.req.param('userId'), 10)
  const u = await queryOne<{
    id: number
    email: string
    name: string
    picture: string | null
    status: string
    is_admin: boolean
    created_at: string
    last_login_at: string
  }>('SELECT id, email, name, picture, status, is_admin, created_at, last_login_at FROM users WHERE id = $1', [userId])

  if (!u) return c.json({ detail: 'user not found' }, 404)

  const apps = await query(
    `SELECT c.client_id, c.client_name, au.role, au.status, au.created_at, au.last_accessed_at
     FROM app_users au JOIN oauth_clients c ON c.client_id = au.client_id
     WHERE au.user_id = $1 ORDER BY au.last_accessed_at DESC`,
    [userId]
  )

  const sessRow = await queryOne<{ c: string }>('SELECT COUNT(*) AS c FROM sessions WHERE user_id = $1', [userId])
  const tokRow = await queryOne<{ c: string }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE user_id = $1', [userId])

  const isSuper = isSuperAdmin(u.email)
  return c.json({
    user: {
      ...u,
      is_admin: Boolean(u.is_admin) || isSuper,
      is_super_admin: isSuper,
    },
    apps,
    active_sessions: parseInt(sessRow?.c || '0', 10),
    active_tokens: parseInt(tokRow?.c || '0', 10),
  })
})

app.post('/admin/users/:userId/force-logout', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const userId = parseInt(c.req.param('userId'), 10)
  const target = await queryOne<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])
  if (!target) return c.json({ detail: 'user not found' }, 404)

  await query('DELETE FROM sessions WHERE user_id = $1', [userId])
  await query('DELETE FROM oauth_tokens WHERE user_id = $1', [userId])
  await query('DELETE FROM oauth_refresh_tokens WHERE user_id = $1', [userId])

  const ip = clientIp(c)
  await logAudit('FORCE_LOGOUT', userId, target.email, null, null, admin.email, null, ip, c.req.header('user-agent') || '')
  return c.json({ ok: true })
})

app.post('/admin/users/:userId/suspend', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const userId = parseInt(c.req.param('userId'), 10)
  const target = await queryOne<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])
  if (!target) return c.json({ detail: 'user not found' }, 404)
  if (isSuperAdmin(target.email)) {
    return c.json({ detail: 'cannot suspend super admin' }, 400)
  }

  await query("UPDATE users SET status = 'suspended' WHERE id = $1", [userId])
  await query('DELETE FROM sessions WHERE user_id = $1', [userId])
  await query('DELETE FROM oauth_tokens WHERE user_id = $1', [userId])
  await query('DELETE FROM oauth_refresh_tokens WHERE user_id = $1', [userId])

  const ip = clientIp(c)
  await logAudit('USER_SUSPENDED', userId, target.email, null, null, admin.email, null, ip, c.req.header('user-agent') || '')
  return c.json({ ok: true, status: 'suspended' })
})

app.post('/admin/users/:userId/unsuspend', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const userId = parseInt(c.req.param('userId'), 10)
  const target = await queryOne<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])
  if (!target) return c.json({ detail: 'user not found' }, 404)

  await query("UPDATE users SET status = 'active' WHERE id = $1", [userId])

  const ip = clientIp(c)
  await logAudit('USER_UNSUSPENDED', userId, target.email, null, null, admin.email, null, ip, c.req.header('user-agent') || '')
  return c.json({ ok: true, status: 'active' })
})

app.post('/admin/users/:userId/admin', async (c) => {
  const admin = await checkSuperAdmin(c)
  if (admin instanceof Response) return admin

  const userId = parseInt(c.req.param('userId'), 10)
  const body = await c.req.json<{ is_admin: boolean }>()
  const target = await queryOne<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])
  if (!target) return c.json({ detail: 'user not found' }, 404)
  if (isSuperAdmin(target.email)) {
    return c.json({ detail: 'cannot modify super admin privileges' }, 400)
  }

  await query('UPDATE users SET is_admin = $1 WHERE id = $2', [Boolean(body.is_admin), userId])

  const ip = clientIp(c)
  await logAudit(
    body.is_admin ? 'ADMIN_GRANTED' : 'ADMIN_REVOKED',
    userId,
    target.email,
    null,
    null,
    admin.email,
    { is_admin: body.is_admin },
    ip,
    c.req.header('user-agent') || ''
  )

  return c.json({ ok: true, is_admin: body.is_admin })
})

// --- OAuth Clients Management ---

app.get('/admin/clients', async (c) => {
  const adminOrRes = await checkAdmin(c)
  if (adminOrRes instanceof Response) return adminOrRes

  const rows = await query<{
    id: number
    client_id: string
    client_name: string
    redirect_uris: string
    is_confidential: boolean
    is_active: boolean
    access_mode: string
    attack_protection: any
    created_at: string
    user_count: string
  }>(
    `SELECT c.id, c.client_id, c.client_name, c.redirect_uris, c.is_confidential,
            c.is_active, c.access_mode, c.attack_protection, c.created_at,
            COUNT(au.id) AS user_count
     FROM oauth_clients c
     LEFT JOIN app_users au ON au.client_id = c.client_id
     GROUP BY c.id ORDER BY c.id DESC`
  )

  return c.json(
    rows.map((r) => {
      let uris: string[] = []
      try {
        uris = JSON.parse(r.redirect_uris)
      } catch {
        uris = (r.redirect_uris || '').split(',').map((u) => u.trim()).filter(Boolean)
      }
      return {
        id: r.id,
        client_id: r.client_id,
        client_name: r.client_name,
        redirect_uris: uris,
        is_confidential: Boolean(r.is_confidential),
        is_active: Boolean(r.is_active),
        access_mode: r.access_mode || 'open',
        attack_protection: parseAttackProtection(r.attack_protection),
        created_at: r.created_at,
        user_count: parseInt(r.user_count || '0', 10),
      }
    })
  )
})

app.post('/admin/clients', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const body = await c.req.json<{
    client_name: string
    redirect_uris: string[]
    is_confidential?: boolean
    access_mode?: string
  }>()

  if (!body.redirect_uris || !body.redirect_uris.length) {
    return c.json({ detail: 'at least one redirect_uri is required' }, 400)
  }
  for (const uri of body.redirect_uris) {
    try {
      validateRedirectUri(uri)
    } catch (e: any) {
      return c.json({ detail: e.message }, 400)
    }
  }

  const accessMode = body.access_mode || 'open'
  if (!['open', 'invite_only'].includes(accessMode)) {
    return c.json({ detail: 'invalid access_mode' }, 400)
  }

  const isConfidential = body.is_confidential !== false
  const clientId = newToken().slice(0, 24)
  const clientSecret = isConfidential ? newToken() : null
  const secretHash = clientSecret ? hashToken(clientSecret) : null
  const now = nowIso()

  await query(
    `INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, is_confidential, is_active, access_mode, attack_protection, created_at)
     VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7, $8)`,
    [
      clientId,
      secretHash,
      body.client_name,
      JSON.stringify(body.redirect_uris),
      isConfidential,
      accessMode,
      JSON.stringify(DEFAULT_ATTACK_PROTECTION),
      now,
    ]
  )

  const ip = clientIp(c)
  await logAudit(
    'CLIENT_CREATED',
    null,
    null,
    clientId,
    body.client_name,
    admin.email,
    { is_confidential: isConfidential, redirect_uris: body.redirect_uris, access_mode: accessMode },
    ip,
    c.req.header('user-agent') || ''
  )

  return c.json({
    client_id: clientId,
    client_secret: clientSecret,
    client_name: body.client_name,
    redirect_uris: body.redirect_uris,
    is_confidential: isConfidential,
    is_active: true,
    access_mode: accessMode,
    attack_protection: DEFAULT_ATTACK_PROTECTION,
  })
})

app.patch('/admin/clients/:clientId/attack-protection', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const clientId = c.req.param('clientId')
  const body = await c.req.json<any>()

  const client = await queryOne<{ client_name: string; attack_protection: any }>(
    'SELECT client_name, attack_protection FROM oauth_clients WHERE client_id = $1',
    [clientId]
  )
  if (!client) return c.json({ detail: 'client not found' }, 404)

  const cfg = parseAttackProtection(client.attack_protection)
  const updates: Record<string, boolean> = {}

  if (body.bot_detection !== undefined) {
    cfg.bot_detection = Boolean(body.bot_detection)
    updates.bot_detection = cfg.bot_detection
  }
  if (body.suspicious_ip_throttling !== undefined) {
    cfg.suspicious_ip_throttling = Boolean(body.suspicious_ip_throttling)
    updates.suspicious_ip_throttling = cfg.suspicious_ip_throttling
  }
  if (body.brute_force_protection !== undefined) {
    cfg.brute_force_protection = Boolean(body.brute_force_protection)
    updates.brute_force_protection = cfg.brute_force_protection
  }
  if (body.suspicious_account_shield !== undefined) {
    cfg.suspicious_account_shield = Boolean(body.suspicious_account_shield)
    updates.suspicious_account_shield = cfg.suspicious_account_shield
  }

  await query('UPDATE oauth_clients SET attack_protection = $1 WHERE client_id = $2', [JSON.stringify(cfg), clientId])

  const ip = clientIp(c)
  await logAudit(
    'ATTACK_PROTECTION_UPDATED',
    null,
    null,
    clientId,
    client.client_name,
    admin.email,
    updates,
    ip,
    c.req.header('user-agent') || ''
  )

  return c.json({ client_id: clientId, attack_protection: cfg })
})

app.patch('/admin/clients/:clientId', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const clientId = c.req.param('clientId')
  const body = await c.req.json<{
    client_name?: string
    redirect_uris?: string[]
    access_mode?: string
    is_active?: boolean
  }>()

  const client = await queryOne<{ client_name: string }>(
    'SELECT client_name FROM oauth_clients WHERE client_id = $1',
    [clientId]
  )
  if (!client) return c.json({ detail: 'client not found' }, 404)

  const updates: string[] = []
  const params: any[] = []
  const auditDetails: Record<string, any> = {}

  if (body.client_name !== undefined) {
    params.push(body.client_name)
    updates.push(`client_name = $${params.length}`)
    auditDetails.client_name = body.client_name
  }

  if (body.redirect_uris !== undefined) {
    if (!body.redirect_uris.length) {
      return c.json({ detail: 'at least one redirect_uri required' }, 400)
    }
    for (const uri of body.redirect_uris) {
      try {
        validateRedirectUri(uri)
      } catch (e: any) {
        return c.json({ detail: e.message }, 400)
      }
    }
    params.push(JSON.stringify(body.redirect_uris))
    updates.push(`redirect_uris = $${params.length}`)
    auditDetails.redirect_uris = body.redirect_uris
  }

  if (body.access_mode !== undefined) {
    if (!['open', 'invite_only'].includes(body.access_mode)) {
      return c.json({ detail: "invalid access_mode. Must be 'open' or 'invite_only'" }, 400)
    }
    params.push(body.access_mode)
    updates.push(`access_mode = $${params.length}`)
    auditDetails.access_mode = body.access_mode
  }

  if (body.is_active !== undefined) {
    params.push(Boolean(body.is_active))
    updates.push(`is_active = $${params.length}`)
    auditDetails.is_active = Boolean(body.is_active)
  }

  if (updates.length > 0) {
    params.push(clientId)
    await query(`UPDATE oauth_clients SET ${updates.join(', ')} WHERE client_id = $${params.length}`, params)

    const ip = clientIp(c)
    await logAudit(
      'CLIENT_UPDATED',
      null,
      null,
      clientId,
      body.client_name || client.client_name,
      admin.email,
      auditDetails,
      ip,
      c.req.header('user-agent') || ''
    )
  }

  return c.json({ ok: true })
})

app.post('/admin/clients/:clientId/rotate-secret', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const clientId = c.req.param('clientId')
  const client = await queryOne<{ client_name: string; is_confidential: boolean }>(
    'SELECT client_name, is_confidential FROM oauth_clients WHERE client_id = $1',
    [clientId]
  )
  if (!client) return c.json({ detail: 'client not found' }, 404)
  if (!client.is_confidential) {
    return c.json({ detail: 'cannot rotate secret for public client' }, 400)
  }

  const newSecret = newToken()
  const newHash = hashToken(newSecret)

  await query('UPDATE oauth_clients SET client_secret_hash = $1 WHERE client_id = $2', [newHash, clientId])

  const ip = clientIp(c)
  await logAudit('SECRET_ROTATED', null, null, clientId, client.client_name, admin.email, null, ip, c.req.header('user-agent') || '')

  return c.json({ client_id: clientId, client_secret: newSecret, message: 'secret rotated' })
})

app.post('/admin/clients/:clientId/status', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const clientId = c.req.param('clientId')
  const body = await c.req.json<{ is_active: boolean }>()

  const client = await queryOne<{ client_name: string }>(
    'SELECT client_name FROM oauth_clients WHERE client_id = $1',
    [clientId]
  )
  if (!client) return c.json({ detail: 'client not found' }, 404)

  const isActive = Boolean(body.is_active)
  await query('UPDATE oauth_clients SET is_active = $1 WHERE client_id = $2', [isActive, clientId])
  if (!isActive) {
    await query('DELETE FROM oauth_tokens WHERE client_id = $1', [clientId])
    await query('DELETE FROM oauth_codes WHERE client_id = $1', [clientId])
    await query('DELETE FROM oauth_refresh_tokens WHERE client_id = $1', [clientId])
  }

  const ip = clientIp(c)
  await logAudit(
    isActive ? 'CLIENT_ENABLED' : 'CLIENT_DISABLED',
    null,
    null,
    clientId,
    client.client_name,
    admin.email,
    { is_active: isActive },
    ip,
    c.req.header('user-agent') || ''
  )

  return c.json({ ok: true, is_active: isActive })
})

app.delete('/admin/clients/:clientId', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const clientId = c.req.param('clientId')
  const client = await queryOne<{ client_name: string }>(
    'SELECT client_name FROM oauth_clients WHERE client_id = $1',
    [clientId]
  )
  const clientName = client?.client_name || null

  const ip = clientIp(c)
  await logAudit('CLIENT_DELETED', null, null, clientId, clientName, admin.email, null, ip, c.req.header('user-agent') || '')

  await query('DELETE FROM oauth_clients WHERE client_id = $1', [clientId])
  return c.json({ ok: true })
})

// --- Invites ---

app.get('/admin/clients/:clientId/invites', async (c) => {
  const adminOrRes = await checkAdmin(c)
  if (adminOrRes instanceof Response) return adminOrRes

  const clientId = c.req.param('clientId')
  const rows = await query('SELECT id, client_id, email, role, created_at FROM app_invites WHERE client_id = $1 ORDER BY id DESC', [clientId])
  return c.json(rows)
})

app.post('/admin/clients/:clientId/invites', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const clientId = c.req.param('clientId')
  const body = await c.req.json<{ email: string; initial_role?: string; role?: string }>()

  const role = body.role || body.initial_role || 'member'
  if (!['admin', 'member', 'viewer'].includes(role)) {
    return c.json({ detail: 'invalid role' }, 400)
  }

  const email = (body.email || '').trim().toLowerCase()
  if (!email || !email.includes('@')) {
    return c.json({ detail: 'invalid email' }, 400)
  }

  const client = await queryOne<{ client_name: string }>('SELECT client_name FROM oauth_clients WHERE client_id = $1', [clientId])
  if (!client) return c.json({ detail: 'client not found' }, 404)

  const now = nowIso()
  const invite = await queryOne<{ id: number; email: string; role: string; created_at: string }>(
    `INSERT INTO app_invites (client_id, email, role, created_at)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (client_id, email) DO UPDATE SET role = EXCLUDED.role
     RETURNING id, email, role, created_at`,
    [clientId, email, role, now]
  )

  const ip = clientIp(c)
  await logAudit('INVITE_ADDED', null, email, clientId, client.client_name, admin.email, { role }, ip, c.req.header('user-agent') || '')

  return c.json(invite)
})

app.delete('/admin/clients/:clientId/invites/:inviteId', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const clientId = c.req.param('clientId')
  const inviteId = parseInt(c.req.param('inviteId'), 10)

  const invite = await queryOne<{ email: string }>('SELECT email FROM app_invites WHERE id = $1 AND client_id = $2', [inviteId, clientId])
  if (!invite) return c.json({ detail: 'invite not found' }, 404)

  const client = await queryOne<{ client_name: string }>('SELECT client_name FROM oauth_clients WHERE client_id = $1', [clientId])
  await query('DELETE FROM app_invites WHERE id = $1', [inviteId])

  const ip = clientIp(c)
  await logAudit('INVITE_REMOVED', null, invite.email, clientId, client?.client_name || null, admin.email, null, ip, c.req.header('user-agent') || '')

  return c.json({ ok: true })
})

// --- Users by App ---

app.get('/admin/clients/:clientId/users', async (c) => {
  const adminOrRes = await checkAdmin(c)
  if (adminOrRes instanceof Response) return adminOrRes

  const clientId = c.req.param('clientId')
  const rows = await query<{
    user_id: number
    email: string
    name: string
    picture: string | null
    role: string
    status: string
    created_at: string
    last_accessed_at: string
  }>(
    `SELECT u.id AS user_id, u.email, u.name, u.picture,
            au.role, au.status, au.created_at, au.last_accessed_at
     FROM app_users au
     JOIN users u ON u.id = au.user_id
     WHERE au.client_id = $1
     ORDER BY au.last_accessed_at DESC`,
    [clientId]
  )

  return c.json(rows)
})

app.post('/admin/clients/:clientId/users/:userId/role', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const clientId = c.req.param('clientId')
  const userId = parseInt(c.req.param('userId'), 10)
  const body = await c.req.json<{ role: string }>()

  if (!['admin', 'member', 'viewer'].includes(body.role)) {
    return c.json({ detail: 'invalid role' }, 400)
  }

  const appUser = await queryOne<{ email: string; client_name: string }>(
    `SELECT u.email, c.client_name FROM app_users au
     JOIN users u ON u.id = au.user_id
     JOIN oauth_clients c ON c.client_id = au.client_id
     WHERE au.client_id = $1 AND au.user_id = $2`,
    [clientId, userId]
  )
  if (!appUser) return c.json({ detail: 'user not found in this client application' }, 404)

  await query('UPDATE app_users SET role = $1 WHERE client_id = $2 AND user_id = $3', [body.role, clientId, userId])

  const ip = clientIp(c)
  await logAudit('ROLE_UPDATED', userId, appUser.email, clientId, appUser.client_name, admin.email, { role: body.role }, ip, c.req.header('user-agent') || '')

  return c.json({ ok: true, role: body.role })
})

app.post('/admin/clients/:clientId/users/:userId/status', async (c) => {
  const admin = await checkAdmin(c)
  if (admin instanceof Response) return admin

  const clientId = c.req.param('clientId')
  const userId = parseInt(c.req.param('userId'), 10)
  const body = await c.req.json<{ status: string }>()

  if (!['active', 'revoked'].includes(body.status)) {
    return c.json({ detail: 'invalid status' }, 400)
  }

  const appUser = await queryOne<{ email: string; client_name: string }>(
    `SELECT u.email, c.client_name FROM app_users au
     JOIN users u ON u.id = au.user_id
     JOIN oauth_clients c ON c.client_id = au.client_id
     WHERE au.client_id = $1 AND au.user_id = $2`,
    [clientId, userId]
  )
  if (!appUser) return c.json({ detail: 'user not found in this client application' }, 404)

  await query('UPDATE app_users SET status = $1 WHERE client_id = $2 AND user_id = $3', [body.status, clientId, userId])
  if (body.status === 'revoked') {
    await query('DELETE FROM oauth_tokens WHERE client_id = $1 AND user_id = $2', [clientId, userId])
    await query('DELETE FROM oauth_refresh_tokens WHERE client_id = $1 AND user_id = $2', [clientId, userId])
  }

  const ip = clientIp(c)
  await logAudit('STATUS_UPDATED', userId, appUser.email, clientId, appUser.client_name, admin.email, { status: body.status }, ip, c.req.header('user-agent') || '')

  return c.json({ ok: true, status: body.status })
})

// --- Audit Logs ---

app.get('/admin/audit-logs', async (c) => {
  const adminOrRes = await checkAdmin(c)
  if (adminOrRes instanceof Response) return adminOrRes

  const q = c.req.query('q')
  const event_type = c.req.query('event_type')
  const client_id = c.req.query('client_id')
  const limit = Math.min(parseInt(c.req.query('limit') || '50', 10), 100)
  const offset = parseInt(c.req.query('offset') || '0', 10)

  const where: string[] = []
  const params: any[] = []

  if (event_type) {
    params.push(event_type)
    where.push(`event_type = $${params.length}`)
  }
  if (client_id) {
    params.push(client_id)
    where.push(`client_id = $${params.length}`)
  }
  if (q) {
    params.push(`%${q}%`)
    const idx = params.length
    where.push(`(user_email ILIKE $${idx} OR client_name ILIKE $${idx} OR action_by ILIKE $${idx} OR details::text ILIKE $${idx})`)
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''

  const countRow = await queryOne<{ total: string }>(`SELECT COUNT(*) AS total FROM audit_logs ${whereSql}`, params)
  const total = parseInt(countRow?.total || '0', 10)

  const dataParams = [...params, limit, offset]
  const rows = await query(
    `SELECT id, event_type, user_id, user_email, client_id, client_name, action_by, details, ip_hmac, ua_short, created_at
     FROM audit_logs ${whereSql} ORDER BY id DESC LIMIT $${dataParams.length - 1} OFFSET $${dataParams.length}`,
    dataParams
  )

  return c.json({ logs: rows, total })
})

app.get('/admin/audit-logs/export', async (c) => {
  const adminOrRes = await checkAdmin(c)
  if (adminOrRes instanceof Response) return adminOrRes

  const q = c.req.query('q')
  const event_type = c.req.query('event_type')
  const client_id = c.req.query('client_id')
  const format = c.req.query('format') || 'csv'

  const where: string[] = []
  const params: any[] = []

  if (event_type) {
    params.push(event_type)
    where.push(`event_type = $${params.length}`)
  }
  if (client_id) {
    params.push(client_id)
    where.push(`client_id = $${params.length}`)
  }
  if (q) {
    params.push(`%${q}%`)
    const idx = params.length
    where.push(`(user_email ILIKE $${idx} OR client_name ILIKE $${idx} OR action_by ILIKE $${idx} OR details::text ILIKE $${idx})`)
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''
  const rows = await query<any>(
    `SELECT id, event_type, user_email, client_name, action_by, details, ip_hmac, ua_short, created_at
     FROM audit_logs ${whereSql} ORDER BY id DESC LIMIT 5000`,
    params
  )

  const dateStr = new Date().toISOString().split('T')[0]

  if (format === 'json') {
    return new Response(JSON.stringify(rows, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="audit_logs_${dateStr}.json"`,
      },
    })
  }

  // CSV
  const header = ['ID', 'Event Type', 'User Email', 'Target App', 'Action By', 'Details', 'IP Hash', 'User Agent', 'Timestamp (UTC)']
  const lines = [header.join(',')]

  for (const r of rows) {
    const row = [
      r.id,
      `"${sanitizeCsvCell(r.event_type)}"`,
      `"${sanitizeCsvCell(r.user_email)}"`,
      `"${sanitizeCsvCell(r.client_name)}"`,
      `"${sanitizeCsvCell(r.action_by)}"`,
      `"${sanitizeCsvCell(r.details)}"`,
      `"${r.ip_hmac}"`,
      `"${sanitizeCsvCell(r.ua_short)}"`,
      `"${r.created_at}"`,
    ]
    lines.push(row.join(','))
  }

  return new Response('\ufeff' + lines.join('\n'), {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="audit_logs_${dateStr}.csv"`,
    },
  })
})

// ==============================================================================
// OAuth 2.0 / SSO Endpoints
// ==============================================================================

app.get('/oauth/client-info', async (c) => {
  const clientId = c.req.query('client_id')
  if (!clientId) return c.json({ detail: 'client_id required' }, 400)

  const row = await queryOne<{
    client_id: string
    client_name: string
    redirect_uris: string
    is_confidential: boolean
    is_active: boolean
    access_mode: string
    attack_protection: any
  }>(
    `SELECT client_id, client_name, redirect_uris, is_confidential, is_active, access_mode, attack_protection
     FROM oauth_clients WHERE client_id = $1`,
    [clientId]
  )

  if (!row) return c.json({ detail: 'client not found' }, 404)
  if (!row.is_active) return c.json({ detail: 'client_disabled: this client application has been disabled' }, 403)

  let uris: string[] = []
  try {
    uris = JSON.parse(row.redirect_uris)
  } catch {
    uris = (row.redirect_uris || '').split(',').map((u) => u.trim()).filter(Boolean)
  }

  return c.json({
    client_id: row.client_id,
    client_name: row.client_name,
    redirect_uris: uris,
    is_confidential: Boolean(row.is_confidential),
    is_active: Boolean(row.is_active),
    access_mode: row.access_mode || 'open',
    attack_protection: parseAttackProtection(row.attack_protection),
  })
})

app.post('/oauth/authorize', async (c) => {
  const user = await getCurrentUser(c)
  if (!user) return c.json({ detail: 'not authenticated' }, 401)

  const ip = clientIp(c)
  if (!rateLimit(`oauth_authorize:${ip}`, 30, 60)) {
    return c.json({ detail: 'too many attempts' }, 429)
  }

  const body = await c.req.json<{
    client_id: string
    redirect_uri: string
    code_challenge?: string
    code_challenge_method?: string
    bot_token?: string
  }>()

  const client = await queryOne<{
    client_id: string
    client_name: string
    redirect_uris: string
    is_confidential: boolean
    is_active: boolean
    access_mode: string
    attack_protection: any
  }>(
    `SELECT client_id, client_name, redirect_uris, is_confidential, is_active, access_mode, attack_protection
     FROM oauth_clients WHERE client_id = $1`,
    [body.client_id]
  )

  if (!client) return c.json({ detail: 'client not found' }, 404)
  if (!client.is_active) return c.json({ detail: 'client_disabled: this client application has been disabled' }, 403)

  const attackCfg = parseAttackProtection(client.attack_protection)

  // Suspicious IP Throttling
  const authLimit = attackCfg.suspicious_ip_throttling ? 10 : 30
  if (!rateLimit(`oauth_auth:${body.client_id}:${ip}`, authLimit, 60)) {
    await logAudit(
      'ATTACK_BLOCKED',
      null,
      null,
      client.client_id,
      client.client_name,
      'system:attack_protection',
      { protection: 'suspicious_ip_throttling', endpoint: '/api/oauth/authorize' },
      ip,
      c.req.header('user-agent') || ''
    )
    return c.json({ detail: 'too many requests' }, 429)
  }

  // Bot detection
  if (attackCfg.bot_detection) {
    if (!body.bot_token || body.bot_token !== 'human-verified') {
      await logAudit(
        'ATTACK_BLOCKED',
        null,
        null,
        client.client_id,
        client.client_name,
        'system:attack_protection',
        { protection: 'bot_detection', reason: 'bot_verification_missing_or_failed' },
        ip,
        c.req.header('user-agent') || ''
      )
      return c.json({ detail: 'bot_detection: verification challenge required' }, 400)
    }
  }

  // Suspicious Account Shield
  if (attackCfg.suspicious_account_shield && user.status !== 'active') {
    await logAudit(
      'ATTACK_BLOCKED',
      user.id,
      user.email,
      client.client_id,
      client.client_name,
      'system:attack_protection',
      { protection: 'suspicious_account_shield', reason: 'account_status_not_active' },
      ip,
      c.req.header('user-agent') || ''
    )
    return c.json({ detail: 'suspicious_account_shield: account verification required' }, 403)
  }

  let allowedUris: string[] = []
  try {
    allowedUris = JSON.parse(client.redirect_uris)
  } catch {
    allowedUris = (client.redirect_uris || '').split(',').map((u) => u.trim()).filter(Boolean)
  }

  if (!allowedUris.includes(body.redirect_uri)) {
    return c.json({ detail: 'invalid redirect_uri' }, 400)
  }

  if (!client.is_confidential && !body.code_challenge) {
    return c.json({ detail: 'code_challenge required for public clients' }, 400)
  }
  if (body.code_challenge && body.code_challenge_method !== 'S256') {
    return c.json({ detail: 'unsupported code_challenge_method: only S256 is supported' }, 400)
  }

  const existingAppUser = await queryOne<{ role: string; status: string }>(
    'SELECT role, status FROM app_users WHERE client_id = $1 AND user_id = $2',
    [body.client_id, user.id]
  )

  if (existingAppUser && existingAppUser.status === 'revoked') {
    return c.json({ detail: 'access_denied: user access is revoked for this app' }, 403)
  }

  let assignedRole = 'member'
  const accessMode = client.access_mode || 'open'

  if (accessMode === 'invite_only' && !existingAppUser) {
    const invite = await queryOne<{ role: string }>(
      'SELECT role FROM app_invites WHERE client_id = $1 AND LOWER(email) = $2',
      [body.client_id, user.email.toLowerCase()]
    )
    if (!invite) {
      return c.json({ detail: 'access_denied: this application is invite-only and you have not been invited' }, 403)
    }
    assignedRole = invite.role
    await query('DELETE FROM app_invites WHERE client_id = $1 AND LOWER(email) = $2', [body.client_id, user.email.toLowerCase()])
  } else if (existingAppUser) {
    assignedRole = existingAppUser.role
  }

  const now = nowIso()
  await query(
    `INSERT INTO app_users (client_id, user_id, role, status, created_at, last_accessed_at)
     VALUES ($1, $2, $3, 'active', $4, $5)
     ON CONFLICT (client_id, user_id) DO UPDATE SET last_accessed_at = EXCLUDED.last_accessed_at`,
    [body.client_id, user.id, assignedRole, now, now]
  )

  const code = newToken()
  const codeHash = hashToken(code)
  const codeExp = expiryIso(10) // 10 minutes

  await query(
    `INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, expires_at, used)
     VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE)`,
    [codeHash, body.client_id, user.id, body.redirect_uri, body.code_challenge || null, body.code_challenge_method || 'S256', codeExp]
  )

  await logAudit(
    'OAUTH_AUTHORIZE',
    user.id,
    user.email,
    client.client_id,
    client.client_name,
    user.email,
    { redirect_uri: body.redirect_uri },
    ip,
    c.req.header('user-agent') || ''
  )

  return c.json({ code, redirect_uri: body.redirect_uri })
})

app.post('/oauth/token', async (c) => {
  const ip = clientIp(c)
  if (!rateLimit(`oauth_token:${ip}`, 30, 60)) {
    return c.json({ detail: 'too many attempts' }, 429)
  }

  const body = await c.req.json<{
    grant_type: string
    client_id: string
    code?: string
    redirect_uri?: string
    client_secret?: string
    code_verifier?: string
    refresh_token?: string
  }>()

  const client = await queryOne<{
    client_id: string
    client_name: string
    client_secret_hash: string | null
    is_confidential: boolean
    is_active: boolean
    attack_protection: any
  }>(
    `SELECT client_id, client_name, client_secret_hash, is_confidential, is_active, attack_protection
     FROM oauth_clients WHERE client_id = $1`,
    [body.client_id]
  )

  if (!client) return c.json({ detail: 'invalid_client' }, 400)
  if (!client.is_active) return c.json({ detail: 'client_disabled: this client application has been disabled' }, 403)

  const attackCfg = parseAttackProtection(client.attack_protection)

  // Brute Force Protection check
  const blockSecs = checkBruteForceBlock(body.client_id, ip, attackCfg)
  if (blockSecs !== null) {
    await logAudit(
      'ATTACK_BLOCKED',
      null,
      null,
      body.client_id,
      client.client_name,
      'system:attack_protection',
      { protection: 'brute_force_protection', reason: 'client_ip_temporarily_blocked', remaining_secs: blockSecs },
      ip,
      c.req.header('user-agent') || ''
    )
    return c.json({ detail: `brute_force_protection: too many failed attempts. Temporarily blocked for ${blockSecs} more seconds.` }, 429)
  }

  // Suspicious IP Throttling
  const tokenLimit = attackCfg.suspicious_ip_throttling ? 10 : 30
  if (!rateLimit(`oauth_token:${body.client_id}:${ip}`, tokenLimit, 60)) {
    await logAudit(
      'ATTACK_BLOCKED',
      null,
      null,
      client.client_id,
      client.client_name,
      'system:attack_protection',
      { protection: 'suspicious_ip_throttling', endpoint: '/api/oauth/token' },
      ip,
      c.req.header('user-agent') || ''
    )
    return c.json({ detail: 'too many attempts' }, 429)
  }

  // Client authentication for confidential clients
  if (client.is_confidential) {
    if (!body.client_secret) {
      recordFailedExchange(body.client_id, ip, attackCfg)
      return c.json({ detail: 'client_secret required' }, 401)
    }
    if (hashToken(body.client_secret) !== client.client_secret_hash) {
      recordFailedExchange(body.client_id, ip, attackCfg)
      return c.json({ detail: 'invalid client_secret' }, 401)
    }
  } else {
    // Public client
    if (body.grant_type === 'authorization_code' && !body.code_verifier) {
      return c.json({ detail: 'code_verifier required for public clients' }, 400)
    }
  }

  const now = nowIso()

  // --- Grant: authorization_code ---
  if (body.grant_type === 'authorization_code') {
    if (!body.code || !body.redirect_uri) {
      return c.json({ detail: 'code and redirect_uri required' }, 400)
    }

    const codeHash = hashToken(body.code)
    const codeRow = await queryOne<{
      code_hash: string
      client_id: string
      user_id: number
      redirect_uri: string
      code_challenge: string | null
      code_challenge_method: string | null
      expires_at: string
      used: boolean
    }>('SELECT * FROM oauth_codes WHERE code_hash = $1 AND client_id = $2', [codeHash, body.client_id])

    if (!codeRow) {
      recordFailedExchange(body.client_id, ip, attackCfg)
      return c.json({ detail: 'invalid_grant: code not found' }, 400)
    }

    if (codeRow.used) {
      recordFailedExchange(body.client_id, ip, attackCfg)
      await query('DELETE FROM oauth_tokens WHERE client_id = $1 AND user_id = $2', [body.client_id, codeRow.user_id])
      await query('UPDATE oauth_refresh_tokens SET revoked = TRUE WHERE client_id = $1 AND user_id = $2', [body.client_id, codeRow.user_id])

      const uRow = await queryOne<{ email: string }>('SELECT email FROM users WHERE id = $1', [codeRow.user_id])
      await logAudit(
        'AUTHORIZATION_CODE_REUSE_DETECTED',
        codeRow.user_id,
        uRow?.email || null,
        client.client_id,
        client.client_name,
        client.client_id,
        { error: 'code_already_used_tokens_revoked' },
        ip,
        c.req.header('user-agent') || ''
      )
      return c.json({ detail: 'invalid_grant: code already used' }, 400)
    }

    if (codeRow.expires_at <= now) {
      recordFailedExchange(body.client_id, ip, attackCfg)
      return c.json({ detail: 'invalid_grant: code expired' }, 400)
    }

    if (codeRow.redirect_uri !== body.redirect_uri) {
      recordFailedExchange(body.client_id, ip, attackCfg)
      return c.json({ detail: 'invalid_grant: redirect_uri mismatch' }, 400)
    }

    if (codeRow.code_challenge) {
      if (!body.code_verifier) {
        recordFailedExchange(body.client_id, ip, attackCfg)
        return c.json({ detail: 'code_verifier required' }, 400)
      }
      if (!verifyPkce(body.code_verifier, codeRow.code_challenge, codeRow.code_challenge_method || 'S256')) {
        recordFailedExchange(body.client_id, ip, attackCfg)
        return c.json({ detail: 'invalid code_verifier' }, 400)
      }
    } else if (!client.is_confidential) {
      return c.json({ detail: 'code_verifier required for public clients' }, 400)
    }

    clearFailedExchange(body.client_id, ip)
    await query('UPDATE oauth_codes SET used = TRUE WHERE code_hash = $1', [codeHash])

    const accessToken = newToken()
    const refreshToken = newToken()
    const tokenHash = hashToken(accessToken)
    const refreshHash = hashToken(refreshToken)
    const tokenExp = expiryIso(60) // 60 mins
    const refreshExp = daysExpiryIso(30) // 30 days

    await query('INSERT INTO oauth_tokens (token_hash, client_id, user_id, expires_at) VALUES ($1, $2, $3, $4)', [
      tokenHash,
      body.client_id,
      codeRow.user_id,
      tokenExp,
    ])

    await query(
      'INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, expires_at, revoked, created_at) VALUES ($1, $2, $3, $4, FALSE, $5)',
      [refreshHash, body.client_id, codeRow.user_id, refreshExp, now]
    )

    const uRow = await queryOne<{ email: string }>('SELECT email FROM users WHERE id = $1', [codeRow.user_id])
    await logAudit(
      'OAUTH_TOKEN',
      codeRow.user_id,
      uRow?.email || null,
      client.client_id,
      client.client_name,
      client.client_id,
      { grant_type: body.grant_type },
      ip,
      c.req.header('user-agent') || ''
    )

    return c.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
    })
  }

  // --- Grant: refresh_token ---
  if (body.grant_type === 'refresh_token') {
    if (!body.refresh_token) {
      return c.json({ detail: 'refresh_token required' }, 400)
    }

    const rfHash = hashToken(body.refresh_token)
    const rfRow = await queryOne<{
      token_hash: string
      client_id: string
      user_id: number
      expires_at: string
      revoked: boolean
    }>('SELECT * FROM oauth_refresh_tokens WHERE token_hash = $1 AND client_id = $2', [rfHash, body.client_id])

    if (!rfRow) {
      recordFailedExchange(body.client_id, ip, attackCfg)
      return c.json({ detail: 'invalid_grant: refresh token not found' }, 400)
    }

    if (rfRow.revoked) {
      recordFailedExchange(body.client_id, ip, attackCfg)
      await query('DELETE FROM oauth_tokens WHERE client_id = $1 AND user_id = $2', [body.client_id, rfRow.user_id])
      await query('DELETE FROM oauth_refresh_tokens WHERE client_id = $1 AND user_id = $2', [body.client_id, rfRow.user_id])
      return c.json({ detail: 'invalid_grant: refresh token reuse detected, tokens revoked' }, 400)
    }

    if (rfRow.expires_at <= now) {
      recordFailedExchange(body.client_id, ip, attackCfg)
      return c.json({ detail: 'invalid_grant: refresh token expired' }, 400)
    }

    clearFailedExchange(body.client_id, ip)

    const uChk = await queryOne<{ status: string }>('SELECT status FROM users WHERE id = $1', [rfRow.user_id])
    if (!uChk || uChk.status === 'suspended') {
      return c.json({ detail: 'access_denied: user account is suspended' }, 403)
    }

    const auChk = await queryOne<{ status: string }>('SELECT status FROM app_users WHERE client_id = $1 AND user_id = $2', [
      body.client_id,
      rfRow.user_id,
    ])
    if (auChk && auChk.status === 'revoked') {
      return c.json({ detail: 'access_denied: user revoked from app' }, 403)
    }

    // Revoke old refresh token (rotation)
    await query('UPDATE oauth_refresh_tokens SET revoked = TRUE WHERE token_hash = $1', [rfHash])

    const newAccessToken = newToken()
    const newRefreshToken = newToken()
    const newAccessHash = hashToken(newAccessToken)
    const newRfHash = hashToken(newRefreshToken)
    const accessExp = expiryIso(60)
    const rfExp = daysExpiryIso(30)

    await query('INSERT INTO oauth_tokens (token_hash, client_id, user_id, expires_at) VALUES ($1, $2, $3, $4)', [
      newAccessHash,
      body.client_id,
      rfRow.user_id,
      accessExp,
    ])

    await query(
      'INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, expires_at, revoked, created_at) VALUES ($1, $2, $3, $4, FALSE, $5)',
      [newRfHash, body.client_id, rfRow.user_id, rfExp, now]
    )

    const uRow = await queryOne<{ email: string }>('SELECT email FROM users WHERE id = $1', [rfRow.user_id])
    await logAudit(
      'TOKEN_REFRESHED',
      rfRow.user_id,
      uRow?.email || null,
      client.client_id,
      client.client_name,
      client.client_id,
      { grant_type: 'refresh_token' },
      ip,
      c.req.header('user-agent') || ''
    )

    return c.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: newRefreshToken,
    })
  }

  return c.json({ detail: 'unsupported grant_type' }, 400)
})

app.post('/oauth/revoke', async (c) => {
  const ip = clientIp(c)
  if (!rateLimit(`oauth_revoke:${ip}`, 30, 60)) {
    return c.json({ detail: 'too many attempts' }, 429)
  }

  const body = await c.req.json<{
    token: string
    token_type_hint?: string
    client_id: string
    client_secret?: string
  }>()

  const client = await queryOne<{
    client_id: string
    client_name: string
    client_secret_hash: string | null
    is_confidential: boolean
  }>('SELECT client_id, client_name, client_secret_hash, is_confidential FROM oauth_clients WHERE client_id = $1', [
    body.client_id,
  ])

  if (!client) return c.json({ detail: 'invalid_client' }, 400)

  if (client.is_confidential) {
    if (!body.client_secret) return c.json({ detail: 'client_secret required' }, 401)
    if (hashToken(body.client_secret) !== client.client_secret_hash) {
      return c.json({ detail: 'invalid client_secret' }, 401)
    }
  }

  const tokenHash = hashToken(body.token)
  const tokRow = await queryOne<{ user_id: number }>('SELECT user_id FROM oauth_tokens WHERE token_hash = $1 AND client_id = $2', [
    tokenHash,
    body.client_id,
  ])
  const rfRow = await queryOne<{ user_id: number }>(
    'SELECT user_id FROM oauth_refresh_tokens WHERE token_hash = $1 AND client_id = $2',
    [tokenHash, body.client_id]
  )

  const userId = tokRow?.user_id || rfRow?.user_id || null

  await query('DELETE FROM oauth_tokens WHERE token_hash = $1 AND client_id = $2', [tokenHash, body.client_id])
  await query('UPDATE oauth_refresh_tokens SET revoked = TRUE WHERE token_hash = $1 AND client_id = $2', [
    tokenHash,
    body.client_id,
  ])

  if (userId) {
    const uRow = await queryOne<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])
    await logAudit(
      'TOKEN_REVOKED',
      userId,
      uRow?.email || null,
      client.client_id,
      client.client_name,
      client.client_id,
      { token_type_hint: body.token_type_hint },
      ip,
      c.req.header('user-agent') || ''
    )
  }

  return c.json({ ok: true })
})

app.get('/oauth/userinfo', async (c) => {
  const authHeader = c.req.header('authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ detail: 'invalid_token: missing bearer header' }, 401)
  }

  const token = authHeader.slice(7).trim()
  const tokenHash = hashToken(token)
  const now = nowIso()

  const user = await queryOne<{
    google_sub: string
    email: string
    name: string
    picture: string | null
    user_status: string
    role: string | null
    status: string | null
    is_active: boolean
  }>(
    `SELECT u.google_sub, u.email, u.name, u.picture, u.status AS user_status,
            au.role, au.status, c.is_active
     FROM oauth_tokens t
     JOIN users u ON u.id = t.user_id
     JOIN oauth_clients c ON c.client_id = t.client_id
     LEFT JOIN app_users au ON au.client_id = t.client_id AND au.user_id = t.user_id
     WHERE t.token_hash = $1 AND t.expires_at > $2`,
    [tokenHash, now]
  )

  if (!user) return c.json({ detail: 'invalid_token: token expired or not found' }, 401)
  if (!user.is_active) return c.json({ detail: 'client_disabled: this client application has been disabled' }, 403)
  if (user.user_status === 'suspended') return c.json({ detail: 'access_denied: user account is suspended' }, 403)
  if (user.status === 'revoked') return c.json({ detail: 'access_denied: user access is revoked for this app' }, 403)

  return c.json({
    sub: String(user.google_sub),
    email: user.email,
    name: user.name,
    picture: user.picture,
    role: user.role || 'member',
    status: user.status || 'active',
  })
})

export default handle(app)

export const config = {
  path: '/api/*',
}
