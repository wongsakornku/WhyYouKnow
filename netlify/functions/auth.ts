import crypto from 'crypto'
import { OAuth2Client } from 'google-auth-library'

const googleClientId = process.env.GOOGLE_CLIENT_ID || process.env.VITE_GOOGLE_CLIENT_ID || ''
const googleClient = new OAuth2Client(googleClientId)

const IP_HMAC_SECRET = process.env.IP_HMAC_SECRET || 'dev-insecure-change-me'
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',')
  .map((e) => e.trim().toLowerCase())
  .filter(Boolean)

export function isSuperAdmin(email: string): boolean {
  return ADMIN_EMAILS.includes(email.toLowerCase())
}

export async function verifyGoogleToken(idToken: string) {
  const ticket = await googleClient.verifyIdToken({
    idToken,
    audience: googleClientId,
  })
  const payload = ticket.getPayload()
  if (!payload || !payload.sub || !payload.email) {
    throw new Error('Invalid Google token payload')
  }
  return {
    sub: payload.sub,
    email: payload.email,
    name: payload.name || payload.email.split('@')[0],
    picture: payload.picture || null,
  }
}

export function newToken(): string {
  return crypto.randomBytes(32).toString('hex')
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex')
}

export function hashIp(ip: string): string {
  return crypto.createHmac('sha256', IP_HMAC_SECRET).update(ip).digest('hex')
}

export function verifyPkce(verifier: string, challenge: string, method = 'S256'): boolean {
  if (method === 'plain') {
    return verifier === challenge
  }
  const hash = crypto.createHash('sha256').update(verifier).digest('base64url')
  return hash === challenge
}

export function nowIso(): string {
  return new Date().toISOString()
}

export function expiryIso(minutes = 60): string {
  const d = new Date()
  d.setMinutes(d.getMinutes() + minutes)
  return d.toISOString()
}

export function daysExpiryIso(days = 30): string {
  const d = new Date()
  d.setDate(d.getDate() + days)
  return d.toISOString()
}

