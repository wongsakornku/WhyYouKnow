import pg from 'pg'

const { Pool } = pg

const connectionString = process.env.DATABASE_URL || ''

let pool: pg.Pool | null = null

export function getPool(): pg.Pool {
  if (!pool) {
    if (!connectionString) {
      console.warn('[DB] Warning: DATABASE_URL environment variable is not set!')
    }
    pool = new Pool({
      connectionString,
      ssl: connectionString.includes('localhost') ? false : { rejectUnauthorized: false },
      max: 10,
      idleTimeoutMillis: 30000,
    })
  }
  return pool
}

export async function query<T = any>(text: string, params: any[] = []): Promise<T[]> {
  const p = getPool()
  const res = await p.query(text, params)
  return res.rows as T[]
}

export async function queryOne<T = any>(text: string, params: any[] = []): Promise<T | null> {
  const rows = await query<T>(text, params)
  return rows[0] || null
}

