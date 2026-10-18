-- ==============================================================================
-- WhyYouKnow Database Schema for PostgreSQL / Supabase
-- Copy and paste this into Supabase SQL Editor and click 'Run'
-- ==============================================================================

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  google_sub VARCHAR(64) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  picture TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  is_admin BOOLEAN NOT NULL DEFAULT FALSE,
  created_at VARCHAR(64) NOT NULL,
  last_login_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- 2. Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
  token_hash VARCHAR(64) PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

-- Optional: Drop deprecated login_logs table to free storage
-- DROP TABLE IF EXISTS login_logs;

-- 3. OAuth Clients Table
CREATE TABLE IF NOT EXISTS oauth_clients (
  id SERIAL PRIMARY KEY,
  client_id VARCHAR(64) NOT NULL UNIQUE,
  client_secret_hash VARCHAR(64),
  client_name VARCHAR(255) NOT NULL,
  redirect_uris TEXT NOT NULL,
  is_confidential BOOLEAN NOT NULL DEFAULT TRUE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  access_mode VARCHAR(32) NOT NULL DEFAULT 'open',
  attack_protection TEXT,
  created_at VARCHAR(64) NOT NULL
);

-- 5. App Invites Table
CREATE TABLE IF NOT EXISTS app_invites (
  id SERIAL PRIMARY KEY,
  client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'member',
  created_at VARCHAR(64) NOT NULL,
  CONSTRAINT uq_client_invite UNIQUE (client_id, email)
);

-- 6. App Users Table
CREATE TABLE IF NOT EXISTS app_users (
  id SERIAL PRIMARY KEY,
  client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(32) NOT NULL DEFAULT 'member',
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at VARCHAR(64) NOT NULL,
  last_accessed_at VARCHAR(64) NOT NULL,
  CONSTRAINT uq_client_user UNIQUE (client_id, user_id)
);

-- 7. OAuth Codes Table
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash VARCHAR(64) PRIMARY KEY,
  client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  code_challenge VARCHAR(128),
  code_challenge_method VARCHAR(16),
  expires_at VARCHAR(64) NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE
);

-- 8. OAuth Access Tokens Table
CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash VARCHAR(64) PRIMARY KEY,
  client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at VARCHAR(64) NOT NULL
);

-- 9. OAuth Refresh Tokens Table
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  token_hash VARCHAR(64) PRIMARY KEY,
  client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at VARCHAR(64) NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at VARCHAR(64) NOT NULL
);

-- 10. Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  user_id INT,
  user_email VARCHAR(255),
  client_id VARCHAR(64),
  client_name VARCHAR(255),
  action_by VARCHAR(255) NOT NULL,
  details JSONB,
  ip_hmac VARCHAR(64) NOT NULL,
  ua_short VARCHAR(128),
  created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_email ON audit_logs(user_email);
CREATE INDEX IF NOT EXISTS idx_audit_logs_client_id ON audit_logs(client_id);
