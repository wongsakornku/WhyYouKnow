from contextlib import contextmanager
import pymysql
import pymysql.cursors

import config

SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      google_sub VARCHAR(255) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      picture TEXT,
      status VARCHAR(32) NOT NULL DEFAULT 'active',
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      created_at VARCHAR(64) NOT NULL,
      last_login_at VARCHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash VARCHAR(64) PRIMARY KEY,
      user_id INT NOT NULL,
      expires_at VARCHAR(64) NOT NULL,
      CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS login_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      at VARCHAR(64) NOT NULL,
      ip_hmac VARCHAR(64) NOT NULL,
      ua_short VARCHAR(128),
      CONSTRAINT fk_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS oauth_clients (
      id INT AUTO_INCREMENT PRIMARY KEY,
      client_id VARCHAR(64) NOT NULL UNIQUE,
      client_secret_hash VARCHAR(64) NULL,
      client_name VARCHAR(255) NOT NULL,
      redirect_uris TEXT NOT NULL,
      is_confidential BOOLEAN NOT NULL DEFAULT TRUE,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      access_mode VARCHAR(32) NOT NULL DEFAULT 'open',
      attack_protection TEXT NULL,
      created_at VARCHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS oauth_codes (
      code_hash VARCHAR(64) PRIMARY KEY,
      client_id VARCHAR(64) NOT NULL,
      user_id INT NOT NULL,
      redirect_uri TEXT NOT NULL,
      code_challenge VARCHAR(128) NULL,
      code_challenge_method VARCHAR(16) NULL,
      expires_at VARCHAR(64) NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      CONSTRAINT fk_oauth_codes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      token_hash VARCHAR(64) PRIMARY KEY,
      client_id VARCHAR(64) NOT NULL,
      user_id INT NOT NULL,
      expires_at VARCHAR(64) NOT NULL,
      CONSTRAINT fk_oauth_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
      token_hash VARCHAR(64) PRIMARY KEY,
      client_id VARCHAR(64) NOT NULL,
      user_id INT NOT NULL,
      expires_at VARCHAR(64) NOT NULL,
      revoked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at VARCHAR(64) NOT NULL,
      CONSTRAINT fk_oauth_refresh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      CONSTRAINT fk_oauth_refresh_client FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS app_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      client_id VARCHAR(64) NOT NULL,
      user_id INT NOT NULL,
      role VARCHAR(32) NOT NULL DEFAULT 'member',
      status VARCHAR(32) NOT NULL DEFAULT 'active',
      created_at VARCHAR(64) NOT NULL,
      last_accessed_at VARCHAR(64) NOT NULL,
      UNIQUE KEY uk_client_user (client_id, user_id),
      CONSTRAINT fk_app_user_client FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
      CONSTRAINT fk_app_user_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS app_invites (
      id INT AUTO_INCREMENT PRIMARY KEY,
      client_id VARCHAR(64) NOT NULL,
      email VARCHAR(255) NOT NULL,
      role VARCHAR(32) NOT NULL DEFAULT 'member',
      created_at VARCHAR(64) NOT NULL,
      UNIQUE KEY uk_invite (client_id, email),
      CONSTRAINT fk_invites_client FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      event_type VARCHAR(64) NOT NULL,
      user_id INT NULL,
      user_email VARCHAR(255) NULL,
      client_id VARCHAR(64) NULL,
      client_name VARCHAR(255) NULL,
      action_by VARCHAR(255) NOT NULL,
      details TEXT NULL,
      ip_hmac VARCHAR(64) NOT NULL,
      ua_short VARCHAR(128) NULL,
      created_at VARCHAR(64) NOT NULL,
      INDEX idx_event (event_type),
      INDEX idx_user (user_email),
      INDEX idx_client (client_id),
      INDEX idx_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
]

MIGRATION_STATEMENTS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'active';",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;",
    "ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;",
    "ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS access_mode VARCHAR(32) NOT NULL DEFAULT 'open';",
    "ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS attack_protection TEXT NULL;",
]


def connect() -> pymysql.connections.Connection:
    conn_kwargs = {
        "user": config.DB_USER,
        "password": config.DB_PASS,
        "database": config.DB_NAME,
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": False,
    }
    if config.DB_SOCKET:
        conn_kwargs["unix_socket"] = config.DB_SOCKET
    else:
        conn_kwargs["host"] = config.DB_HOST
        conn_kwargs["port"] = config.DB_PORT

    return pymysql.connect(**conn_kwargs)


class DBContext:
    def __init__(self, conn: pymysql.connections.Connection):
        self.conn = conn
        self.cursor = conn.cursor()

    def execute(self, query: str, args=None):
        self.cursor.execute(query, args)
        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()


@contextmanager
def get_db():
    conn = connect()
    ctx = DBContext(conn)
    try:
        yield ctx
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        ctx.cursor.close()
        conn.close()


def init_db() -> None:
    # First ensure database exists (graceful for managed Cloud SQL where user may lack global CREATE DATABASE)
    try:
        root_kwargs = {
            "user": config.DB_USER,
            "password": config.DB_PASS,
            "charset": "utf8mb4",
            "autocommit": True,
        }
        if config.DB_SOCKET:
            root_kwargs["unix_socket"] = config.DB_SOCKET
        else:
            root_kwargs["host"] = config.DB_HOST
            root_kwargs["port"] = config.DB_PORT

        root_conn = pymysql.connect(**root_kwargs)
        with root_conn.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{config.DB_NAME}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
            )
        root_conn.close()
    except Exception:
        pass

    # Create tables inside the database and apply migrations
    with get_db() as ctx:
        for stmt in SCHEMA_STATEMENTS:
            ctx.execute(stmt)
        for stmt in MIGRATION_STATEMENTS:
            try:
                ctx.execute(stmt)
            except Exception:
                pass
