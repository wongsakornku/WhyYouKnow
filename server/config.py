import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
IP_HMAC_SECRET = os.environ.get("IP_HMAC_SECRET", "dev-insecure-change-me")
ADMIN_EMAILS = {
    e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()
}
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "")
DB_NAME = os.environ.get("DB_NAME", "kno")
INSTANCE_CONNECTION_NAME = os.environ.get("INSTANCE_CONNECTION_NAME", "")
DB_SOCKET = os.environ.get("DB_SOCKET", "")
if INSTANCE_CONNECTION_NAME and not DB_SOCKET:
    DB_SOCKET = f"/cloudsql/{INSTANCE_CONNECTION_NAME}"


ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]
TRUSTED_PROXIES = {
    p.strip() for p in os.environ.get("TRUSTED_PROXIES", "").split(",") if p.strip()
}
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() != "false"
SESSION_DAYS = 7
LOG_RETENTION_DAYS = 30
AUDIT_LOG_RETENTION_DAYS = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", "90"))
OAUTH_ACCESS_TOKEN_MINUTES = int(os.environ.get("OAUTH_ACCESS_TOKEN_MINUTES", "60"))
OAUTH_REFRESH_TOKEN_DAYS = int(os.environ.get("OAUTH_REFRESH_TOKEN_DAYS", "30"))
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()


def validate_production_config() -> None:
    if ENVIRONMENT == "production":
        if IP_HMAC_SECRET in ("", "dev-insecure-change-me"):
            raise ValueError("Insecure configuration: IP_HMAC_SECRET must be set to a cryptographically strong secret in production.")
        if not GOOGLE_CLIENT_ID:
            raise ValueError("Insecure configuration: GOOGLE_CLIENT_ID must be set in production.")
        if not COOKIE_SECURE:
            raise ValueError("Insecure configuration: COOKIE_SECURE must be true in production.")
