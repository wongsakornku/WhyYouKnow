import base64
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from google.auth.transport import requests as g_requests
from google.oauth2 import id_token

import config


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def verify_google_token(credential: str) -> dict:
    """Verify signature, audience, issuer and expiry. Raises ValueError."""
    info = id_token.verify_oauth2_token(
        credential, g_requests.Request(), config.GOOGLE_CLIENT_ID
    )
    if not info.get("email_verified"):
        raise ValueError("email not verified")
    return info


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hmac_ip(ip: str) -> str:
    return hmac.new(config.IP_HMAC_SECRET.encode(), ip.encode(), hashlib.sha256).hexdigest()


def short_ua(ua: str) -> str:
    browser = next(
        (b for b in ("Edg", "OPR", "Firefox", "Chrome", "Safari") if b in ua), "Other"
    )
    os_name = next(
        (o for o in ("Windows", "Android", "iPhone", "Mac OS", "Linux") if o in ua), "Other"
    )
    return f"{re.sub('Edg$', 'Edge', browser)}/{os_name}"


def session_expiry() -> datetime:
    return now() + timedelta(days=config.SESSION_DAYS)


def oauth_code_expiry() -> datetime:
    return now() + timedelta(minutes=5)


def oauth_token_expiry() -> datetime:
    return now() + timedelta(minutes=config.OAUTH_ACCESS_TOKEN_MINUTES)


def oauth_refresh_token_expiry() -> datetime:
    return now() + timedelta(days=config.OAUTH_REFRESH_TOKEN_DAYS)


PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    if not code_verifier or not PKCE_VERIFIER_RE.match(code_verifier):
        return False
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return hmac.compare_digest(computed, code_challenge)
    return False


def generate_client_credentials():
    client_id = f"wyk_{secrets.token_hex(16)}"
    client_secret = f"sec_{secrets.token_urlsafe(32)}"
    return client_id, client_secret
