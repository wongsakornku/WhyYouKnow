import csv
import hmac
import io
import json
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import timedelta
from urllib.parse import urlparse

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import auth
import config
import db

COOKIE = "session"
_attempts: dict[str, deque] = defaultdict(deque)

DEFAULT_ATTACK_PROTECTION = {
    "bot_detection": False,
    "suspicious_ip_throttling": True,
    "brute_force_protection": True,
    "suspicious_account_shield": False,
}

def parse_attack_protection(raw: str | dict | None) -> dict:
    cfg = dict(DEFAULT_ATTACK_PROTECTION)
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if k in cfg:
                        cfg[k] = bool(v)
        except Exception:
            pass
    elif isinstance(raw, dict):
        for k, v in raw.items():
            if k in cfg:
                cfg[k] = bool(v)
    return cfg

_failed_exchanges: dict[str, deque] = defaultdict(deque)
_blocked_entities: dict[str, float] = {}


def check_brute_force_block(client_id: str, ip: str, attack_cfg: dict, conn, client_name: str | None = None, request: Request | None = None):
    if not attack_cfg.get("brute_force_protection", True):
        return
    key = f"{client_id}:{ip}"
    t = time.monotonic()
    blocked_until = _blocked_entities.get(key, 0)
    if t < blocked_until:
        remaining = int(blocked_until - t)
        log_audit(
            conn,
            event_type="ATTACK_BLOCKED",
            client_id=client_id,
            client_name=client_name,
            action_by="system:attack_protection",
            details={"protection": "brute_force_protection", "reason": "client_ip_temporarily_blocked", "remaining_secs": remaining},
            ip=ip,
            ua=request.headers.get("user-agent", "") if request else "",
        )
        raise HTTPException(429, f"brute_force_protection: too many failed attempts. Temporarily blocked for {remaining} more seconds.")


def record_failed_exchange(client_id: str, ip: str, attack_cfg: dict, conn, client_name: str | None = None, request: Request | None = None):
    if not attack_cfg.get("brute_force_protection", True):
        return
    key = f"{client_id}:{ip}"
    t = time.monotonic()
    q = _failed_exchanges[key]
    while q and t - q[0] > 900:  # 15-minute window
        q.popleft()
    q.append(t)
    if len(q) >= 5:
        _blocked_entities[key] = t + 900  # 15-minute block
        log_audit(
            conn,
            event_type="ATTACK_BLOCKED",
            client_id=client_id,
            client_name=client_name,
            action_by="system:attack_protection",
            details={"protection": "brute_force_protection", "reason": "consecutive_exchange_failures", "failures_count": len(q), "blocked_secs": 900},
            ip=ip,
            ua=request.headers.get("user-agent", "") if request else "",
        )


def clear_failed_exchange(client_id: str, ip: str):
    key = f"{client_id}:{ip}"
    _failed_exchanges.pop(key, None)
    _blocked_entities.pop(key, None)


def log_audit(
    conn,
    event_type: str,
    user_id: int | None = None,
    user_email: str | None = None,
    client_id: str | None = None,
    client_name: str | None = None,
    action_by: str = "system",
    details: dict | str | None = None,
    ip: str = "unknown",
    ua: str = "",
):
    details_str = json.dumps(details, ensure_ascii=False) if isinstance(details, dict) else details
    conn.execute(
        "INSERT INTO audit_logs (event_type, user_id, user_email, client_id, client_name, "
        "action_by, details, ip_hmac, ua_short, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            event_type,
            user_id,
            user_email,
            client_id,
            client_name,
            action_by,
            details_str,
            auth.hmac_ip(ip),
            auth.short_ua(ua),
            auth.iso(auth.now()),
        ),
    )


def purge_old_logs() -> None:
    now_iso = auth.iso(auth.now())
    cutoff = auth.iso(auth.now() - timedelta(days=config.LOG_RETENTION_DAYS))
    audit_cutoff = auth.iso(auth.now() - timedelta(days=config.AUDIT_LOG_RETENTION_DAYS))
    with db.get_db() as conn:
        conn.execute("DELETE FROM login_logs WHERE at < %s", (cutoff,))
        conn.execute("DELETE FROM audit_logs WHERE created_at < %s", (audit_cutoff,))
        conn.execute("DELETE FROM sessions WHERE expires_at < %s", (now_iso,))
        conn.execute("DELETE FROM oauth_codes WHERE expires_at < %s OR used = TRUE", (now_iso,))
        conn.execute("DELETE FROM oauth_tokens WHERE expires_at < %s", (now_iso,))
        conn.execute("DELETE FROM oauth_refresh_tokens WHERE expires_at < %s OR revoked = TRUE", (now_iso,))


@asynccontextmanager
async def lifespan(_: FastAPI):
    config.validate_production_config()
    db.init_db()
    purge_old_logs()
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


def add_security_headers(res: Response) -> Response:
    res.headers["X-Content-Type-Options"] = "nosniff"
    res.headers["X-Frame-Options"] = "DENY"
    res.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    res.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    res.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    if config.COOKIE_SECURE:
        res.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return res


def sanitize_csv_cell(val: str | None) -> str:
    if not val:
        return ""
    s = str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def validate_redirect_uri(uri: str) -> None:
    parsed = urlparse(uri)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(400, f"invalid redirect_uri format: {uri}")
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, f"invalid scheme in redirect_uri: {uri}. Only http and https allowed")
    if parsed.scheme == "http":
        hostname = (parsed.hostname or "").lower()
        if hostname not in ("localhost", "127.0.0.1", "::1"):
            raise HTTPException(400, f"http redirect_uri only allowed for localhost: {uri}")
    if parsed.fragment:
        raise HTTPException(400, f"redirect_uri must not contain a fragment identifier: {uri}")


def escape_like(val: str) -> str:
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@app.middleware("http")
async def handle_security_and_cors(request: Request, call_next):
    # Preflight for external OAuth endpoints
    if request.method == "OPTIONS" and request.url.path.startswith("/api/oauth/"):
        res = Response(status_code=204)
        res.headers["Access-Control-Allow-Origin"] = "*"
        res.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        res.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return add_security_headers(res)

    # Allow token exchange, userinfo, and token revocation from external apps
    if request.url.path in ("/api/oauth/token", "/api/oauth/userinfo", "/api/oauth/revoke"):
        res = await call_next(request)
        res.headers["Access-Control-Allow-Origin"] = "*"
        return add_security_headers(res)

    # CSRF defense: state-changing requests must come from an allowed origin
    if request.method in ("POST", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin not in config.ALLOWED_ORIGINS:
            from fastapi.responses import JSONResponse

            res = JSONResponse({"detail": "bad origin"}, status_code=403)
            return add_security_headers(res)

    res = await call_next(request)
    return add_security_headers(res)


@app.get("/api/health")
def health_check():
    return {"status": "ok"}


def client_ip(request: Request) -> str:
    peer_ip = request.client.host if request.client else "unknown"
    if config.TRUSTED_PROXIES and peer_ip in config.TRUSTED_PROXIES:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return peer_ip


def rate_limit(
    request: Request,
    key_prefix: str = "general",
    max_attempts: int = 10,
    window_secs: int = 60,
) -> None:
    ip, t = client_ip(request), time.monotonic()
    rate_key = f"{key_prefix}:{ip}"

    # Prevent memory exhaustion: prune stale rate limit buckets if tracking too many keys
    if len(_attempts) > 10000:
        stale_keys = [k for k, timestamps in _attempts.items() if not timestamps or (t - timestamps[-1] > 3600)]
        for k in stale_keys:
            _attempts.pop(k, None)

    q = _attempts[rate_key]
    while q and t - q[0] > window_secs:
        q.popleft()
    if len(q) >= max_attempts:
        raise HTTPException(429, "too many attempts")
    q.append(t)


def current_user(session: str | None = Cookie(default=None)):
    if not session:
        raise HTTPException(401, "not authenticated")
    with db.get_db() as conn:
        row = conn.execute(
            "SELECT u.id, u.email, u.name, u.picture, u.status, u.is_admin FROM sessions s "
            "JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = %s AND s.expires_at > %s",
            (auth.hash_token(session), auth.iso(auth.now())),
        ).fetchone()
    if not row:
        raise HTTPException(401, "not authenticated")
    if row.get("status") == "suspended":
        raise HTTPException(403, "account_suspended: your account has been suspended by an administrator")
    is_super = row["email"].lower() in config.ADMIN_EMAILS
    is_admin = bool(row.get("is_admin")) or is_super
    user_dict = dict(row)
    user_dict["is_admin"] = is_admin
    user_dict["is_super_admin"] = is_super
    return user_dict


def require_admin(user: dict = Depends(current_user)):
    if not user.get("is_admin"):
        raise HTTPException(403, "forbidden")
    return user


def require_super_admin(user: dict = Depends(current_user)):
    if not user.get("is_super_admin"):
        raise HTTPException(403, "forbidden: super admin required")
    return user


class GoogleLoginBody(BaseModel):
    credential: str


@app.post("/api/auth/google")
def login(body: GoogleLoginBody, request: Request, response: Response):
    rate_limit(request, key_prefix="google", max_attempts=10, window_secs=60)
    try:
        info = auth.verify_google_token(body.credential)
    except ValueError:
        raise HTTPException(401, "invalid token")
    now = auth.iso(auth.now())
    token = auth.new_session_token()
    is_super = info["email"].lower() in config.ADMIN_EMAILS

    with db.get_db() as conn:
        existing = conn.execute("SELECT id, status FROM users WHERE google_sub = %s", (info["sub"],)).fetchone()
        if existing and existing.get("status") == "suspended":
            raise HTTPException(403, "account_suspended: your account has been suspended by an administrator")

        conn.execute(
            "INSERT INTO users (google_sub, email, name, picture, status, is_admin, created_at, last_login_at) "
            "VALUES (%s, %s, %s, %s, 'active', %s, %s, %s) ON DUPLICATE KEY UPDATE "
            "email = %s, name = %s, picture = %s, last_login_at = %s"
            + (", is_admin = TRUE" if is_super else ""),
            (info["sub"], info["email"], info.get("name", info["email"]),
             info.get("picture"), is_super, now, now,
             info["email"], info.get("name", info["email"]),
             info.get("picture"), now),
        )
        user = conn.execute(
            "SELECT id, email, name, picture, is_admin, status FROM users WHERE google_sub = %s", (info["sub"],)
        ).fetchone()
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (%s, %s, %s)",
            (auth.hash_token(token), user["id"], auth.iso(auth.session_expiry())),
        )
        conn.execute(
            "INSERT INTO login_logs (user_id, at, ip_hmac, ua_short) VALUES (%s, %s, %s, %s)",
            (user["id"], now, auth.hmac_ip(client_ip(request)),
             auth.short_ua(request.headers.get("user-agent", ""))),
        )
        log_audit(
            conn,
            event_type="LOGIN",
            user_id=user["id"],
            user_email=user["email"],
            action_by=user["email"],
            details={"method": "google"},
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )

    response.set_cookie(
        COOKIE, token, httponly=True, secure=config.COOKIE_SECURE, samesite="lax",
        max_age=config.SESSION_DAYS * 86400, path="/",
    )
    user_is_admin = bool(user.get("is_admin")) or is_super
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "picture": user["picture"],
        "status": user.get("status", "active"),
        "is_admin": user_is_admin,
        "is_super_admin": is_super,
    }


@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "picture": user["picture"],
        "status": user.get("status", "active"),
        "is_admin": user.get("is_admin", False),
        "is_super_admin": user.get("is_super_admin", False),
    }


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, session: str | None = Cookie(default=None)):
    if session:
        with db.get_db() as conn:
            sess_row = conn.execute(
                "SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = %s",
                (auth.hash_token(session),),
            ).fetchone()
            if sess_row:
                log_audit(
                    conn,
                    event_type="LOGOUT",
                    user_id=sess_row["id"],
                    user_email=sess_row["email"],
                    action_by=sess_row["email"],
                    ip=client_ip(request),
                    ua=request.headers.get("user-agent", ""),
                )
            conn.execute("DELETE FROM sessions WHERE token_hash = %s", (auth.hash_token(session),))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.delete("/api/me")
def delete_me(request: Request, response: Response, user: dict = Depends(current_user)):
    with db.get_db() as conn:
        log_audit(
            conn,
            event_type="ACCOUNT_DELETED",
            user_id=user["id"],
            user_email=user["email"],
            action_by=user["email"],
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
        conn.execute("DELETE FROM users WHERE id = %s", (user["id"],))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me/dashboard")
def me_dashboard(user: dict = Depends(current_user)):
    with db.get_db() as conn:
        apps = conn.execute(
            "SELECT c.client_id, c.client_name, au.role, au.status, au.created_at, au.last_accessed_at "
            "FROM app_users au JOIN oauth_clients c ON c.client_id = au.client_id "
            "WHERE au.user_id = %s ORDER BY au.last_accessed_at DESC",
            (user["id"],),
        ).fetchall()
        recent_activity = conn.execute(
            "SELECT id, event_type, client_name, created_at, details "
            "FROM audit_logs WHERE user_id = %s "
            "ORDER BY id DESC LIMIT 5",
            (user["id"],),
        ).fetchall()
    return {
        "profile": user,
        "apps": apps,
        "recent_activity": recent_activity,
    }


@app.delete("/api/me/apps/{client_id}")
def me_disconnect_app(client_id: str, request: Request, user: dict = Depends(current_user)):
    with db.get_db() as conn:
        client = conn.execute(
            "SELECT client_name FROM oauth_clients WHERE client_id = %s",
            (client_id,),
        ).fetchone()
        if not client:
            raise HTTPException(404, "client not found")
        conn.execute(
            "DELETE FROM app_users WHERE client_id = %s AND user_id = %s",
            (client_id, user["id"]),
        )
        conn.execute(
            "DELETE FROM oauth_tokens WHERE client_id = %s AND user_id = %s",
            (client_id, user["id"]),
        )
        conn.execute(
            "DELETE FROM oauth_refresh_tokens WHERE client_id = %s AND user_id = %s",
            (client_id, user["id"]),
        )
        log_audit(
            conn,
            event_type="USER_APP_DISCONNECTED",
            user_id=user["id"],
            user_email=user["email"],
            client_id=client_id,
            client_name=client["client_name"],
            action_by=user["email"],
            details=f"User self-disconnected {client['client_name']}",
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
    return {"ok": True}


@app.get("/api/admin/dashboard-stats")
def admin_dashboard_stats(user: dict = Depends(require_admin)):
    now = auth.iso(auth.now())
    with db.get_db() as conn:
        total_apps = conn.execute("SELECT COUNT(*) AS c FROM oauth_clients").fetchone()["c"]
        active_apps = conn.execute("SELECT COUNT(*) AS c FROM oauth_clients WHERE is_active = TRUE").fetchone()["c"]
        total_users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        active_sessions = conn.execute(
            "SELECT COUNT(*) AS c FROM sessions WHERE expires_at > %s",
            (now,),
        ).fetchone()["c"]
        active_tokens = conn.execute(
            "SELECT COUNT(*) AS c FROM oauth_tokens WHERE expires_at > %s",
            (now,),
        ).fetchone()["c"]
        recent_logs = conn.execute(
            "SELECT id, event_type, user_email, client_name, action_by, details, created_at "
            "FROM audit_logs ORDER BY id DESC LIMIT 5"
        ).fetchall()
    return {
        "total_apps": total_apps,
        "active_apps": active_apps,
        "total_users": total_users,
        "active_sessions": active_sessions,
        "active_tokens": active_tokens,
        "recent_logs": recent_logs,
    }


@app.get("/api/admin/users")
def admin_users(user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        rows = conn.execute("SELECT id, email, name, status, is_admin, created_at, last_login_at FROM users ORDER BY id DESC").fetchall()
    return [
        {
            "id": r["id"],
            "email": r["email"],
            "name": r["name"],
            "status": r.get("status") or "active",
            "is_admin": bool(r.get("is_admin")) or (r["email"].lower() in config.ADMIN_EMAILS),
            "is_super_admin": r["email"].lower() in config.ADMIN_EMAILS,
            "created_at": r["created_at"],
            "last_login_at": r["last_login_at"],
        }
        for r in rows
    ]


@app.get("/api/admin/users/{user_id}")
def admin_get_user_detail(user_id: int, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        u = conn.execute(
            "SELECT id, email, name, picture, status, is_admin, created_at, last_login_at FROM users WHERE id = %s",
            (user_id,),
        ).fetchone()
        if not u:
            raise HTTPException(404, "user not found")

        apps = conn.execute(
            "SELECT c.client_id, c.client_name, au.role, au.status, au.created_at, au.last_accessed_at "
            "FROM app_users au JOIN oauth_clients c ON c.client_id = au.client_id "
            "WHERE au.user_id = %s ORDER BY au.last_accessed_at DESC",
            (user_id,),
        ).fetchall()

        sess_count = conn.execute("SELECT COUNT(*) AS c FROM sessions WHERE user_id = %s", (user_id,)).fetchone()["c"]
        tok_count = conn.execute("SELECT COUNT(*) AS c FROM oauth_tokens WHERE user_id = %s", (user_id,)).fetchone()["c"]

    is_super = u["email"].lower() in config.ADMIN_EMAILS
    return {
        "user": {
            **u,
            "is_admin": bool(u.get("is_admin")) or is_super,
            "is_super_admin": is_super,
        },
        "apps": apps,
        "active_sessions": sess_count,
        "active_tokens": tok_count,
    }


@app.post("/api/admin/users/{user_id}/force-logout")
def admin_force_logout(user_id: int, request: Request, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        target = conn.execute("SELECT email FROM users WHERE id = %s", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user not found")

        conn.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
        conn.execute("DELETE FROM oauth_tokens WHERE user_id = %s", (user_id,))
        conn.execute("DELETE FROM oauth_refresh_tokens WHERE user_id = %s", (user_id,))
        log_audit(
            conn,
            event_type="FORCE_LOGOUT",
            user_id=user_id,
            user_email=target["email"],
            action_by=user["email"],
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
    return {"ok": True}


@app.post("/api/admin/users/{user_id}/suspend")
def admin_suspend_user(user_id: int, request: Request, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        target = conn.execute("SELECT email FROM users WHERE id = %s", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user not found")
        if target["email"].lower() in config.ADMIN_EMAILS:
            raise HTTPException(400, "cannot suspend super admin")

        conn.execute("UPDATE users SET status = 'suspended' WHERE id = %s", (user_id,))
        conn.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
        conn.execute("DELETE FROM oauth_tokens WHERE user_id = %s", (user_id,))
        conn.execute("DELETE FROM oauth_refresh_tokens WHERE user_id = %s", (user_id,))
        log_audit(
            conn,
            event_type="USER_SUSPENDED",
            user_id=user_id,
            user_email=target["email"],
            action_by=user["email"],
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
    return {"ok": True, "status": "suspended"}


@app.post("/api/admin/users/{user_id}/unsuspend")
def admin_unsuspend_user(user_id: int, request: Request, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        target = conn.execute("SELECT email FROM users WHERE id = %s", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user not found")

        conn.execute("UPDATE users SET status = 'active' WHERE id = %s", (user_id,))
        log_audit(
            conn,
            event_type="USER_UNSUSPENDED",
            user_id=user_id,
            user_email=target["email"],
            action_by=user["email"],
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
    return {"ok": True, "status": "active"}


class SetAdminBody(BaseModel):
    is_admin: bool


@app.post("/api/admin/users/{user_id}/admin")
def admin_set_user_admin(user_id: int, body: SetAdminBody, request: Request, user: dict = Depends(require_super_admin)):
    with db.get_db() as conn:
        target = conn.execute("SELECT email, is_admin FROM users WHERE id = %s", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user not found")
        if target["email"].lower() in config.ADMIN_EMAILS:
            raise HTTPException(400, "cannot modify super admin privileges")

        conn.execute("UPDATE users SET is_admin = %s WHERE id = %s", (body.is_admin, user_id))
        log_audit(
            conn,
            event_type="ADMIN_GRANTED" if body.is_admin else "ADMIN_REVOKED",
            user_id=user_id,
            user_email=target["email"],
            action_by=user["email"],
            details={"is_admin": body.is_admin},
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
    return {"ok": True, "is_admin": body.is_admin}


# ==============================================================================
# OAuth 2.0 / SSO Endpoints
# ==============================================================================

@app.get("/api/oauth/client-info")
def get_client_info(client_id: str):
    with db.get_db() as conn:
        row = conn.execute(
            "SELECT client_id, client_name, redirect_uris, is_confidential, is_active, access_mode, attack_protection "
            "FROM oauth_clients WHERE client_id = %s",
            (client_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "client not found")
    if not bool(row.get("is_active", True)):
        raise HTTPException(403, "client_disabled: this client application has been disabled")
    try:
        uris = json.loads(row["redirect_uris"])
    except Exception:
        uris = [u.strip() for u in row["redirect_uris"].split(",") if u.strip()]
    return {
        "client_id": row["client_id"],
        "client_name": row["client_name"],
        "redirect_uris": uris,
        "is_confidential": bool(row["is_confidential"]),
        "is_active": bool(row.get("is_active", True)),
        "access_mode": row.get("access_mode", "open"),
        "attack_protection": parse_attack_protection(row.get("attack_protection")),
    }


class AuthorizeBody(BaseModel):
    client_id: str
    redirect_uri: str
    code_challenge: str | None = None
    code_challenge_method: str | None = "S256"
    bot_token: str | None = None


@app.post("/api/oauth/authorize")
def authorize_client(body: AuthorizeBody, request: Request, user: dict = Depends(current_user)):
    rate_limit(request, key_prefix="oauth_authorize", max_attempts=30, window_secs=60)
    with db.get_db() as conn:
        client = conn.execute(
            "SELECT client_id, client_name, redirect_uris, is_confidential, is_active, access_mode, attack_protection "
            "FROM oauth_clients WHERE client_id = %s",
            (body.client_id,),
        ).fetchone()
    if not client:
        raise HTTPException(404, "client not found")

    if not bool(client.get("is_active", True)):
        raise HTTPException(403, "client_disabled: this client application has been disabled")

    attack_cfg = parse_attack_protection(client.get("attack_protection"))

    # Attack Protection: Suspicious IP Throttling
    auth_limit = 10 if attack_cfg.get("suspicious_ip_throttling") else 30
    try:
        rate_limit(request, key_prefix=f"oauth_auth:{body.client_id}", max_attempts=auth_limit, window_secs=60)
    except HTTPException as e:
        if e.status_code == 429:
            with db.get_db() as conn:
                log_audit(
                    conn,
                    event_type="ATTACK_BLOCKED",
                    client_id=client["client_id"],
                    client_name=client["client_name"],
                    action_by="system:attack_protection",
                    details={"protection": "suspicious_ip_throttling", "endpoint": "/api/oauth/authorize"},
                    ip=client_ip(request),
                    ua=request.headers.get("user-agent", ""),
                )
        raise e

    # Attack Protection: Bot Detection
    if attack_cfg.get("bot_detection"):
        if not body.bot_token or body.bot_token != "human-verified":
            with db.get_db() as conn:
                log_audit(
                    conn,
                    event_type="ATTACK_BLOCKED",
                    client_id=client["client_id"],
                    client_name=client["client_name"],
                    action_by="system:attack_protection",
                    details={"protection": "bot_detection", "reason": "bot_verification_missing_or_failed"},
                    ip=client_ip(request),
                    ua=request.headers.get("user-agent", ""),
                )
            raise HTTPException(400, "bot_detection: verification challenge required")

    # Attack Protection: Suspicious Account Shield
    if attack_cfg.get("suspicious_account_shield"):
        if user.get("status") != "active":
            with db.get_db() as conn:
                log_audit(
                    conn,
                    event_type="ATTACK_BLOCKED",
                    user_id=user["id"],
                    user_email=user["email"],
                    client_id=client["client_id"],
                    client_name=client["client_name"],
                    action_by="system:attack_protection",
                    details={"protection": "suspicious_account_shield", "reason": "account_status_not_active"},
                    ip=client_ip(request),
                    ua=request.headers.get("user-agent", ""),
                )
            raise HTTPException(403, "suspicious_account_shield: account verification required")

    try:
        allowed_uris = json.loads(client["redirect_uris"])
    except Exception:
        allowed_uris = [u.strip() for u in client["redirect_uris"].split(",") if u.strip()]

    if body.redirect_uri not in allowed_uris:
        raise HTTPException(400, "invalid redirect_uri")

    # Enforce PKCE for public clients (RFC 7636 / OAuth 2.1)
    if not client["is_confidential"]:
        if not body.code_challenge:
            raise HTTPException(400, "code_challenge required for public clients")
    if body.code_challenge and body.code_challenge_method != "S256":
        raise HTTPException(400, "unsupported code_challenge_method: only S256 is supported")

    # Access control: check access_mode (open vs invite_only)
    assigned_role = "member"
    now_iso = auth.iso(auth.now())
    with db.get_db() as conn:
        existing_app_user = conn.execute(
            "SELECT role, status FROM app_users WHERE client_id = %s AND user_id = %s",
            (body.client_id, user["id"]),
        ).fetchone()

        if existing_app_user and existing_app_user["status"] == "revoked":
            raise HTTPException(403, "access_denied: user access is revoked for this app")

        access_mode = client.get("access_mode", "open")
        if access_mode == "invite_only" and not existing_app_user:
            invite = conn.execute(
                "SELECT role FROM app_invites WHERE client_id = %s AND LOWER(email) = %s",
                (body.client_id, user["email"].lower()),
            ).fetchone()
            if not invite:
                raise HTTPException(403, "access_denied: this application is invite-only and you have not been invited")
            assigned_role = invite["role"]
            conn.execute(
                "DELETE FROM app_invites WHERE client_id = %s AND LOWER(email) = %s",
                (body.client_id, user["email"].lower()),
            )
        elif existing_app_user:
            assigned_role = existing_app_user["role"]

        # Associate or update user in app_users
        conn.execute(
            "INSERT INTO app_users (client_id, user_id, role, status, created_at, last_accessed_at) "
            "VALUES (%s, %s, %s, 'active', %s, %s) ON DUPLICATE KEY UPDATE "
            "last_accessed_at = %s",
            (body.client_id, user["id"], assigned_role, now_iso, now_iso, now_iso),
        )

    code = auth.new_session_token()
    code_hash = auth.hash_token(code)
    expiry = auth.iso(auth.oauth_code_expiry())

    with db.get_db() as conn:
        conn.execute(
            "INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, expires_at, used) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE)",
            (code_hash, body.client_id, user["id"], body.redirect_uri,
             body.code_challenge, body.code_challenge_method, expiry),
        )
        log_audit(
            conn,
            event_type="OAUTH_AUTHORIZE",
            user_id=user["id"],
            user_email=user["email"],
            client_id=client["client_id"],
            client_name=client["client_name"],
            action_by=user["email"],
            details={"redirect_uri": body.redirect_uri},
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )

    return {"code": code, "redirect_uri": body.redirect_uri}


class TokenExchangeBody(BaseModel):
    grant_type: str
    client_id: str
    code: str | None = None
    redirect_uri: str | None = None
    client_secret: str | None = None
    code_verifier: str | None = None
    refresh_token: str | None = None


@app.post("/api/oauth/token")
def exchange_token(body: TokenExchangeBody, request: Request):
    rate_limit(request, key_prefix="oauth_token", max_attempts=30, window_secs=60)
    ip = client_ip(request)
    now_iso = auth.iso(auth.now())

    with db.get_db() as conn:
        client = conn.execute(
            "SELECT client_id, client_name, client_secret_hash, is_confidential, is_active, attack_protection "
            "FROM oauth_clients WHERE client_id = %s",
            (body.client_id,),
        ).fetchone()
    if not client:
        raise HTTPException(400, "invalid_client")

    if not bool(client.get("is_active", True)):
        raise HTTPException(403, "client_disabled: this client application has been disabled")

    attack_cfg = parse_attack_protection(client.get("attack_protection"))

    # Attack Protection: Brute-Force Check
    with db.get_db() as conn:
        check_brute_force_block(body.client_id, ip, attack_cfg, conn, client["client_name"], request)

    # Attack Protection: Suspicious IP Throttling
    token_limit = 10 if attack_cfg.get("suspicious_ip_throttling") else 30
    try:
        rate_limit(request, key_prefix=f"oauth_token:{body.client_id}", max_attempts=token_limit, window_secs=60)
    except HTTPException as e:
        if e.status_code == 429:
            with db.get_db() as conn:
                log_audit(
                    conn,
                    event_type="ATTACK_BLOCKED",
                    client_id=client["client_id"],
                    client_name=client["client_name"],
                    action_by="system:attack_protection",
                    details={"protection": "suspicious_ip_throttling", "endpoint": "/api/oauth/token"},
                    ip=ip,
                    ua=request.headers.get("user-agent", ""),
                )
        raise e

    if client["is_confidential"]:
        if not body.client_secret:
            with db.get_db() as conn:
                record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
            raise HTTPException(401, "client_secret required")
        if not hmac.compare_digest(auth.hash_token(body.client_secret), client["client_secret_hash"]):
            with db.get_db() as conn:
                record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
            raise HTTPException(401, "invalid client_secret")
    else:
        # Public client
        if body.grant_type == "authorization_code" and not body.code_verifier:
            raise HTTPException(400, "code_verifier required for public clients")

    # Flow A: authorization_code
    if body.grant_type == "authorization_code":
        if not body.code or not body.redirect_uri:
            raise HTTPException(400, "code and redirect_uri required")

        code_hash = auth.hash_token(body.code)
        with db.get_db() as conn:
            code_row = conn.execute(
                "SELECT code_hash, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, expires_at, used "
                "FROM oauth_codes WHERE code_hash = %s AND client_id = %s",
                (code_hash, body.client_id),
            ).fetchone()

        if not code_row:
            with db.get_db() as conn:
                record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
            raise HTTPException(400, "invalid_grant: code not found")
        if code_row["used"]:
            with db.get_db() as conn:
                record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
                conn.execute(
                    "DELETE FROM oauth_tokens WHERE client_id = %s AND user_id = %s",
                    (body.client_id, code_row["user_id"]),
                )
                conn.execute(
                    "UPDATE oauth_refresh_tokens SET revoked = TRUE WHERE client_id = %s AND user_id = %s",
                    (body.client_id, code_row["user_id"]),
                )
                u_row = conn.execute("SELECT email FROM users WHERE id = %s", (code_row["user_id"],)).fetchone()
                u_email = u_row["email"] if u_row else None
                log_audit(
                    conn,
                    event_type="AUTHORIZATION_CODE_REUSE_DETECTED",
                    user_id=code_row["user_id"],
                    user_email=u_email,
                    client_id=client["client_id"],
                    client_name=client["client_name"],
                    action_by=client["client_id"],
                    details={"error": "code_already_used_tokens_revoked"},
                    ip=client_ip(request),
                )
            raise HTTPException(400, "invalid_grant: code already used")
        if code_row["expires_at"] <= now_iso:
            with db.get_db() as conn:
                record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
            raise HTTPException(400, "invalid_grant: code expired")
        if code_row["redirect_uri"] != body.redirect_uri:
            with db.get_db() as conn:
                record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
            raise HTTPException(400, "invalid_grant: redirect_uri mismatch")

        if code_row["code_challenge"]:
            if not body.code_verifier:
                with db.get_db() as conn:
                    record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
                raise HTTPException(400, "code_verifier required")
            if not auth.verify_pkce(body.code_verifier, code_row["code_challenge"], code_row["code_challenge_method"] or "S256"):
                with db.get_db() as conn:
                    record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
                raise HTTPException(400, "invalid code_verifier")
        elif not client["is_confidential"]:
            raise HTTPException(400, "code_verifier required for public clients")

        clear_failed_exchange(body.client_id, ip)

        with db.get_db() as conn:
            conn.execute("UPDATE oauth_codes SET used = TRUE WHERE code_hash = %s", (code_hash,))

        access_token = auth.new_session_token()
        refresh_token = auth.new_session_token()
        token_hash = auth.hash_token(access_token)
        refresh_hash = auth.hash_token(refresh_token)
        token_expiry = auth.iso(auth.oauth_token_expiry())
        refresh_expiry = auth.iso(auth.oauth_refresh_token_expiry())

        with db.get_db() as conn:
            conn.execute(
                "INSERT INTO oauth_tokens (token_hash, client_id, user_id, expires_at) VALUES (%s, %s, %s, %s)",
                (token_hash, body.client_id, code_row["user_id"], token_expiry),
            )
            conn.execute(
                "INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, expires_at, revoked, created_at) "
                "VALUES (%s, %s, %s, %s, FALSE, %s)",
                (refresh_hash, body.client_id, code_row["user_id"], refresh_expiry, now_iso),
            )
            u_row = conn.execute("SELECT email FROM users WHERE id = %s", (code_row["user_id"],)).fetchone()
            u_email = u_row["email"] if u_row else None
            log_audit(
                conn,
                event_type="OAUTH_TOKEN",
                user_id=code_row["user_id"],
                user_email=u_email,
                client_id=client["client_id"],
                client_name=client["client_name"],
                action_by=client["client_id"],
                details={"grant_type": body.grant_type},
                ip=client_ip(request),
                ua=request.headers.get("user-agent", ""),
            )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": config.OAUTH_ACCESS_TOKEN_MINUTES * 60,
            "refresh_token": refresh_token,
        }

    # Flow B: refresh_token
    elif body.grant_type == "refresh_token":
        if not body.refresh_token:
            raise HTTPException(400, "refresh_token required")

        rf_hash = auth.hash_token(body.refresh_token)
        with db.get_db() as conn:
            rf_row = conn.execute(
                "SELECT token_hash, client_id, user_id, expires_at, revoked FROM oauth_refresh_tokens "
                "WHERE token_hash = %s AND client_id = %s",
                (rf_hash, body.client_id),
            ).fetchone()

        if not rf_row:
            with db.get_db() as conn:
                record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
            raise HTTPException(400, "invalid_grant: refresh token not found")

        if rf_row["revoked"]:
            # Token reuse detection: revoke all tokens for this user & client
            with db.get_db() as conn:
                record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
                conn.execute("DELETE FROM oauth_tokens WHERE client_id = %s AND user_id = %s", (body.client_id, rf_row["user_id"]))
                conn.execute("DELETE FROM oauth_refresh_tokens WHERE client_id = %s AND user_id = %s", (body.client_id, rf_row["user_id"]))
            raise HTTPException(400, "invalid_grant: refresh token reuse detected, tokens revoked")

        if rf_row["expires_at"] <= now_iso:
            with db.get_db() as conn:
                record_failed_exchange(body.client_id, ip, attack_cfg, conn, client["client_name"], request)
            raise HTTPException(400, "invalid_grant: refresh token expired")

        clear_failed_exchange(body.client_id, ip)

        # Check user status
        with db.get_db() as conn:
            u_chk = conn.execute("SELECT status FROM users WHERE id = %s", (rf_row["user_id"],)).fetchone()
            if not u_chk or u_chk.get("status") == "suspended":
                raise HTTPException(403, "access_denied: user account is suspended")
            au_chk = conn.execute("SELECT status FROM app_users WHERE client_id = %s AND user_id = %s", (body.client_id, rf_row["user_id"])).fetchone()
            if au_chk and au_chk["status"] == "revoked":
                raise HTTPException(403, "access_denied: user revoked from app")

            # Mark old refresh token as revoked (rotation)
            conn.execute("UPDATE oauth_refresh_tokens SET revoked = TRUE WHERE token_hash = %s", (rf_hash,))

            new_access_token = auth.new_session_token()
            new_refresh_token = auth.new_session_token()
            new_access_hash = auth.hash_token(new_access_token)
            new_rf_hash = auth.hash_token(new_refresh_token)
            access_expiry = auth.iso(auth.oauth_token_expiry())
            rf_expiry = auth.iso(auth.oauth_refresh_token_expiry())

            conn.execute(
                "INSERT INTO oauth_tokens (token_hash, client_id, user_id, expires_at) VALUES (%s, %s, %s, %s)",
                (new_access_hash, body.client_id, rf_row["user_id"], access_expiry),
            )
            conn.execute(
                "INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, expires_at, revoked, created_at) "
                "VALUES (%s, %s, %s, %s, FALSE, %s)",
                (new_rf_hash, body.client_id, rf_row["user_id"], rf_expiry, now_iso),
            )
            u_row = conn.execute("SELECT email FROM users WHERE id = %s", (rf_row["user_id"],)).fetchone()
            u_email = u_row["email"] if u_row else None
            log_audit(
                conn,
                event_type="TOKEN_REFRESHED",
                user_id=rf_row["user_id"],
                user_email=u_email,
                client_id=client["client_id"],
                client_name=client["client_name"],
                action_by=client["client_id"],
                details={"grant_type": "refresh_token"},
                ip=client_ip(request),
                ua=request.headers.get("user-agent", ""),
            )

        return {
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": config.OAUTH_ACCESS_TOKEN_MINUTES * 60,
            "refresh_token": new_refresh_token,
        }

    else:
        raise HTTPException(400, "unsupported grant_type")


class RevokeTokenBody(BaseModel):
    token: str
    token_type_hint: str | None = None
    client_id: str
    client_secret: str | None = None


@app.post("/api/oauth/revoke")
def revoke_token(body: RevokeTokenBody, request: Request):
    rate_limit(request, key_prefix="oauth_revoke", max_attempts=30, window_secs=60)
    with db.get_db() as conn:
        client = conn.execute(
            "SELECT client_id, client_name, client_secret_hash, is_confidential FROM oauth_clients WHERE client_id = %s",
            (body.client_id,),
        ).fetchone()
    if not client:
        raise HTTPException(400, "invalid_client")

    if client["is_confidential"]:
        if not body.client_secret:
            raise HTTPException(401, "client_secret required")
        if not hmac.compare_digest(auth.hash_token(body.client_secret), client["client_secret_hash"]):
            raise HTTPException(401, "invalid client_secret")

    token_hash = auth.hash_token(body.token)
    with db.get_db() as conn:
        tok_row = conn.execute("SELECT user_id FROM oauth_tokens WHERE token_hash = %s AND client_id = %s", (token_hash, body.client_id)).fetchone()
        rf_row = conn.execute("SELECT user_id FROM oauth_refresh_tokens WHERE token_hash = %s AND client_id = %s", (token_hash, body.client_id)).fetchone()
        user_id = tok_row["user_id"] if tok_row else (rf_row["user_id"] if rf_row else None)

        conn.execute("DELETE FROM oauth_tokens WHERE token_hash = %s AND client_id = %s", (token_hash, body.client_id))
        conn.execute("UPDATE oauth_refresh_tokens SET revoked = TRUE WHERE token_hash = %s AND client_id = %s", (token_hash, body.client_id))

        if user_id:
            u_row = conn.execute("SELECT email FROM users WHERE id = %s", (user_id,)).fetchone()
            u_email = u_row["email"] if u_row else None
            log_audit(
                conn,
                event_type="TOKEN_REVOKED",
                user_id=user_id,
                user_email=u_email,
                client_id=client["client_id"],
                client_name=client["client_name"],
                action_by=client["client_id"],
                details={"token_type_hint": body.token_type_hint},
                ip=client_ip(request),
                ua=request.headers.get("user-agent", ""),
            )

    return {"ok": True}


@app.get("/api/oauth/userinfo")
def oauth_userinfo(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "invalid_token: missing bearer header")

    token = authorization[7:].strip()
    token_hash = auth.hash_token(token)
    now_iso = auth.iso(auth.now())

    with db.get_db() as conn:
        user = conn.execute(
            "SELECT u.google_sub, u.email, u.name, u.picture, u.status AS user_status, "
            "au.role, au.status, c.is_active "
            "FROM oauth_tokens t "
            "JOIN users u ON u.id = t.user_id "
            "JOIN oauth_clients c ON c.client_id = t.client_id "
            "LEFT JOIN app_users au ON au.client_id = t.client_id AND au.user_id = t.user_id "
            "WHERE t.token_hash = %s AND t.expires_at > %s",
            (token_hash, now_iso),
        ).fetchone()

    if not user:
        raise HTTPException(401, "invalid_token: token expired or not found")

    if not bool(user.get("is_active", True)):
        raise HTTPException(403, "client_disabled: this client application has been disabled")

    if user.get("user_status") == "suspended":
        raise HTTPException(403, "access_denied: user account is suspended")

    if user["status"] == "revoked":
        raise HTTPException(403, "access_denied: user access is revoked for this app")

    return {
        "sub": str(user["google_sub"]),
        "email": user["email"],
        "name": user["name"],
        "picture": user["picture"],
        "role": user["role"] or "member",
        "status": user["status"] or "active",
    }


# ==============================================================================
# Admin: OAuth Clients & Users-by-App Management
# ==============================================================================

@app.get("/api/admin/clients")
def admin_list_clients(user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        rows = conn.execute(
            "SELECT c.id, c.client_id, c.client_name, c.redirect_uris, c.is_confidential, "
            "c.is_active, c.access_mode, c.attack_protection, c.created_at, "
            "COUNT(au.id) AS user_count "
            "FROM oauth_clients c "
            "LEFT JOIN app_users au ON au.client_id = c.client_id "
            "GROUP BY c.id ORDER BY c.id DESC"
        ).fetchall()

    clients = []
    for r in rows:
        try:
            uris = json.loads(r["redirect_uris"])
        except Exception:
            uris = [u.strip() for u in r["redirect_uris"].split(",") if u.strip()]
        clients.append({
            "id": r["id"],
            "client_id": r["client_id"],
            "client_name": r["client_name"],
            "redirect_uris": uris,
            "is_confidential": bool(r["is_confidential"]),
            "is_active": bool(r.get("is_active", True)),
            "access_mode": r.get("access_mode", "open"),
            "attack_protection": parse_attack_protection(r.get("attack_protection")),
            "created_at": r["created_at"],
            "user_count": r["user_count"],
        })
    return clients


class CreateClientBody(BaseModel):
    client_name: str
    redirect_uris: list[str]
    is_confidential: bool = True
    access_mode: str = "open"


@app.post("/api/admin/clients")
def admin_create_client(body: CreateClientBody, request: Request, user: dict = Depends(require_admin)):
    if not body.redirect_uris:
        raise HTTPException(400, "at least one redirect_uri is required")
    for uri in body.redirect_uris:
        validate_redirect_uri(uri)

    if body.access_mode not in ("open", "invite_only"):
        raise HTTPException(400, "invalid access_mode")

    client_id, client_secret = auth.generate_client_credentials()
    secret_hash = auth.hash_token(client_secret) if body.is_confidential else None
    now_iso = auth.iso(auth.now())
    uris_json = json.dumps(body.redirect_uris)
    attack_json = json.dumps(DEFAULT_ATTACK_PROTECTION)

    with db.get_db() as conn:
        conn.execute(
            "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, is_confidential, is_active, access_mode, attack_protection, created_at) "
            "VALUES (%s, %s, %s, %s, %s, TRUE, %s, %s, %s)",
            (client_id, secret_hash, body.client_name, uris_json, body.is_confidential, body.access_mode, attack_json, now_iso),
        )
        log_audit(
            conn,
            event_type="CLIENT_CREATED",
            client_id=client_id,
            client_name=body.client_name,
            action_by=user["email"],
            details={"is_confidential": body.is_confidential, "redirect_uris": body.redirect_uris, "access_mode": body.access_mode},
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )

    return {
        "client_id": client_id,
        "client_secret": client_secret if body.is_confidential else None,
        "client_name": body.client_name,
        "redirect_uris": body.redirect_uris,
        "is_confidential": body.is_confidential,
        "is_active": True,
        "access_mode": body.access_mode,
        "attack_protection": DEFAULT_ATTACK_PROTECTION,
    }


class AttackProtectionBody(BaseModel):
    bot_detection: bool | None = None
    suspicious_ip_throttling: bool | None = None
    brute_force_protection: bool | None = None
    suspicious_account_shield: bool | None = None


@app.patch("/api/admin/clients/{client_id}/attack-protection")
def admin_update_client_attack_protection(
    client_id: str,
    body: AttackProtectionBody,
    request: Request,
    user: dict = Depends(require_admin)
):
    with db.get_db() as conn:
        client = conn.execute("SELECT client_name, attack_protection FROM oauth_clients WHERE client_id = %s", (client_id,)).fetchone()
    if not client:
        raise HTTPException(404, "client not found")

    cfg = parse_attack_protection(client.get("attack_protection"))
    updates = {}
    if body.bot_detection is not None:
        cfg["bot_detection"] = body.bot_detection
        updates["bot_detection"] = body.bot_detection
    if body.suspicious_ip_throttling is not None:
        cfg["suspicious_ip_throttling"] = body.suspicious_ip_throttling
        updates["suspicious_ip_throttling"] = body.suspicious_ip_throttling
    if body.brute_force_protection is not None:
        cfg["brute_force_protection"] = body.brute_force_protection
        updates["brute_force_protection"] = body.brute_force_protection
    if body.suspicious_account_shield is not None:
        cfg["suspicious_account_shield"] = body.suspicious_account_shield
        updates["suspicious_account_shield"] = body.suspicious_account_shield

    cfg_json = json.dumps(cfg)
    with db.get_db() as conn:
        conn.execute("UPDATE oauth_clients SET attack_protection = %s WHERE client_id = %s", (cfg_json, client_id))
        log_audit(
            conn,
            event_type="ATTACK_PROTECTION_UPDATED",
            client_id=client_id,
            client_name=client["client_name"],
            action_by=user["email"],
            details=updates,
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )

    return {"client_id": client_id, "attack_protection": cfg}


class UpdateClientBody(BaseModel):
    client_name: str | None = None
    redirect_uris: list[str] | None = None
    access_mode: str | None = None


@app.patch("/api/admin/clients/{client_id}")
def admin_update_client(client_id: str, body: UpdateClientBody, request: Request, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        client = conn.execute("SELECT client_name, redirect_uris, access_mode FROM oauth_clients WHERE client_id = %s", (client_id,)).fetchone()
    if not client:
        raise HTTPException(404, "client not found")

    updates = []
    params = []
    audit_details = {}

    if body.client_name is not None:
        updates.append("client_name = %s")
        params.append(body.client_name)
        audit_details["client_name"] = body.client_name

    if body.redirect_uris is not None:
        if not body.redirect_uris:
            raise HTTPException(400, "at least one redirect_uri required")
        for uri in body.redirect_uris:
            validate_redirect_uri(uri)
        updates.append("redirect_uris = %s")
        params.append(json.dumps(body.redirect_uris))
        audit_details["redirect_uris"] = body.redirect_uris

    if body.access_mode is not None:
        if body.access_mode not in ("open", "invite_only"):
            raise HTTPException(400, "invalid access_mode. Must be 'open' or 'invite_only'")
        updates.append("access_mode = %s")
        params.append(body.access_mode)
        audit_details["access_mode"] = body.access_mode

    if not updates:
        return {"ok": True}

    params.append(client_id)
    with db.get_db() as conn:
        conn.execute(f"UPDATE oauth_clients SET {', '.join(updates)} WHERE client_id = %s", tuple(params))
        log_audit(
            conn,
            event_type="CLIENT_UPDATED",
            client_id=client_id,
            client_name=body.client_name or client["client_name"],
            action_by=user["email"],
            details=audit_details,
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )

    return {"ok": True}


@app.post("/api/admin/clients/{client_id}/rotate-secret")
def admin_rotate_client_secret(client_id: str, request: Request, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        client = conn.execute("SELECT client_name, is_confidential FROM oauth_clients WHERE client_id = %s", (client_id,)).fetchone()
    if not client:
        raise HTTPException(404, "client not found")
    if not client["is_confidential"]:
        raise HTTPException(400, "cannot rotate secret for public client")

    _, new_secret = auth.generate_client_credentials()
    new_hash = auth.hash_token(new_secret)

    with db.get_db() as conn:
        conn.execute("UPDATE oauth_clients SET client_secret_hash = %s WHERE client_id = %s", (new_hash, client_id))
        log_audit(
            conn,
            event_type="SECRET_ROTATED",
            client_id=client_id,
            client_name=client["client_name"],
            action_by=user["email"],
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )

    return {"client_id": client_id, "client_secret": new_secret}


class ClientStatusBody(BaseModel):
    is_active: bool


@app.post("/api/admin/clients/{client_id}/status")
def admin_set_client_status(client_id: str, body: ClientStatusBody, request: Request, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        client = conn.execute("SELECT client_name FROM oauth_clients WHERE client_id = %s", (client_id,)).fetchone()
    if not client:
        raise HTTPException(404, "client not found")

    with db.get_db() as conn:
        conn.execute("UPDATE oauth_clients SET is_active = %s WHERE client_id = %s", (body.is_active, client_id))
        if not body.is_active:
            conn.execute("DELETE FROM oauth_tokens WHERE client_id = %s", (client_id,))
            conn.execute("DELETE FROM oauth_codes WHERE client_id = %s", (client_id,))
            conn.execute("DELETE FROM oauth_refresh_tokens WHERE client_id = %s", (client_id,))
        log_audit(
            conn,
            event_type="CLIENT_ENABLED" if body.is_active else "CLIENT_DISABLED",
            client_id=client_id,
            client_name=client["client_name"],
            action_by=user["email"],
            details={"is_active": body.is_active},
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )

    return {"ok": True, "is_active": body.is_active}


@app.delete("/api/admin/clients/{client_id}")
def admin_delete_client(client_id: str, request: Request, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        client = conn.execute("SELECT client_name FROM oauth_clients WHERE client_id = %s", (client_id,)).fetchone()
        c_name = client["client_name"] if client else None
        log_audit(
            conn,
            event_type="CLIENT_DELETED",
            client_id=client_id,
            client_name=c_name,
            action_by=user["email"],
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
        conn.execute("DELETE FROM oauth_tokens WHERE client_id = %s", (client_id,))
        conn.execute("DELETE FROM oauth_refresh_tokens WHERE client_id = %s", (client_id,))
        conn.execute("DELETE FROM oauth_codes WHERE client_id = %s", (client_id,))
        conn.execute("DELETE FROM app_users WHERE client_id = %s", (client_id,))
        conn.execute("DELETE FROM app_invites WHERE client_id = %s", (client_id,))
        conn.execute("DELETE FROM oauth_clients WHERE client_id = %s", (client_id,))
    return {"ok": True}


# --- Invites Management ---

@app.get("/api/admin/clients/{client_id}/invites")
def admin_get_client_invites(client_id: str, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        rows = conn.execute(
            "SELECT id, client_id, email, role, created_at FROM app_invites WHERE client_id = %s ORDER BY id DESC",
            (client_id,),
        ).fetchall()
    return rows


class CreateInviteBody(BaseModel):
    email: str
    role: str = "member"


@app.post("/api/admin/clients/{client_id}/invites")
def admin_create_client_invite(client_id: str, body: CreateInviteBody, request: Request, user: dict = Depends(require_admin)):
    if body.role not in ("admin", "member", "viewer"):
        raise HTTPException(400, "invalid role")
    clean_email = body.email.strip().lower()
    if not clean_email or "@" not in clean_email:
        raise HTTPException(400, "invalid email")

    with db.get_db() as conn:
        client = conn.execute("SELECT client_name FROM oauth_clients WHERE client_id = %s", (client_id,)).fetchone()
    if not client:
        raise HTTPException(404, "client not found")

    now_iso = auth.iso(auth.now())
    with db.get_db() as conn:
        conn.execute(
            "INSERT INTO app_invites (client_id, email, role, created_at) "
            "VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE role = %s",
            (client_id, clean_email, body.role, now_iso, body.role),
        )
        log_audit(
            conn,
            event_type="INVITE_ADDED",
            client_id=client_id,
            client_name=client["client_name"],
            user_email=clean_email,
            action_by=user["email"],
            details={"role": body.role},
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
    return {"ok": True, "email": clean_email, "role": body.role}


@app.delete("/api/admin/clients/{client_id}/invites/{invite_id}")
def admin_delete_client_invite(client_id: str, invite_id: int, request: Request, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        invite = conn.execute("SELECT email, client_id FROM app_invites WHERE id = %s AND client_id = %s", (invite_id, client_id)).fetchone()
        if not invite:
            raise HTTPException(404, "invite not found")
        client = conn.execute("SELECT client_name FROM oauth_clients WHERE client_id = %s", (client_id,)).fetchone()
        conn.execute("DELETE FROM app_invites WHERE id = %s", (invite_id,))
        log_audit(
            conn,
            event_type="INVITE_REMOVED",
            client_id=client_id,
            client_name=client["client_name"] if client else None,
            user_email=invite["email"],
            action_by=user["email"],
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
    return {"ok": True}


# --- Users by App Management ---

@app.get("/api/admin/clients/{client_id}/users")
def admin_get_app_users(client_id: str, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        rows = conn.execute(
            "SELECT u.id AS user_id, u.email, u.name, u.picture, "
            "au.role, au.status, au.created_at, au.last_accessed_at "
            "FROM app_users au "
            "JOIN users u ON u.id = au.user_id "
            "WHERE au.client_id = %s "
            "ORDER BY au.last_accessed_at DESC",
            (client_id,),
        ).fetchall()

    return [
        {
            "user_id": r["user_id"],
            "email": r["email"],
            "name": r["name"],
            "picture": r["picture"],
            "role": r["role"],
            "status": r["status"],
            "created_at": r["created_at"],
            "last_accessed_at": r["last_accessed_at"],
        }
        for r in rows
    ]


class UpdateRoleBody(BaseModel):
    role: str


@app.post("/api/admin/clients/{client_id}/users/{user_id}/role")
def admin_update_app_user_role(
    client_id: str, user_id: int, body: UpdateRoleBody, request: Request, user: dict = Depends(require_admin)
):
    if body.role not in ("admin", "member", "viewer"):
        raise HTTPException(400, "invalid role")

    with db.get_db() as conn:
        app_user = conn.execute(
            "SELECT au.id, u.email, c.client_name FROM app_users au "
            "JOIN users u ON u.id = au.user_id "
            "JOIN oauth_clients c ON c.client_id = au.client_id "
            "WHERE au.client_id = %s AND au.user_id = %s",
            (client_id, user_id),
        ).fetchone()
        if not app_user:
            raise HTTPException(404, "user not found in this client application")

        conn.execute(
            "UPDATE app_users SET role = %s WHERE client_id = %s AND user_id = %s",
            (body.role, client_id, user_id),
        )
        log_audit(
            conn,
            event_type="ROLE_UPDATED",
            user_id=user_id,
            user_email=app_user["email"],
            client_id=client_id,
            client_name=app_user["client_name"],
            action_by=user["email"],
            details={"role": body.role},
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
    return {"ok": True, "role": body.role}


class UpdateStatusBody(BaseModel):
    status: str


@app.post("/api/admin/clients/{client_id}/users/{user_id}/status")
def admin_update_app_user_status(
    client_id: str, user_id: int, body: UpdateStatusBody, request: Request, user: dict = Depends(require_admin)
):
    if body.status not in ("active", "revoked"):
        raise HTTPException(400, "invalid status")

    with db.get_db() as conn:
        app_user = conn.execute(
            "SELECT au.id, u.email, c.client_name FROM app_users au "
            "JOIN users u ON u.id = au.user_id "
            "JOIN oauth_clients c ON c.client_id = au.client_id "
            "WHERE au.client_id = %s AND au.user_id = %s",
            (client_id, user_id),
        ).fetchone()
        if not app_user:
            raise HTTPException(404, "user not found in this client application")

        conn.execute(
            "UPDATE app_users SET status = %s WHERE client_id = %s AND user_id = %s",
            (body.status, client_id, user_id),
        )
        if body.status == "revoked":
            conn.execute(
                "DELETE FROM oauth_tokens WHERE client_id = %s AND user_id = %s",
                (client_id, user_id),
            )
            conn.execute(
                "DELETE FROM oauth_refresh_tokens WHERE client_id = %s AND user_id = %s",
                (client_id, user_id),
            )
        log_audit(
            conn,
            event_type="STATUS_UPDATED",
            user_id=user_id,
            user_email=app_user["email"],
            client_id=client_id,
            client_name=app_user["client_name"],
            action_by=user["email"],
            details={"status": body.status},
            ip=client_ip(request),
            ua=request.headers.get("user-agent", ""),
        )
    return {"ok": True, "status": body.status}


# ==============================================================================
# Admin: Audit Logs & Export
# ==============================================================================

@app.get("/api/admin/audit-logs")
def admin_get_audit_logs(
    q: str | None = None,
    event_type: str | None = None,
    client_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
    user: dict = Depends(require_admin),
):
    where_clauses = []
    params = []

    if event_type:
        where_clauses.append("event_type = %s")
        params.append(event_type)
    if client_id:
        where_clauses.append("client_id = %s")
        params.append(client_id)
    if q:
        where_clauses.append("(user_email LIKE %s OR client_name LIKE %s OR action_by LIKE %s OR details LIKE %s)")
        like_val = f"%{escape_like(q)}%"
        params.extend([like_val, like_val, like_val, like_val])

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    with db.get_db() as conn:
        count_row = conn.execute(f"SELECT COUNT(*) AS total FROM audit_logs {where_sql}", tuple(params)).fetchone()
        total = count_row["total"] if count_row else 0

        data_params = list(params)
        data_params.extend([limit, offset])
        rows = conn.execute(
            f"SELECT id, event_type, user_id, user_email, client_id, client_name, action_by, details, ip_hmac, ua_short, created_at "
            f"FROM audit_logs {where_sql} ORDER BY id DESC LIMIT %s OFFSET %s",
            tuple(data_params),
        ).fetchall()

    return {"logs": rows, "total": total}


@app.get("/api/admin/audit-logs/export")
def admin_export_audit_logs(
    q: str | None = None,
    event_type: str | None = None,
    client_id: str | None = None,
    format: str = "csv",
    user: dict = Depends(require_admin),
):
    where_clauses = []
    params = []

    if event_type:
        where_clauses.append("event_type = %s")
        params.append(event_type)
    if client_id:
        where_clauses.append("client_id = %s")
        params.append(client_id)
    if q:
        where_clauses.append("(user_email LIKE %s OR client_name LIKE %s OR action_by LIKE %s OR details LIKE %s)")
        like_val = f"%{escape_like(q)}%"
        params.extend([like_val, like_val, like_val, like_val])

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    with db.get_db() as conn:
        rows = conn.execute(
            f"SELECT id, event_type, user_email, client_name, action_by, details, ip_hmac, ua_short, created_at "
            f"FROM audit_logs {where_sql} ORDER BY id DESC LIMIT 5000",
            tuple(params),
        ).fetchall()

    filename_date = auth.now().strftime("%Y-%m-%d")

    if format == "json":
        content = json.dumps(rows, ensure_ascii=False, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="audit_logs_{filename_date}.json"'},
        )

    # CSV format with UTF-8 BOM (\ufeff)
    output = io.StringIO()
    output.write("\ufeff")
    writer = csv.writer(output)
    writer.writerow(["ID", "Event Type", "User Email", "Target App", "Action By", "Details", "IP Hash", "User Agent", "Timestamp (UTC)"])
    for r in rows:
        writer.writerow([
            r["id"],
            sanitize_csv_cell(r["event_type"]),
            sanitize_csv_cell(r["user_email"]),
            sanitize_csv_cell(r["client_name"]),
            sanitize_csv_cell(r["action_by"]),
            sanitize_csv_cell(r["details"]),
            r["ip_hmac"],
            sanitize_csv_cell(r["ua_short"]),
            r["created_at"],
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="audit_logs_{filename_date}.csv"'},
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run("main:app", host=host, port=port, reload=False)

