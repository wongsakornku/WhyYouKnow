import base64
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DB_NAME"] = "kno_test"
os.environ["ADMIN_EMAILS"] = "admin@example.com"
os.environ["COOKIE_SECURE"] = "false"

import pytest
from fastapi.testclient import TestClient

import auth
import config
import db
import main

ORIGIN = {"Origin": "http://localhost:5173"}


def fake(email, sub, verified=True):
    def _v(_cred):
        return {"sub": sub, "email": email, "name": email.split("@")[0], "picture": "http://p/x"}
    return _v


@pytest.fixture(autouse=True)
def setup_test_db():
    config.DB_NAME = "kno_test"
    db.init_db()
    with db.get_db() as ctx:
        ctx.execute("SET FOREIGN_KEY_CHECKS = 0;")
        ctx.execute("TRUNCATE TABLE audit_logs;")
        ctx.execute("TRUNCATE TABLE app_invites;")
        ctx.execute("TRUNCATE TABLE app_users;")
        ctx.execute("TRUNCATE TABLE oauth_refresh_tokens;")
        ctx.execute("TRUNCATE TABLE oauth_tokens;")
        ctx.execute("TRUNCATE TABLE oauth_codes;")
        ctx.execute("TRUNCATE TABLE oauth_clients;")
        ctx.execute("TRUNCATE TABLE login_logs;")
        ctx.execute("TRUNCATE TABLE sessions;")
        ctx.execute("TRUNCATE TABLE users;")
        ctx.execute("SET FOREIGN_KEY_CHECKS = 1;")
    yield


@pytest.fixture
def client(monkeypatch):
    main._attempts.clear()
    with TestClient(main.app) as c:
        yield c


def login(client, monkeypatch, email, sub):
    monkeypatch.setattr(auth, "verify_google_token", fake(email, sub))
    return client.post("/api/auth/google", json={"credential": "x"}, headers=ORIGIN)


def test_invalid_token_rejected(client):
    r = client.post("/api/auth/google", json={"credential": "garbage"}, headers=ORIGIN)
    assert r.status_code == 401


def test_bad_origin_rejected(client):
    r = client.post("/api/auth/google", json={"credential": "x"}, headers={"Origin": "http://evil"})
    assert r.status_code == 403


def test_login_me_logout(client, monkeypatch):
    r = login(client, monkeypatch, "a@example.com", "1")
    assert r.status_code == 200
    assert "httponly" in r.headers["set-cookie"].lower()
    assert client.get("/api/me").json()["email"] == "a@example.com"
    client.post("/api/auth/logout", headers=ORIGIN)
    assert client.get("/api/me").status_code == 401


def test_admin_forbidden_and_columns(client, monkeypatch):
    login(client, monkeypatch, "u@example.com", "2")
    assert client.get("/api/admin/users").status_code == 403
    client.cookies.clear()
    login(client, monkeypatch, "admin@example.com", "3")
    rows = client.get("/api/admin/users").json()
    assert rows and all("email" in r and "name" in r for r in rows)


def test_no_raw_ip_or_token_in_db(client, monkeypatch):
    login(client, monkeypatch, "z@example.com", "4")
    token = client.cookies.get("session")
    with db.get_db() as ctx:
        logs = ctx.execute("SELECT ip_hmac FROM login_logs").fetchall()
        sessions = ctx.execute("SELECT token_hash FROM sessions").fetchall()
    assert len(sessions) > 0
    assert all(token != s["token_hash"] for s in sessions)
    assert all("testclient" != l["ip_hmac"] for l in logs)


def test_delete_account_cascades(client, monkeypatch):
    login(client, monkeypatch, "d@example.com", "5")
    assert client.delete("/api/me", headers=ORIGIN).status_code == 200
    with db.get_db() as ctx:
        u_count = ctx.execute("SELECT COUNT(*) AS cnt FROM users WHERE google_sub='5'").fetchone()["cnt"]
        orphan_logs = ctx.execute(
            "SELECT COUNT(*) AS cnt FROM login_logs WHERE user_id NOT IN (SELECT id FROM users)"
        ).fetchone()["cnt"]
    assert u_count == 0
    assert orphan_logs == 0
    assert client.get("/api/me").status_code == 401


def test_oauth_flow_confidential_client(client, monkeypatch):
    # 1. Admin creates client
    login(client, monkeypatch, "admin@example.com", "admin_1")
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "App 1", "redirect_uris": ["http://localhost:3000/callback"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    client_id = reg["client_id"]
    client_secret = reg["client_secret"]
    assert client_id and client_secret

    # 2. Get client info
    info = client.get(f"/api/oauth/client-info?client_id={client_id}").json()
    assert info["client_name"] == "App 1"
    assert "http://localhost:3000/callback" in info["redirect_uris"]

    # 3. User logs in & authorizes
    client.cookies.clear()
    login(client, monkeypatch, "user1@example.com", "u_100")
    auth_res = client.post(
        "/api/oauth/authorize",
        json={"client_id": client_id, "redirect_uri": "http://localhost:3000/callback"},
        headers=ORIGIN,
    )
    assert auth_res.status_code == 200
    code = auth_res.json()["code"]

    # 4. App 1 exchanges code for access token
    token_res = client.post(
        "/api/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "http://localhost:3000/callback",
        },
    )
    assert token_res.status_code == 200
    access_token = token_res.json()["access_token"]
    assert access_token

    # 5. App 1 fetches userinfo (must have role and status)
    userinfo_res = client.get(
        "/api/oauth/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert userinfo_res.status_code == 200
    u_data = userinfo_res.json()
    assert u_data["email"] == "user1@example.com"
    assert u_data["name"] == "user1"
    assert u_data["role"] == "member"
    assert u_data["status"] == "active"

    # 6. Reusing code is rejected
    reuse_res = client.post(
        "/api/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "http://localhost:3000/callback",
        },
    )
    assert reuse_res.status_code == 400


def test_oauth_flow_pkce_public_client(client, monkeypatch):
    # 1. Admin creates public client (no secret)
    login(client, monkeypatch, "admin@example.com", "admin_1")
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "SPA App", "redirect_uris": ["http://localhost:5000/callback"], "is_confidential": False},
        headers=ORIGIN,
    ).json()
    client_id = reg["client_id"]
    assert reg["client_secret"] is None

    # 2. Prepare PKCE verifier and challenge (S256)
    code_verifier = "a-high-entropy-random-string-used-as-code-verifier-1234567890"
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    # 3. User authorizes with PKCE challenge
    client.cookies.clear()
    login(client, monkeypatch, "pkce_user@example.com", "u_pkce")
    auth_res = client.post(
        "/api/oauth/authorize",
        json={
            "client_id": client_id,
            "redirect_uri": "http://localhost:5000/callback",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        headers=ORIGIN,
    )
    code = auth_res.json()["code"]

    # 4. Exchange code with wrong verifier fails
    bad_token_res = client.post(
        "/api/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": "http://localhost:5000/callback",
            "code_verifier": "wrong-verifier",
        },
    )
    assert bad_token_res.status_code == 400

    # 5. Exchange code with correct verifier succeeds
    good_token_res = client.post(
        "/api/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": "http://localhost:5000/callback",
            "code_verifier": code_verifier,
        },
    )
    assert good_token_res.status_code == 200
    token = good_token_res.json()["access_token"]

    # 6. Fetch user info
    user_res = client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {token}"})
    assert user_res.status_code == 200
    assert user_res.json()["email"] == "pkce_user@example.com"
    assert user_res.json()["role"] == "member"
    assert user_res.json()["status"] == "active"


def test_user_management_by_app(client, monkeypatch):
    # 1. Admin creates App
    login(client, monkeypatch, "admin@example.com", "admin_1")
    app = client.post(
        "/api/admin/clients",
        json={"client_name": "Portal App", "redirect_uris": ["http://localhost:4000/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    client_id = app["client_id"]
    client_secret = app["client_secret"]

    # 2. User authorizes app
    client.cookies.clear()
    login(client, monkeypatch, "target@example.com", "t_1")
    user_id = client.get("/api/me").json()["id"]
    code = client.post(
        "/api/oauth/authorize",
        json={"client_id": client_id, "redirect_uri": "http://localhost:4000/cb"},
        headers=ORIGIN,
    ).json()["code"]

    token = client.post(
        "/api/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "http://localhost:4000/cb",
        },
    ).json()["access_token"]

    # 3. Admin views users for this app
    client.cookies.clear()
    login(client, monkeypatch, "admin@example.com", "admin_1")
    app_users = client.get(f"/api/admin/clients/{client_id}/users").json()
    assert len(app_users) == 1
    assert app_users[0]["email"] == "target@example.com"
    assert app_users[0]["role"] == "member"
    assert app_users[0]["status"] == "active"

    # 4. Admin changes role to admin
    role_res = client.post(
        f"/api/admin/clients/{client_id}/users/{user_id}/role",
        json={"role": "admin"},
        headers=ORIGIN,
    )
    assert role_res.status_code == 200
    u_info = client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {token}"}).json()
    assert u_info["role"] == "admin"

    # 5. Admin revokes user access
    status_res = client.post(
        f"/api/admin/clients/{client_id}/users/{user_id}/status",
        json={"status": "revoked"},
        headers=ORIGIN,
    )
    assert status_res.status_code == 200

    # User's token is immediately revoked (401 or 403)
    revoked_userinfo = client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {token}"})
    assert revoked_userinfo.status_code in (401, 403)

    # Trying to authorize again is rejected with 403
    client.cookies.clear()
    login(client, monkeypatch, "target@example.com", "t_1")
    re_auth = client.post(
        "/api/oauth/authorize",
        json={"client_id": client_id, "redirect_uri": "http://localhost:4000/cb"},
        headers=ORIGIN,
    )
    assert re_auth.status_code == 403


def test_audit_logs_and_export(client, monkeypatch):
    # 1. Perform actions: Login admin, create client, login user, authorize
    login(client, monkeypatch, "admin@example.com", "admin_1")
    app = client.post(
        "/api/admin/clients",
        json={"client_name": "Audit App", "redirect_uris": ["http://localhost:6000/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()

    client.cookies.clear()
    login(client, monkeypatch, "audit_user@example.com", "aud_1")
    client.post(
        "/api/oauth/authorize",
        json={"client_id": app["client_id"], "redirect_uri": "http://localhost:6000/cb"},
        headers=ORIGIN,
    )

    # 2. Admin queries audit logs
    client.cookies.clear()
    login(client, monkeypatch, "admin@example.com", "admin_1")
    res = client.get("/api/admin/audit-logs").json()
    assert res["total"] >= 3
    event_types = [l["event_type"] for l in res["logs"]]
    assert "LOGIN" in event_types
    assert "CLIENT_CREATED" in event_types
    assert "OAUTH_AUTHORIZE" in event_types

    # 3. Filter by search query
    filtered = client.get("/api/admin/audit-logs?q=audit_user").json()
    assert filtered["total"] >= 1
    assert any(l["user_email"] == "audit_user@example.com" for l in filtered["logs"])

    # 4. Export CSV
    csv_res = client.get("/api/admin/audit-logs/export?format=csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert csv_res.content.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM
    assert b"Event Type" in csv_res.content
    assert b"audit_user@example.com" in csv_res.content

    # 5. Export JSON
    json_res = client.get("/api/admin/audit-logs/export?format=json")
    assert json_res.status_code == 200
    assert "application/json" in json_res.headers["content-type"]
    json_data = json_res.json()
    assert isinstance(json_data, list) and len(json_data) >= 3


def test_security_headers_present(client):
    r = client.get("/api/oauth/client-info?client_id=nonexistent")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in r.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "")


def test_redirect_uri_validation_on_client_creation(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")

    # JavaScript URI rejected
    r1 = client.post(
        "/api/admin/clients",
        json={"client_name": "Bad App 1", "redirect_uris": ["javascript:alert(1)"], "is_confidential": True},
        headers=ORIGIN,
    )
    assert r1.status_code == 400

    # Non-localhost HTTP rejected
    r2 = client.post(
        "/api/admin/clients",
        json={"client_name": "Bad App 2", "redirect_uris": ["http://evil.com/callback"], "is_confidential": True},
        headers=ORIGIN,
    )
    assert r2.status_code == 400

    # Fragment identifier rejected
    r3 = client.post(
        "/api/admin/clients",
        json={"client_name": "Bad App 3", "redirect_uris": ["https://good.com/cb#fragment"], "is_confidential": True},
        headers=ORIGIN,
    )
    assert r3.status_code == 400

    # Valid HTTPS allowed
    r4 = client.post(
        "/api/admin/clients",
        json={"client_name": "Good App", "redirect_uris": ["https://good.com/cb", "http://localhost:8080/cb"], "is_confidential": True},
        headers=ORIGIN,
    )
    assert r4.status_code == 200


def test_public_client_pkce_enforcement(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "Public App", "redirect_uris": ["http://localhost:3000/cb"], "is_confidential": False},
        headers=ORIGIN,
    ).json()
    client_id = reg["client_id"]

    client.cookies.clear()
    login(client, monkeypatch, "user@example.com", "u1")

    # Authorizing without code_challenge must be rejected for public client
    no_pkce = client.post(
        "/api/oauth/authorize",
        json={"client_id": client_id, "redirect_uri": "http://localhost:3000/cb"},
        headers=ORIGIN,
    )
    assert no_pkce.status_code == 400
    assert "code_challenge required" in no_pkce.json()["detail"]

    # Plain method must be rejected under OAuth 2.1 / RFC 9700
    plain_pkce = client.post(
        "/api/oauth/authorize",
        json={
            "client_id": client_id,
            "redirect_uri": "http://localhost:3000/cb",
            "code_challenge": "plainchallenge" * 3,
            "code_challenge_method": "plain",
        },
        headers=ORIGIN,
    )
    assert plain_pkce.status_code == 400
    assert "unsupported code_challenge_method" in plain_pkce.json()["detail"]


def test_pkce_rfc7636_verifier_format():
    # Valid verifier: 43 to 128 chars
    valid_verifier = "A" * 43
    digest = hashlib.sha256(valid_verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    assert auth.verify_pkce(valid_verifier, challenge, "S256") is True

    # Plain method rejected
    assert auth.verify_pkce(valid_verifier, valid_verifier, "plain") is False

    # Too short (< 43 chars)
    short_verifier = "A" * 42
    short_digest = hashlib.sha256(short_verifier.encode("ascii")).digest()
    short_challenge = base64.urlsafe_b64encode(short_digest).decode("ascii").rstrip("=")
    assert auth.verify_pkce(short_verifier, short_challenge, "S256") is False

    # Invalid characters (contains space or special punctuation)
    invalid_chars_verifier = ("A" * 42) + "!"
    inv_digest = hashlib.sha256(invalid_chars_verifier.encode("ascii")).digest()
    inv_challenge = base64.urlsafe_b64encode(inv_digest).decode("ascii").rstrip("=")
    assert auth.verify_pkce(invalid_chars_verifier, inv_challenge, "S256") is False


def test_delete_client_purges_tokens_and_codes(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "Ephemeral App", "redirect_uris": ["http://localhost:9000/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    c_id = reg["client_id"]
    c_sec = reg["client_secret"]

    client.cookies.clear()
    login(client, monkeypatch, "u_token@example.com", "u_t")
    code = client.post(
        "/api/oauth/authorize",
        json={"client_id": c_id, "redirect_uri": "http://localhost:9000/cb"},
        headers=ORIGIN,
    ).json()["code"]

    tok_res = client.post(
        "/api/oauth/token",
        json={"grant_type": "authorization_code", "code": code, "client_id": c_id, "client_secret": c_sec, "redirect_uri": "http://localhost:9000/cb"},
    ).json()
    token = tok_res["access_token"]

    # Verify token works
    assert client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    # Delete client as admin
    client.cookies.clear()
    login(client, monkeypatch, "admin@example.com", "admin_1")
    del_res = client.delete(f"/api/admin/clients/{c_id}", headers=ORIGIN)
    assert del_res.status_code == 200

    # Token must now be purged and fail
    assert client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    # Verify DB tables are clean of this client
    with db.get_db() as ctx:
        assert ctx.execute("SELECT COUNT(*) AS c FROM oauth_tokens WHERE client_id = %s", (c_id,)).fetchone()["c"] == 0
        assert ctx.execute("SELECT COUNT(*) AS c FROM oauth_codes WHERE client_id = %s", (c_id,)).fetchone()["c"] == 0
        assert ctx.execute("SELECT COUNT(*) AS c FROM app_users WHERE client_id = %s", (c_id,)).fetchone()["c"] == 0


def test_csv_formula_injection_defense(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")
    # Create client with formula injection payload in client_name
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "=1+1", "redirect_uris": ["https://calc.app/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()

    csv_res = client.get("/api/admin/audit-logs/export?format=csv")
    assert csv_res.status_code == 200
    # The cell must be prefixed with single quote (') so spreadsheet engines won't execute formulas
    assert b"'=1+1" in csv_res.content


def test_oauth_token_rate_limiting(client):
    main._attempts.clear()
    for i in range(30):
        r = client.post(
            "/api/oauth/token",
            json={"grant_type": "authorization_code", "code": "fake", "client_id": "c", "redirect_uri": "http://localhost:3000/cb"},
        )
        assert r.status_code != 429
    # The 31st attempt should be rate limited
    r_block = client.post(
        "/api/oauth/token",
        json={"grant_type": "authorization_code", "code": "fake", "client_id": "c", "redirect_uri": "http://localhost:3000/cb"},
    )
    assert r_block.status_code == 429
    assert "too many attempts" in r_block.json()["detail"]


def test_admin_update_nonexistent_user_returns_404(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")
    # Update role for user that does not belong to client
    r1 = client.post(
        "/api/admin/clients/wyk_fake_client/users/9999/role",
        json={"role": "admin"},
        headers=ORIGIN,
    )
    assert r1.status_code == 404

    # Update status for user that does not belong to client
    r2 = client.post(
        "/api/admin/clients/wyk_fake_client/users/9999/status",
        json={"status": "revoked"},
        headers=ORIGIN,
    )
    assert r2.status_code == 404


def test_production_config_validation(monkeypatch):
    monkeypatch.setattr(config, "ENVIRONMENT", "production")
    monkeypatch.setattr(config, "IP_HMAC_SECRET", "dev-insecure-change-me")
    with pytest.raises(ValueError, match="IP_HMAC_SECRET must be set"):
        config.validate_production_config()

    monkeypatch.setattr(config, "IP_HMAC_SECRET", "strong-secret-key-1234567890")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "")
    with pytest.raises(ValueError, match="GOOGLE_CLIENT_ID must be set"):
        config.validate_production_config()

    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "google-client-id-123")
    monkeypatch.setattr(config, "COOKIE_SECURE", False)
    with pytest.raises(ValueError, match="COOKIE_SECURE must be true"):
        config.validate_production_config()

    monkeypatch.setattr(config, "COOKIE_SECURE", True)
    config.validate_production_config()


def test_audit_log_escape_like():
    assert main.escape_like("100%_pure") == r"100\%\_pure"
    assert main.escape_like(r"C:\test") == r"C:\\test"


def test_trusted_proxies_ip_handling(client, monkeypatch):
    main._attempts.clear()
    # 1. By default, TRUSTED_PROXIES is empty, so X-Forwarded-For should be ignored
    monkeypatch.setattr(config, "TRUSTED_PROXIES", set())
    # Send request with spoofed IP
    r1 = client.get("/api/oauth/client-info?client_id=none", headers={"X-Forwarded-For": "1.2.3.4"})
    assert r1.status_code == 404

    # 2. When testclient IP is trusted, X-Forwarded-For is used
    monkeypatch.setattr(config, "TRUSTED_PROXIES", {"testclient"})
    # Verify rate limit key uses forwarded IP
    main._attempts.clear()
    for _ in range(10):
        client.post("/api/auth/google", json={"credential": "x"}, headers={**ORIGIN, "X-Forwarded-For": "5.6.7.8"})
    # 11th request from same forwarded IP should be rate limited
    r_limit = client.post("/api/auth/google", json={"credential": "x"}, headers={**ORIGIN, "X-Forwarded-For": "5.6.7.8"})
    assert r_limit.status_code == 429
    # Request from different forwarded IP should succeed past rate limit
    r_diff = client.post("/api/auth/google", json={"credential": "x"}, headers={**ORIGIN, "X-Forwarded-For": "9.9.9.9"})
    assert r_diff.status_code == 401  # Passes rate limit, fails on invalid token


def test_client_patch_rotate_and_disable(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")

    # Create client
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "Original Name", "redirect_uris": ["https://app.com/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    c_id = reg["client_id"]
    old_secret = reg["client_secret"]

    # 1. PATCH client
    patch_res = client.patch(
        f"/api/admin/clients/{c_id}",
        json={"client_name": "Updated Name", "redirect_uris": ["https://app.com/new-cb"], "access_mode": "invite_only"},
        headers=ORIGIN,
    )
    assert patch_res.status_code == 200

    info = client.get(f"/api/oauth/client-info?client_id={c_id}").json()
    assert info["client_name"] == "Updated Name"
    assert info["redirect_uris"] == ["https://app.com/new-cb"]
    assert info["access_mode"] == "invite_only"

    # 2. Rotate secret
    rot_res = client.post(f"/api/admin/clients/{c_id}/rotate-secret", headers=ORIGIN)
    assert rot_res.status_code == 200
    new_secret = rot_res.json()["client_secret"]
    assert new_secret != old_secret

    # 3. Disable client
    dis_res = client.post(f"/api/admin/clients/{c_id}/status", json={"is_active": False}, headers=ORIGIN)
    assert dis_res.status_code == 200
    assert dis_res.json()["is_active"] is False

    # Calling client-info returns 403 client_disabled
    assert client.get(f"/api/oauth/client-info?client_id={c_id}").status_code == 403


def test_refresh_token_lifecycle_and_reuse_detection(client, monkeypatch):
    # Admin creates client
    login(client, monkeypatch, "admin@example.com", "admin_1")
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "Token App", "redirect_uris": ["https://token.app/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    c_id = reg["client_id"]
    c_sec = reg["client_secret"]

    # User authorizes
    client.cookies.clear()
    login(client, monkeypatch, "token_user@example.com", "tok_u")
    code = client.post(
        "/api/oauth/authorize",
        json={"client_id": c_id, "redirect_uri": "https://token.app/cb"},
        headers=ORIGIN,
    ).json()["code"]

    # Exchange code for access_token AND refresh_token
    tok_res = client.post(
        "/api/oauth/token",
        json={"grant_type": "authorization_code", "code": code, "client_id": c_id, "client_secret": c_sec, "redirect_uri": "https://token.app/cb"},
    ).json()
    access_token_1 = tok_res["access_token"]
    refresh_token_1 = tok_res["refresh_token"]
    assert access_token_1 and refresh_token_1

    # Call userinfo
    assert client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {access_token_1}"}).status_code == 200

    # 1. Use refresh_token to get new token pair (rotation)
    ref_res = client.post(
        "/api/oauth/token",
        json={"grant_type": "refresh_token", "refresh_token": refresh_token_1, "client_id": c_id, "client_secret": c_sec},
    )
    assert ref_res.status_code == 200
    access_token_2 = ref_res.json()["access_token"]
    refresh_token_2 = ref_res.json()["refresh_token"]
    assert access_token_2 != access_token_1
    assert refresh_token_2 != refresh_token_1

    # 2. Token reuse attack: using refresh_token_1 again should fail and trigger revocation!
    reuse_res = client.post(
        "/api/oauth/token",
        json={"grant_type": "refresh_token", "refresh_token": refresh_token_1, "client_id": c_id, "client_secret": c_sec},
    )
    assert reuse_res.status_code == 400
    assert "reuse detected" in reuse_res.json()["detail"]

    # Now even access_token_2 should be revoked!
    assert client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {access_token_2}"}).status_code == 401

    # 3. Test RFC 7009 revoke endpoint
    # Obtain a fresh token pair
    code2 = client.post(
        "/api/oauth/authorize",
        json={"client_id": c_id, "redirect_uri": "https://token.app/cb"},
        headers=ORIGIN,
    ).json()["code"]
    fresh_tok = client.post(
        "/api/oauth/token",
        json={"grant_type": "authorization_code", "code": code2, "client_id": c_id, "client_secret": c_sec, "redirect_uri": "https://token.app/cb"},
    ).json()
    fresh_access = fresh_tok["access_token"]

    rev_res = client.post(
        "/api/oauth/revoke",
        json={"token": fresh_access, "client_id": c_id, "client_secret": c_sec},
    )
    assert rev_res.status_code == 200
    assert client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {fresh_access}"}).status_code == 401


def test_per_app_invite_only_access(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")
    app = client.post(
        "/api/admin/clients",
        json={"client_name": "VIP App", "redirect_uris": ["https://vip.app/cb"], "access_mode": "invite_only"},
        headers=ORIGIN,
    ).json()
    c_id = app["client_id"]

    # Uninvited user tries to authorize -> 403 access_denied
    client.cookies.clear()
    login(client, monkeypatch, "stranger@example.com", "stranger_1")
    uninv_res = client.post(
        "/api/oauth/authorize",
        json={"client_id": c_id, "redirect_uri": "https://vip.app/cb"},
        headers=ORIGIN,
    )
    assert uninv_res.status_code == 403
    assert "invite-only" in uninv_res.json()["detail"]

    # Admin invites the user as admin role
    client.cookies.clear()
    login(client, monkeypatch, "admin@example.com", "admin_1")
    inv_res = client.post(
        f"/api/admin/clients/{c_id}/invites",
        json={"email": "stranger@example.com", "role": "admin"},
        headers=ORIGIN,
    )
    assert inv_res.status_code == 200

    # User authorizes successfully now
    client.cookies.clear()
    login(client, monkeypatch, "stranger@example.com", "stranger_1")
    auth_res = client.post(
        "/api/oauth/authorize",
        json={"client_id": c_id, "redirect_uri": "https://vip.app/cb"},
        headers=ORIGIN,
    )
    assert auth_res.status_code == 200

    # Check that app_users has the invited role ("admin")
    with db.get_db() as ctx:
        au = ctx.execute("SELECT role FROM app_users WHERE client_id = %s", (c_id,)).fetchone()
        assert au["role"] == "admin"


def test_user_details_force_logout_and_suspend(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")
    # Login a regular user
    client.cookies.clear()
    login(client, monkeypatch, "regular@example.com", "reg_1")
    me = client.get("/api/me").json()
    reg_id = me["id"]

    # Admin inspects user detail
    client.cookies.clear()
    login(client, monkeypatch, "admin@example.com", "admin_1")
    det_res = client.get(f"/api/admin/users/{reg_id}")
    assert det_res.status_code == 200
    assert det_res.json()["user"]["email"] == "regular@example.com"
    assert det_res.json()["active_sessions"] >= 1

    # Force logout
    fl_res = client.post(f"/api/admin/users/{reg_id}/force-logout", headers=ORIGIN)
    assert fl_res.status_code == 200

    # User's session is gone
    client.cookies.clear()
    # Check that cookie session fails
    assert client.get("/api/me").status_code == 401

    # Admin suspends user
    login(client, monkeypatch, "admin@example.com", "admin_1")
    susp_res = client.post(f"/api/admin/users/{reg_id}/suspend", headers=ORIGIN)
    assert susp_res.status_code == 200

    # Suspended user cannot log in with Google
    client.cookies.clear()
    login_attempt = login(client, monkeypatch, "regular@example.com", "reg_1")
    assert login_attempt.status_code == 403
    assert "suspended" in login_attempt.json()["detail"]

    # Admin unsuspends user
    login(client, monkeypatch, "admin@example.com", "admin_1")
    unsusp_res = client.post(f"/api/admin/users/{reg_id}/unsuspend", headers=ORIGIN)
    assert unsusp_res.status_code == 200

    # User can now log in
    client.cookies.clear()
    login_ok = login(client, monkeypatch, "regular@example.com", "reg_1")
    assert login_ok.status_code == 200


def test_admin_management_in_db(client, monkeypatch):
    # Super admin creates regular user
    login(client, monkeypatch, "regular2@example.com", "reg_2")
    user_id = client.get("/api/me").json()["id"]

    # Regular user cannot access /api/admin/users
    assert client.get("/api/admin/users").status_code == 403

    # Super admin grants admin to regular2
    client.cookies.clear()
    login(client, monkeypatch, "admin@example.com", "admin_1")
    grant_res = client.post(f"/api/admin/users/{user_id}/admin", json={"is_admin": True}, headers=ORIGIN)
    assert grant_res.status_code == 200

    # Now regular2 can access /api/admin/users
    client.cookies.clear()
    login(client, monkeypatch, "regular2@example.com", "reg_2")
    assert client.get("/api/admin/users").status_code == 200

    # But regular2 (non-super admin) cannot grant admin to others
    cannot_grant = client.post(f"/api/admin/users/{user_id}/admin", json={"is_admin": False}, headers=ORIGIN)
    assert cannot_grant.status_code == 403

    # Cannot suspend super admin
    client.cookies.clear()
    login(client, monkeypatch, "admin@example.com", "admin_1")
    admin_id = client.get("/api/me").json()["id"]
    cant_susp = client.post(f"/api/admin/users/{admin_id}/suspend", headers=ORIGIN)
    assert cant_susp.status_code == 400


def test_home_dashboard_stats_and_user_disconnect(client, monkeypatch):
    # 1. Setup client and user
    login(client, monkeypatch, "admin@example.com", "admin_1")
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "Dash App", "redirect_uris": ["https://dash.app/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    c_id = reg["client_id"]
    c_sec = reg["client_secret"]

    # 2. Regular user login & authorize app
    client.cookies.clear()
    login(client, monkeypatch, "dash_user@example.com", "dash_u")
    auth_res = client.post(
        "/api/oauth/authorize",
        json={"client_id": c_id, "redirect_uri": "https://dash.app/cb"},
        headers=ORIGIN,
    )
    assert auth_res.status_code == 200
    code = auth_res.json()["code"]

    # Exchange code for tokens
    tok_res = client.post(
        "/api/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": c_id,
            "client_secret": c_sec,
            "code": code,
            "redirect_uri": "https://dash.app/cb",
        },
    )
    assert tok_res.status_code == 200
    at = tok_res.json()["access_token"]

    # 3. Test user dashboard
    dash = client.get("/api/me/dashboard").json()
    assert dash["profile"]["email"] == "dash_user@example.com"
    assert len(dash["apps"]) == 1
    assert dash["apps"][0]["client_id"] == c_id
    assert dash["apps"][0]["client_name"] == "Dash App"
    assert len(dash["recent_activity"]) >= 1

    # Non-admin cannot access admin dashboard stats
    assert client.get("/api/admin/dashboard-stats").status_code == 403

    # 4. Admin dashboard stats
    client.cookies.clear()
    login(client, monkeypatch, "admin@example.com", "admin_1")
    stats = client.get("/api/admin/dashboard-stats").json()
    assert stats["total_apps"] >= 1
    assert stats["active_apps"] >= 1
    assert stats["total_users"] >= 2
    assert stats["active_sessions"] >= 1
    assert stats["active_tokens"] >= 1
    assert len(stats["recent_logs"]) >= 1

    # 5. User self-disconnects app
    client.cookies.clear()
    login(client, monkeypatch, "dash_user@example.com", "dash_u")
    del_res = client.delete(f"/api/me/apps/{c_id}", headers=ORIGIN)
    assert del_res.status_code == 200

    # Token should no longer work
    u_info = client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {at}"})
    assert u_info.status_code == 401

    # App should no longer be listed in user dashboard
    dash_after = client.get("/api/me/dashboard").json()
    assert len(dash_after["apps"]) == 0
    # USER_APP_DISCONNECTED is logged in recent activity
    event_types = [a["event_type"] for a in dash_after["recent_activity"]]
    assert "USER_APP_DISCONNECTED" in event_types


def test_authorization_code_reuse_revokes_all_tokens(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "Reuse Test App", "redirect_uris": ["https://reuse.app/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    c_id = reg["client_id"]
    c_sec = reg["client_secret"]

    client.cookies.clear()
    login(client, monkeypatch, "reuse_user@example.com", "reuse_u")

    # Authorize to obtain code
    code = client.post(
        "/api/oauth/authorize",
        json={"client_id": c_id, "redirect_uri": "https://reuse.app/cb"},
        headers=ORIGIN,
    ).json()["code"]

    # 1. Legitimate exchange
    tok_res = client.post(
        "/api/oauth/token",
        json={"grant_type": "authorization_code", "code": code, "client_id": c_id, "client_secret": c_sec, "redirect_uri": "https://reuse.app/cb"},
    )
    assert tok_res.status_code == 200
    access_token = tok_res.json()["access_token"]
    refresh_token = tok_res.json()["refresh_token"]

    # Verify access token works
    assert client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {access_token}"}).status_code == 200

    # 2. Attacker replays the same authorization code
    replay_res = client.post(
        "/api/oauth/token",
        json={"grant_type": "authorization_code", "code": code, "client_id": c_id, "client_secret": c_sec, "redirect_uri": "https://reuse.app/cb"},
    )
    assert replay_res.status_code == 400
    assert "code already used" in replay_res.json()["detail"]

    # 3. According to RFC 6749 4.1.2, previously issued tokens must be revoked
    assert client.get("/api/oauth/userinfo", headers={"Authorization": f"Bearer {access_token}"}).status_code == 401

    # Refresh token should also be revoked
    rf_attempt = client.post(
        "/api/oauth/token",
        json={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": c_id, "client_secret": c_sec},
    )
    assert rf_attempt.status_code == 400

    # Audit log must contain AUTHORIZATION_CODE_REUSE_DETECTED
    with db.get_db() as conn:
        audit = conn.execute(
            "SELECT event_type FROM audit_logs WHERE client_id = %s AND event_type = 'AUTHORIZATION_CODE_REUSE_DETECTED'",
            (c_id,),
        ).fetchone()
        assert audit is not None


def test_rate_limiter_stale_bucket_cleanup(client):
    main._attempts.clear()
    import time
    from collections import deque

    # Populate 10,050 stale keys
    t_old = time.monotonic() - 7200  # 2 hours ago
    for i in range(10050):
        main._attempts[f"stale_key_{i}"] = deque([t_old])

    assert len(main._attempts) == 10050

    # Trigger an endpoint that invokes rate_limit
    client.post("/api/auth/google", json={"credential": "x"}, headers=ORIGIN)

    # Stale keys must have been pruned
    assert len(main._attempts) < 10000


def test_attack_protection_defaults_and_patch_update(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")

    # 1. Create client, verify default attack protection
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "Attack Test App", "redirect_uris": ["https://app.com/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    c_id = reg["client_id"]
    cfg = reg["attack_protection"]
    assert cfg["bot_detection"] is False
    assert cfg["suspicious_ip_throttling"] is True
    assert cfg["brute_force_protection"] is True
    assert cfg["suspicious_account_shield"] is False

    # 2. Patch attack protection toggles
    patch_res = client.patch(
        f"/api/admin/clients/{c_id}/attack-protection",
        json={"bot_detection": True, "suspicious_ip_throttling": False},
        headers=ORIGIN,
    )
    assert patch_res.status_code == 200
    updated_cfg = patch_res.json()["attack_protection"]
    assert updated_cfg["bot_detection"] is True
    assert updated_cfg["suspicious_ip_throttling"] is False

    # 3. Verify in client list
    cls = client.get("/api/admin/clients").json()
    matched = next(c for c in cls if c["client_id"] == c_id)
    assert matched["attack_protection"]["bot_detection"] is True

    # 4. Verify audit log ATTACK_PROTECTION_UPDATED
    with db.get_db() as conn:
        audit = conn.execute(
            "SELECT event_type, details FROM audit_logs WHERE client_id = %s AND event_type = 'ATTACK_PROTECTION_UPDATED'",
            (c_id,),
        ).fetchone()
        assert audit is not None
        assert "bot_detection" in audit["details"]


def test_attack_protection_brute_force_enforcement(client, monkeypatch):
    main._failed_exchanges.clear()
    main._blocked_entities.clear()

    login(client, monkeypatch, "admin@example.com", "admin_1")
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "BF Shield App", "redirect_uris": ["https://bf.app/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    c_id = reg["client_id"]
    c_sec = reg["client_secret"]

    # Trigger 5 failed token exchanges
    for i in range(5):
        res = client.post(
            "/api/oauth/token",
            json={"grant_type": "authorization_code", "code": f"bad_code_{i}", "client_id": c_id, "client_secret": c_sec, "redirect_uri": "https://bf.app/cb"},
        )
        assert res.status_code in (400, 429)

    # 6th attempt must be blocked by Brute-force Protection (429)
    blocked_res = client.post(
        "/api/oauth/token",
        json={"grant_type": "authorization_code", "code": "another_bad_code", "client_id": c_id, "client_secret": c_sec, "redirect_uri": "https://bf.app/cb"},
    )
    assert blocked_res.status_code == 429
    assert "brute_force_protection" in blocked_res.json()["detail"]

    # Verify audit log contains ATTACK_BLOCKED
    with db.get_db() as conn:
        audit = conn.execute(
            "SELECT event_type, details FROM audit_logs WHERE client_id = %s AND event_type = 'ATTACK_BLOCKED'",
            (c_id,),
        ).fetchone()
        assert audit is not None
        assert "brute_force_protection" in audit["details"]


def test_attack_protection_bot_detection_enforcement(client, monkeypatch):
    login(client, monkeypatch, "admin@example.com", "admin_1")
    reg = client.post(
        "/api/admin/clients",
        json={"client_name": "Bot Shield App", "redirect_uris": ["https://bot.app/cb"], "is_confidential": True},
        headers=ORIGIN,
    ).json()
    c_id = reg["client_id"]

    # Enable Bot Detection toggle
    client.patch(
        f"/api/admin/clients/{c_id}/attack-protection",
        json={"bot_detection": True},
        headers=ORIGIN,
    )

    client.cookies.clear()
    login(client, monkeypatch, "user_bot@example.com", "u_b")

    # Authorize without bot_token must fail with 400
    fail_res = client.post(
        "/api/oauth/authorize",
        json={"client_id": c_id, "redirect_uri": "https://bot.app/cb"},
        headers=ORIGIN,
    )
    assert fail_res.status_code == 400
    assert "bot_detection: verification challenge required" in fail_res.json()["detail"]

    # Authorize with bot_token succeeds
    ok_res = client.post(
        "/api/oauth/authorize",
        json={"client_id": c_id, "redirect_uri": "https://bot.app/cb", "bot_token": "human-verified"},
        headers=ORIGIN,
    )
    assert ok_res.status_code == 200
    assert "code" in ok_res.json()
