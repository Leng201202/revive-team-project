from datetime import datetime, timedelta, timezone
import hashlib
import logging

import jwt
import pytest
from werkzeug.security import check_password_hash

from app import (
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    create_app,
    get_db,
    initialize_database,
)


def test_f01_export_command_injection_is_rejected(client, login):
    assert login().status_code == 302
    attack = client.get("/export", query_string={"fmt": "txt;id"})
    assert attack.status_code == 400
    assert b"uid=" not in attack.data
    legitimate = client.get("/export", query_string={"fmt": "txt"})
    assert legitimate.status_code == 200
    assert legitimate.mimetype == "text/plain"


def test_f02_login_sql_injection_fails(client, csrf):
    response = client.post(
        "/login",
        data={"username": "alice'--", "password": "anything", "csrf_token": csrf()},
    )
    assert response.status_code == 401
    assert client.get("/api/notes/1").status_code == 401


def test_f03_search_union_injection_fails(client, login):
    assert login().status_code == 302
    response = client.get(
        "/search", query_string={"q": "' UNION SELECT id,username,password_hash FROM users--"}
    )
    assert response.status_code == 200
    assert b"admin" not in response.data
    assert b"password" not in response.data


def test_f04_registration_ignores_attacker_role(client, csrf, login):
    response = client.post(
        "/register",
        data={
            "username": "mallory",
            "password": "correct-horse-battery",
            "role": "admin",
            "csrf_token": csrf(),
        },
    )
    assert response.status_code == 302
    assert login("mallory", "correct-horse-battery").status_code == 302
    assert client.get("/admin").status_code == 403


def test_f05_duplicate_admin_registration_is_blocked(client, csrf, login):
    response = client.post(
        "/register",
        data={"username": "admin", "password": "attacker-password", "csrf_token": csrf()},
    )
    assert response.status_code == 409
    assert login("admin", "admin123").status_code == 302
    assert client.get("/admin").status_code == 200


def test_f06_forged_jwt_with_old_secret_is_rejected(client):
    now = datetime.now(timezone.utc)
    with pytest.warns(jwt.InsecureKeyLengthWarning):
        forged = jwt.encode(
            {
                "sub": "admin",
                "iat": now,
                "exp": now + timedelta(minutes=15),
                "jti": "forged",
                "aud": JWT_AUDIENCE,
                "iss": JWT_ISSUER,
            },
            "notevault-dev-secret",
            algorithm=JWT_ALGORITHM,
        )
    client.set_cookie("session", forged)
    assert client.get("/admin").status_code == 401


def test_f07_idor_returns_not_found_for_another_users_note(client, login):
    assert login().status_code == 302
    assert client.get("/api/notes/1").status_code == 200
    assert client.get("/api/notes/2").status_code == 404


def test_f08_admin_response_excludes_password_hash(client, login):
    assert login("admin", "admin123").status_code == 302
    response = client.get("/admin")
    assert response.status_code == 200
    assert all("password" not in user and "password_hash" not in user for user in response.json)


def test_f09_stored_xss_is_escaped(client, csrf, login):
    assert login().status_code == 302
    payload = "<script>alert(document.cookie)</script>"
    response = client.post(
        "/notes",
        data={"title": "xss", "body": payload, "csrf_token": csrf()},
    )
    assert response.status_code == 302
    page = client.get("/")
    assert payload.encode() not in page.data
    assert b"&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in page.data


def test_f10_session_has_flags_claims_and_logout_revokes(client, csrf, login, app):
    response = login()
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    token = client.get_cookie("session").value
    claims = jwt.decode(
        token,
        app.config["JWT_SECRET"],
        algorithms=[JWT_ALGORITHM],
        audience=JWT_AUDIENCE,
        issuer=JWT_ISSUER,
    )
    assert {"sub", "iat", "exp", "jti", "aud", "iss"} <= claims.keys()
    assert claims["exp"] - claims["iat"] == 900
    assert client.post("/logout", data={"csrf_token": csrf()}).status_code == 302
    client.set_cookie("session", token)
    assert client.get("/api/notes/1").status_code == 401


def test_f10_production_cookie_uses_secure_flag(tmp_path):
    secure_app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "secure-cookie.db"),
            "JWT_SECRET": "a-production-like-secret-with-at-least-32-characters",
            "COOKIE_SECURE": True,
        }
    )
    client = secure_app.test_client()
    first = client.get("/")
    token = client.get_cookie("csrf_token").value
    response = client.post(
        "/login",
        data={"username": "alice", "password": "alicepw", "csrf_token": token},
    )
    assert "Secure" in first.headers.get("Set-Cookie", "")
    assert "Secure" in response.headers.get("Set-Cookie", "")


def test_f11_login_rate_limit_returns_429(client, csrf):
    token = csrf()
    for _ in range(5):
        response = client.post(
            "/login",
            data={"username": "alice", "password": "wrong", "csrf_token": token},
        )
        assert response.status_code == 401
    limited = client.post(
        "/login",
        data={"username": "alice", "password": "wrong", "csrf_token": token},
    )
    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "60"


def test_f12_csrf_is_required_and_origin_checked(client, csrf, login):
    assert login().status_code == 302
    assert client.post("/notes", data={"title": "a", "body": "b"}).status_code == 403
    response = client.post(
        "/notes",
        data={"title": "a", "body": "b", "csrf_token": csrf()},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


def test_f13_debug_disabled_and_errors_are_generic(app):
    assert app.debug is False
    assert app.config["PROPAGATE_EXCEPTIONS"] is not True


def test_f14_dependencies_are_upgraded():
    requirements = open("requirements.txt", encoding="utf-8").read()
    for old_version in ("Flask==2.0.1", "Werkzeug==2.0.1", "PyJWT==1.7.1"):
        assert old_version not in requirements


def test_f15_dockerfile_is_hardened():
    dockerfile = open("Dockerfile", encoding="utf-8").read()
    assert "@sha256:" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "ENV APP_SECRET" not in dockerfile
    assert "COPY . ." not in dockerfile


def test_f16_security_events_are_logged(client, csrf, caplog):
    caplog.set_level(logging.WARNING)
    client.post(
        "/login",
        data={"username": "alice", "password": "wrong", "csrf_token": csrf()},
    )
    assert "security_event=login_failed" in caplog.text
    assert "actor='alice'" in caplog.text


def test_f17_database_initialization_preserves_existing_data(app):
    with app.app_context():
        connection = get_db()
        connection.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
            ("persistent", "not-used-in-this-test"),
        )
        connection.commit()
    initialize_database(app)
    with app.app_context():
        assert get_db().execute(
            "SELECT 1 FROM users WHERE username = 'persistent'"
        ).fetchone()


def test_weak_md5_password_storage_is_replaced(app):
    with app.app_context():
        stored = get_db().execute(
            "SELECT password_hash FROM users WHERE username = 'alice'"
        ).fetchone()["password_hash"]
    assert stored != hashlib.md5(b"alicepw").hexdigest()
    assert check_password_hash(stored, "alicepw")


def test_security_headers_are_present(client):
    response = client.get("/")
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")


def test_short_or_missing_app_secret_fails_fast(tmp_path):
    with pytest.raises(RuntimeError, match="at least 32"):
        create_app({"DATABASE": str(tmp_path / "unused.db"), "JWT_SECRET": "short"})
