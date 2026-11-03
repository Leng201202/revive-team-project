import re

import pytest

from app import create_app


@pytest.fixture()
def app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "notevault-test.db"),
            "JWT_SECRET": "test-only-secret-that-is-longer-than-32-characters",
            "COOKIE_SECURE": False,
            "TEAM_ID": "REVIVE-TEST",
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def csrf(client):
    def get_token():
        response = client.get("/")
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        assert match is not None
        return match.group(1).decode()

    return get_token


@pytest.fixture()
def login(client, csrf):
    def sign_in(username="alice", password="alicepw"):
        return client.post(
            "/login",
            data={"username": username, "password": password, "csrf_token": csrf()},
        )

    return sign_in
