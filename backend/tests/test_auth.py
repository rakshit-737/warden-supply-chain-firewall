from tests.conftest import auth


def test_login_success_and_me(client, admin_token):
    resp = client.get("/api/v1/auth/me", headers=auth(admin_token))
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


def test_login_wrong_password_rejected(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@warden.io", "password": "wrong-password"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


def test_protected_route_requires_token(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_rbac_viewer_cannot_create_policy(client, admin_token):
    # Create a viewer, log in as them, attempt an admin-only action.
    client.post(
        "/api/v1/auth/register",
        headers=auth(admin_token),
        json={"email": "viewer@warden.io", "password": "ViewerPassw0rd!2026", "role": "viewer"},
    )
    tok = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@warden.io", "password": "ViewerPassw0rd!2026"},
    ).json()["access_token"]

    resp = client.post(
        "/api/v1/policies",
        headers=auth(tok),
        json={"name": "x", "warn_threshold": 10, "block_threshold": 20},
    )
    assert resp.status_code == 403


def test_refresh_rotation(client):
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@warden.io", "password": "AdminPassw0rd!2026"},
    )
    assert "warden_refresh" in login.cookies
    refreshed = client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"]
