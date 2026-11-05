"""API tests – run with:  pytest -v
The 14 mandatory scenarios of the task are marked MANDATORY 1..14."""
import base64
import hashlib
import hmac
import json
import os
import time
from datetime import timedelta

import jwt
import pytest

from app.core.security import create_access_token
from app.database.connection import SessionLocal
from app.models.user_model import User
from tests.conftest import NEW_PASSWORD, PASSWORD, register_payload, set_active

REGISTER, LOGIN, ME = "/api/auth/register", "/api/auth/login", "/api/auth/me"
VERIFY, CHANGE = "/api/auth/verify-token", "/api/auth/change-password"
SECRET = os.environ["JWT_SECRET_KEY"]


# =============================================================== registration
def test_mandatory_1_register_success(client):
    r = client.post(REGISTER, json=register_payload())
    assert r.status_code == 201
    body = r.json()
    assert body == {"message": "User registered successfully", "user_id": 1, "full_name": "Sai Tej",
                    "email": "sai@example.com", "is_active": True}


def test_mandatory_2_register_duplicate_email(client, registered):
    r = client.post(REGISTER, json=register_payload(full_name="Someone Else"))
    assert r.status_code == 409
    assert r.json()["message"] == "An account with this email already exists"


def test_duplicate_email_is_case_insensitive(client, registered):
    assert client.post(REGISTER, json=register_payload(email="SAI@Example.COM")).status_code == 409


@pytest.mark.parametrize("email", ["not-an-email", "sai@", "@example.com", "sai example@x.com", ""])
def test_mandatory_3_register_invalid_email(client, email):
    r = client.post(REGISTER, json=register_payload(email=email))
    assert r.status_code == 422
    assert r.json()["details"][0]["field"] == "email"


def test_mandatory_4_register_mismatched_passwords(client):
    r = client.post(REGISTER, json=register_payload(confirm_password="Different@123"))
    assert r.status_code == 422
    assert r.json()["details"] == [{"field": "confirm_password", "message": "Passwords do not match"}]


@pytest.mark.parametrize("password", ["short1!", "alllowercase1!", "ALLUPPERCASE1!", "NoDigits!!", "NoSpecial123", "x" * 80 + "A1!"])
def test_weak_passwords_rejected(client, password):
    r = client.post(REGISTER, json=register_payload(password=password, confirm_password=password))
    assert r.status_code == 422
    assert r.json()["details"][0]["field"] == "password"


def test_missing_fields(client):
    r = client.post(REGISTER, json={})
    assert r.status_code == 422
    assert {d["field"] for d in r.json()["details"]} == {"full_name", "email", "password", "confirm_password"}


@pytest.mark.parametrize("name", ["", "A", "1234", "<script>", "x" * 101])
def test_invalid_full_name(client, name):
    assert client.post(REGISTER, json=register_payload(full_name=name)).status_code == 422


def test_register_never_returns_password_or_hash(client):
    r = client.post(REGISTER, json=register_payload())
    assert "password" not in r.text.lower().replace("passwords", "")
    assert "$2b$" not in r.text


def test_password_is_stored_as_bcrypt_hash(client, registered):
    with SessionLocal() as db:
        stored = db.query(User).one().password_hash
    assert stored.startswith("$2b$") and PASSWORD not in stored


def test_new_user_gets_default_role(client, registered, auth):
    assert client.get(ME, headers=auth).json()["role"] == "customer"


def test_validation_errors_do_not_echo_the_password(client):
    r = client.post(REGISTER, json=register_payload(password="weak", confirm_password="weak"))
    assert "weak" not in r.text


# =============================================================== login
def test_mandatory_5_login_success(client, registered):
    r = client.post(LOGIN, json={"email": "sai@example.com", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["message"] == "Login successful" and body["token_type"] == "bearer" and body["expires_in"] == 1800
    assert body["user"] == {"id": 1, "full_name": "Sai Tej", "email": "sai@example.com", "role": "customer", "is_active": True}
    claims = jwt.decode(body["access_token"], SECRET, algorithms=["HS256"])
    assert claims["sub"] == "1" and claims["role"] == "customer" and claims["exp"] > time.time()


def test_login_email_is_case_insensitive(client, registered):
    assert client.post(LOGIN, json={"email": "SAI@EXAMPLE.COM", "password": PASSWORD}).status_code == 200


def test_mandatory_6_login_wrong_password(client, registered):
    r = client.post(LOGIN, json={"email": "sai@example.com", "password": "Wrong@12345"})
    assert r.status_code == 401
    assert r.json()["message"] == "Invalid email or password"


def test_login_unknown_email_gives_same_error(client, registered):
    r = client.post(LOGIN, json={"email": "nobody@example.com", "password": PASSWORD})
    assert r.status_code == 401 and r.json()["message"] == "Invalid email or password"


def test_mandatory_7_login_inactive_account(client, registered):
    set_active("sai@example.com", False)
    r = client.post(LOGIN, json={"email": "sai@example.com", "password": PASSWORD})
    assert r.status_code == 403
    assert "inactive" in r.json()["message"]


def test_inactive_account_with_wrong_password_is_401_not_403(client, registered):
    set_active("sai@example.com", False)
    r = client.post(LOGIN, json={"email": "sai@example.com", "password": "Wrong@12345"})
    assert r.status_code == 401


def test_login_missing_fields(client):
    assert client.post(LOGIN, json={"email": "sai@example.com"}).status_code == 422


# =============================================================== /me and token validation
def test_mandatory_8_me_with_valid_token(client, auth):
    r = client.get(ME, headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == 1 and body["email"] == "sai@example.com" and body["full_name"] == "Sai Tej"
    assert body["is_active"] is True and "created_at" in body and "updated_at" in body
    assert "password" not in json.dumps(body).lower()


def test_mandatory_9_protected_endpoint_without_token(client):
    for method, url in [("get", ME), ("post", VERIFY), ("post", CHANGE)]:
        r = getattr(client, method)(url)
        assert r.status_code == 401, url
        assert r.json()["error"] == "Unauthorized"
        assert r.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("bad", ["abc.def.ghi", "not-a-jwt", "Bearer", "a.b"])
def test_mandatory_10_protected_endpoint_with_invalid_token(client, bad):
    r = client.get(ME, headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401 and r.json()["message"] == "Invalid token"


def test_tampered_token_rejected(client, token):
    header, payload, signature = token.split(".")
    forged = base64.urlsafe_b64encode(json.dumps({"sub": "1", "role": "admin", "exp": 9999999999}).encode()).rstrip(b"=").decode()
    r = client.get(ME, headers={"Authorization": f"Bearer {header}.{forged}.{signature}"})
    assert r.status_code == 401


def test_token_signed_with_another_secret_rejected(client, registered):
    fake = jwt.encode({"sub": "1", "role": "customer", "exp": time.time() + 600}, "another-secret-another-secret-another", algorithm="HS256")
    assert client.get(ME, headers={"Authorization": f"Bearer {fake}"}).status_code == 401


def test_alg_none_token_rejected(client, registered):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    none_token = f"{enc({'alg': 'none', 'typ': 'JWT'})}.{enc({'sub': '1', 'role': 'admin', 'exp': 9999999999})}."
    assert client.get(ME, headers={"Authorization": f"Bearer {none_token}"}).status_code == 401


def test_mandatory_11_protected_endpoint_with_expired_token(client, registered):
    expired, _ = create_access_token(1, "customer", expires_delta=timedelta(seconds=-10))
    r = client.get(ME, headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401 and r.json()["message"] == "Token has expired"


def test_expired_token_built_like_the_postman_script(client, registered):
    """Same construction as the pre-request script in the Postman collection (HS256 signed by hand)."""
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    now = int(time.time())
    data = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + "." + \
        b64(json.dumps({"sub": "1", "role": "customer", "iat": now - 7200, "exp": now - 3600}).encode())
    sig = b64(hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).digest())
    r = client.get(ME, headers={"Authorization": f"Bearer {data}.{sig}"})
    assert r.status_code == 401 and r.json()["message"] == "Token has expired"


def test_token_of_deleted_user_rejected(client, auth):
    with SessionLocal() as db:
        db.delete(db.query(User).one())
        db.commit()
    r = client.get(ME, headers=auth)
    assert r.status_code == 401 and r.json()["message"] == "User no longer exists"


def test_token_of_deactivated_user_rejected(client, auth):
    set_active("sai@example.com", False)
    assert client.get(ME, headers=auth).status_code == 403


def test_verify_token(client, auth):
    r = client.post(VERIFY, headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True and body["user_id"] == 1 and body["role"] == "customer" and body["email"] == "sai@example.com"
    assert client.post(VERIFY, headers={"Authorization": "Bearer abc.def.ghi"}).status_code == 401


# =============================================================== change password
def change(client, auth, current=PASSWORD, new=NEW_PASSWORD, confirm=None):
    return client.post(CHANGE, headers=auth, json={"current_password": current, "new_password": new,
                                                    "confirm_new_password": confirm or new})


def test_mandatory_12_change_password_success(client, auth):
    r = change(client, auth)
    assert r.status_code == 200 and r.json() == {"message": "Password changed successfully"}
    assert PASSWORD not in r.text and NEW_PASSWORD not in r.text


def test_mandatory_13_change_password_wrong_current(client, auth):
    r = change(client, auth, current="Wrong@12345")
    assert r.status_code == 400 and r.json()["message"] == "Current password is incorrect"
    # nothing changed: the old password still works
    assert client.post(LOGIN, json={"email": "sai@example.com", "password": PASSWORD}).status_code == 200


def test_mandatory_14_new_password_works_old_does_not(client, auth):
    assert change(client, auth).status_code == 200
    ok = client.post(LOGIN, json={"email": "sai@example.com", "password": NEW_PASSWORD})
    old = client.post(LOGIN, json={"email": "sai@example.com", "password": PASSWORD})
    assert ok.status_code == 200 and old.status_code == 401


def test_change_password_validations(client, auth):
    assert change(client, auth, new="weak").status_code == 422
    assert change(client, auth, confirm="Mismatch@789").status_code == 422
    r = change(client, auth, new=PASSWORD)
    assert r.status_code == 400 and "different" in r.json()["message"]


def test_change_password_requires_token(client, registered):
    r = client.post(CHANGE, json={"current_password": PASSWORD, "new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD})
    assert r.status_code == 401


def test_new_hash_differs_and_is_bcrypt(client, auth):
    with SessionLocal() as db:
        before = db.query(User).one().password_hash
    change(client, auth)
    with SessionLocal() as db:
        after = db.query(User).one().password_hash
    assert after != before and after.startswith("$2b$")


# =============================================================== general
def test_health_and_docs(client):
    assert client.get("/health").status_code == 200
    assert client.get("/docs").status_code == 200
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths) >= {REGISTER, LOGIN, ME, VERIFY, CHANGE}


def test_unknown_route_and_wrong_method(client):
    assert client.get("/nope").status_code == 404
    assert client.get(LOGIN).status_code == 405


def test_unexpected_error_returns_500_without_details(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.services import auth_service

    def boom(*a, **k):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(auth_service, "get_user_by_email", boom)
    r = TestClient(app, raise_server_exceptions=False).post(LOGIN, json={"email": "a@example.com", "password": "x"})
    assert r.status_code == 500 and "secret" not in r.text
