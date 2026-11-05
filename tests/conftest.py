"""Test setup: an in-memory SQLite database and a throw-away JWT secret.
The environment variables must be set BEFORE the application is imported."""
import os

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-automated-tests-only-0123456789"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"

import pytest
from fastapi.testclient import TestClient

from app.database.connection import Base, SessionLocal, engine
from app.main import app
from app.models.user_model import User

PASSWORD = "Secret@123"
NEW_PASSWORD = "NewSecret@456"


@pytest.fixture(autouse=True)
def fresh_database():
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def client():
    return TestClient(app)


def register_payload(**overrides):
    data = {"full_name": "Sai Tej", "email": "sai@example.com", "password": PASSWORD, "confirm_password": PASSWORD}
    data.update(overrides)
    return data


@pytest.fixture
def registered(client):
    """A registered user (sai@example.com / Secret@123)."""
    r = client.post("/api/auth/register", json=register_payload())
    assert r.status_code == 201
    return r.json()


@pytest.fixture
def token(client, registered):
    r = client.post("/api/auth/login", json={"email": "sai@example.com", "password": PASSWORD})
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture
def auth(token):
    return {"Authorization": f"Bearer {token}"}


def set_active(email: str, active: bool):
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=email).one()
        user.is_active = active
        db.commit()
