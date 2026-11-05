"""Configuration rules and the Alembic migration."""
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect

from app.core.config import Settings

ROOT = Path(__file__).resolve().parent.parent
GOOD_SECRET = "s" * 40


def settings(**kwargs):
    return Settings(_env_file=None, **kwargs)


def test_secrets_have_no_defaults(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY")
    with pytest.raises(ValidationError):
        settings(database_url="sqlite://")


def test_short_jwt_secret_rejected():
    with pytest.raises(ValidationError, match="at least 32"):
        settings(database_url="sqlite://", jwt_secret_key="short")


def test_unsafe_jwt_algorithm_rejected():
    with pytest.raises(ValidationError):
        settings(database_url="sqlite://", jwt_secret_key=GOOD_SECRET, jwt_algorithm="none")


def test_missing_database_settings_rejected(monkeypatch):
    monkeypatch.delenv("DATABASE_URL")
    with pytest.raises(ValidationError, match="MYSQL_HOST"):
        settings(jwt_secret_key=GOOD_SECRET)


def test_mysql_url_is_built_from_settings_with_encoding(monkeypatch):
    monkeypatch.delenv("DATABASE_URL")
    s = settings(jwt_secret_key=GOOD_SECRET, mysql_host="auth-db", mysql_database="shopease_auth_db",
                 mysql_user="shopease_auth", mysql_password="p@ss/word")
    assert s.sqlalchemy_url == "mysql+pymysql://shopease_auth:p%40ss%2Fword@auth-db:3306/shopease_auth_db"
    assert "p@ss" not in repr(s)  # secrets are hidden in repr


def test_alembic_migration_creates_and_drops_users_table(tmp_path):
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'migrated.db'}")
    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{tmp_path / 'migrated.db'}")
    insp = inspect(engine)
    columns = {c["name"]: c for c in insp.get_columns("users")}
    assert set(columns) == {"id", "full_name", "email", "password_hash", "role", "is_active", "created_at", "updated_at"}
    assert any(ix["unique"] and ix["column_names"] == ["email"] for ix in insp.get_indexes("users"))

    command.check(cfg)  # raises if the model and the migrations disagree
    command.downgrade(cfg, "base")
    assert "users" not in inspect(engine).get_table_names()
