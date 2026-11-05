"""Application settings – every value comes from environment variables or the .env file.

Nothing secret has a default value: if the database credentials or the JWT secret
are missing, the service refuses to start instead of falling back to something insecure.
"""
from functools import lru_cache
from urllib.parse import quote_plus

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ShopEase Authentication Service"
    app_version: str = "1.0.0"
    debug: bool = False

    # ---- database (MySQL). DATABASE_URL can override everything (used by the automated tests)
    database_url: str | None = None
    mysql_host: str | None = None
    mysql_port: int = 3306
    mysql_database: str | None = None
    mysql_user: str | None = None
    mysql_password: SecretStr | None = None

    # ---- JWT
    jwt_secret_key: SecretStr = Field(..., description="At least 32 characters")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=30, gt=0)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @field_validator("jwt_secret_key")
    @classmethod
    def secret_must_be_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")
        return value

    @field_validator("jwt_algorithm")
    @classmethod
    def algorithm_must_be_hmac(cls, value: str) -> str:
        if value not in {"HS256", "HS384", "HS512"}:
            raise ValueError("JWT_ALGORITHM must be HS256, HS384 or HS512")
        return value

    @model_validator(mode="after")
    def database_settings_must_be_complete(self):
        if not self.database_url:
            missing = [name for name in ("mysql_host", "mysql_database", "mysql_user", "mysql_password")
                       if not getattr(self, name)]
            if missing:
                raise ValueError("Missing database settings: " + ", ".join(m.upper() for m in missing))
        return self

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        user = quote_plus(self.mysql_user)
        password = quote_plus(self.mysql_password.get_secret_value())
        return f"mysql+pymysql://{user}:{password}@{self.mysql_host}:{self.mysql_port}/{self.mysql_database}"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
