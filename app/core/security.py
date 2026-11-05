"""Security helpers: password hashing (Passlib/bcrypt) and JWT creation / validation."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from app.core.config import settings

# ------------------------------------------------------------------ passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# used to spend the same time on "unknown e-mail" as on "wrong password"
DUMMY_HASH = pwd_context.hash("dummy-password-used-for-timing")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except ValueError:  # malformed hash
        return False


# ------------------------------------------------------------------ JWT
class AuthenticationError(Exception):
    """Missing, invalid or expired token (HTTP 401)."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass
class TokenData:
    user_id: int
    role: str
    expires_at: datetime


def create_access_token(user_id: int, role: str, expires_delta: timedelta | None = None) -> tuple[str, int]:
    """Returns (token, lifetime in seconds). The token carries the user id (sub) and the role."""
    expires_delta = expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    now = datetime.now(timezone.utc)
    claims = {"sub": str(user_id), "role": role, "iat": now, "exp": now + expires_delta}
    token = jwt.encode(claims, settings.jwt_secret_key.get_secret_value(), algorithm=settings.jwt_algorithm)
    return token, int(expires_delta.total_seconds())


def decode_access_token(token: str) -> TokenData:
    """Checks signature and expiry. Raises AuthenticationError for anything wrong."""
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],  # fixed list: "alg: none" tokens are rejected
            options={"require": ["exp", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except jwt.PyJWTError:
        raise AuthenticationError("Invalid token")
    sub = str(claims["sub"])
    if not sub.isdigit():
        raise AuthenticationError("Invalid token")
    return TokenData(user_id=int(sub), role=str(claims.get("role", "")),
                     expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc))


# ------------------------------------------------------------------ reusable dependency
# auto_error=False -> we return our own consistent 401 instead of FastAPI's default
bearer_scheme = HTTPBearer(auto_error=False, description="Paste the access_token from /api/auth/login")


def get_token_data(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)) -> TokenData:
    """Dependency for any protected endpoint: validates the Bearer token and returns its claims."""
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Not authenticated: Bearer token is missing")
    return decode_access_token(credentials.credentials)
