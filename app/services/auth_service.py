"""Business logic of the Authentication Service (all database operations for users live here)."""
import logging

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import (
    DUMMY_HASH,
    AuthenticationError,
    TokenData,
    create_access_token,
    get_token_data,
    hash_password,
    verify_password,
)
from app.database.connection import get_db
from app.models.user_model import DEFAULT_ROLE, User
from app.schemas.auth_schema import ChangePasswordRequest, LoginRequest, RegisterRequest

logger = logging.getLogger("auth-service")


# ------------------------------------------------------------------ business errors
class AuthServiceError(Exception):
    status_code = 400
    error = "Bad Request"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class DuplicateEmailError(AuthServiceError):
    status_code, error = 409, "Conflict"

    def __init__(self):
        super().__init__("An account with this email already exists")


class InvalidCredentialsError(AuthServiceError):
    status_code, error = 401, "Unauthorized"

    def __init__(self):  # same message for unknown e-mail and wrong password (no user enumeration)
        super().__init__("Invalid email or password")


class InactiveAccountError(AuthServiceError):
    status_code, error = 403, "Forbidden"

    def __init__(self):
        super().__init__("This account is inactive. Please contact support")


class IncorrectPasswordError(AuthServiceError):
    def __init__(self):
        super().__init__("Current password is incorrect")


class SamePasswordError(AuthServiceError):
    def __init__(self):
        super().__init__("New password must be different from the current password")


# ------------------------------------------------------------------ operations
def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def register_user(db: Session, data: RegisterRequest) -> User:
    if get_user_by_email(db, data.email):
        raise DuplicateEmailError()
    user = User(full_name=data.full_name, email=data.email,
                password_hash=hash_password(data.password), role=DEFAULT_ROLE, is_active=True)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:  # two simultaneous registrations with the same e-mail
        db.rollback()
        raise DuplicateEmailError()
    db.refresh(user)
    logger.info("Registered user id=%s", user.id)
    return user


def login_user(db: Session, data: LoginRequest) -> tuple[User, str, int]:
    user = get_user_by_email(db, data.email)
    # always run one bcrypt check so response time does not reveal whether the e-mail exists
    password_ok = verify_password(data.password, user.password_hash if user else DUMMY_HASH)
    if user is None or not password_ok:
        raise InvalidCredentialsError()
    if not user.is_active:
        raise InactiveAccountError()
    token, expires_in = create_access_token(user.id, user.role)
    logger.info("User id=%s logged in", user.id)
    return user, token, expires_in


def change_password(db: Session, user: User, data: ChangePasswordRequest) -> None:
    if not verify_password(data.current_password, user.password_hash):
        raise IncorrectPasswordError()
    if verify_password(data.new_password, user.password_hash):
        raise SamePasswordError()
    user.password_hash = hash_password(data.new_password)
    db.commit()
    logger.info("User id=%s changed password", user.id)


# ------------------------------------------------------------------ reusable dependency for protected APIs
def get_current_user(token: TokenData = Depends(get_token_data), db: Session = Depends(get_db)) -> User:
    """Validates the Bearer token, loads the user and makes sure the account is still usable.
    Other protected endpoints (here or in other services) can simply depend on this."""
    user = db.get(User, token.user_id)
    if user is None:
        raise AuthenticationError("User no longer exists")
    if not user.is_active:
        raise InactiveAccountError()
    return user
