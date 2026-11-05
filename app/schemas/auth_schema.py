"""Pydantic schemas: validation of requests and shape of responses."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_BYTES = 72  # bcrypt only uses the first 72 bytes


def check_password_strength(password: str) -> str:
    problems = []
    if len(password) < PASSWORD_MIN_LENGTH:
        problems.append(f"at least {PASSWORD_MIN_LENGTH} characters")
    if len(password.encode()) > PASSWORD_MAX_BYTES:
        problems.append(f"at most {PASSWORD_MAX_BYTES} bytes")
    if not any(c.isupper() for c in password):
        problems.append("an uppercase letter")
    if not any(c.islower() for c in password):
        problems.append("a lowercase letter")
    if not any(c.isdigit() for c in password):
        problems.append("a digit")
    if all(c.isalnum() for c in password):
        problems.append("a special character")
    if problems:
        raise ValueError("Password must contain " + ", ".join(problems))
    return password


# ------------------------------------------------------------------ requests
class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(..., examples=["Sai Tej"])
    email: EmailStr = Field(..., examples=["sai@example.com"])
    password: str = Field(..., examples=["Secret@123"])
    confirm_password: str = Field(..., examples=["Secret@123"])

    @field_validator("full_name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        value = " ".join(value.split())  # trim and collapse spaces
        if not 2 <= len(value) <= 100:
            raise ValueError("Full name must be between 2 and 100 characters")
        if not any(c.isalpha() for c in value) or not all(c.isalpha() or c in " .'-" for c in value):
            raise ValueError("Full name may contain only letters, spaces, dots, apostrophes and hyphens")
        return value

    @field_validator("email", mode="before")
    @classmethod
    def clean_email(cls, value):
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        return check_password_strength(value)

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, value: str, info) -> str:
        if "password" in info.data and value != info.data["password"]:
            raise ValueError("Passwords do not match")
        return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., examples=["sai@example.com"])
    password: str = Field(..., min_length=1, max_length=128, examples=["Secret@123"])

    @field_validator("email", mode="before")
    @classmethod
    def clean_email(cls, value):
        return value.strip().lower() if isinstance(value, str) else value


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., examples=["NewSecret@456"])
    confirm_new_password: str = Field(..., examples=["NewSecret@456"])

    @field_validator("new_password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        return check_password_strength(value)

    @field_validator("confirm_new_password")
    @classmethod
    def passwords_match(cls, value: str, info) -> str:
        if "new_password" in info.data and value != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return value


# ------------------------------------------------------------------ responses (never contain a password or hash)
class RegisterResponse(BaseModel):
    message: str
    user_id: int
    full_name: str
    email: str
    is_active: bool


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    email: str
    role: str
    is_active: bool


class UserProfile(UserOut):
    created_at: datetime
    updated_at: datetime


class LoginResponse(BaseModel):
    message: str
    access_token: str
    token_type: str
    expires_in: int = Field(description="Token lifetime in seconds")
    user: UserOut


class VerifyTokenResponse(BaseModel):
    valid: bool
    user_id: int
    email: str
    role: str
    expires_at: datetime


class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    status_code: int
    error: str
    message: str
    details: list[dict] | None = None
