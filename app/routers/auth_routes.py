"""Authentication endpoints. Routes only receive the request and call the service layer."""
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.security import TokenData, get_token_data
from app.database.connection import get_db
from app.models.user_model import User
from app.schemas.auth_schema import (
    ChangePasswordRequest,
    ErrorResponse,
    LoginRequest,
    LoginResponse,
    MessageResponse,
    RegisterRequest,
    RegisterResponse,
    UserOut,
    UserProfile,
    VerifyTokenResponse,
)
from app.services import auth_service

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

E401 = {401: {"model": ErrorResponse, "description": "Missing, invalid or expired token"}}
E403 = {403: {"model": ErrorResponse, "description": "Account is inactive"}}
E422 = {422: {"model": ErrorResponse, "description": "Validation error"}}


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED,
             summary="Register a new user",
             responses={409: {"model": ErrorResponse, "description": "Email already registered"}, **E422})
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    user = auth_service.register_user(db, payload)
    return RegisterResponse(message="User registered successfully", user_id=user.id,
                            full_name=user.full_name, email=user.email, is_active=user.is_active)


@router.post("/login", response_model=LoginResponse, summary="Log in and get a JWT access token",
             responses={401: {"model": ErrorResponse, "description": "Invalid email or password"}, **E403, **E422})
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user, token, expires_in = auth_service.login_user(db, payload)
    return LoginResponse(message="Login successful", access_token=token, token_type="bearer",
                         expires_in=expires_in, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserProfile, summary="Get the current user (requires Bearer token)",
            responses={**E401, **E403})
def read_current_user(current_user: User = Depends(auth_service.get_current_user)):
    return current_user


@router.post("/verify-token", response_model=VerifyTokenResponse,
             summary="Validate the Bearer token (for use by other services)", responses={**E401, **E403})
def verify_token(token: TokenData = Depends(get_token_data),
                 current_user: User = Depends(auth_service.get_current_user)):
    return VerifyTokenResponse(valid=True, user_id=current_user.id, email=current_user.email,
                               role=current_user.role, expires_at=token.expires_at)


@router.post("/change-password", response_model=MessageResponse,
             summary="Change the password of the authenticated user",
             responses={400: {"model": ErrorResponse, "description": "Current password incorrect / new password unchanged"},
                        **E401, **E403, **E422})
def change_password(payload: ChangePasswordRequest, current_user: User = Depends(auth_service.get_current_user),
                    db: Session = Depends(get_db)):
    auth_service.change_password(db, current_user, payload)
    return MessageResponse(message="Password changed successfully")
