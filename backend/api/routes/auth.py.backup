"""
Authentication API endpoints.
"""
import logging
from datetime import timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field

from backend.core.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    APIKey,
    Token,
    User,
    authenticate_user,
    create_access_token,
    create_refresh_token,
    create_user,
    create_user_api_key,
    decode_token,
    get_current_active_user,
    get_current_admin_user,
    API_KEYS_DB,
    USERS_DB,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# Request/Response Models
class UserCreate(BaseModel):
    """User creation request."""

    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(None, max_length=100)


class UserResponse(BaseModel):
    """User response."""

    user_id: str
    email: str
    full_name: str = None
    is_active: bool
    is_admin: bool
    scopes: List[str]


class APIKeyCreate(BaseModel):
    """API key creation request."""

    name: str = Field(..., min_length=1, max_length=100)
    scopes: List[str] = Field(default=["read", "scan"])
    expires_in_days: int = Field(None, gt=0, le=365, description="Expiration in days (max 365)")


class APIKeyResponse(BaseModel):
    """API key response."""

    key_id: str
    name: str
    key: str = Field(None, description="Full API key (only shown once)")
    key_prefix: str
    scopes: List[str]
    created_at: str
    expires_at: str = None
    is_active: bool


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str


# Authentication Endpoints
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate) -> UserResponse:
    """
    Register new user.

    Args:
        user_data: User registration data

    Returns:
        Created user
    """
    try:
        user = create_user(
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name,
            scopes=["read", "scan"],  # Default scopes for new users
        )

        logger.info(f"New user registered: {user.email}")

        return UserResponse(
            user_id=user.user_id,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            is_admin=user.is_admin,
            scopes=user.scopes,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error registering user: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user",
        )


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    """
    Login with email and password.

    Returns JWT access token and refresh token.

    Args:
        form_data: OAuth2 form data (username=email, password)

    Returns:
        JWT tokens
    """
    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.user_id, "email": user.email, "scopes": user.scopes},
        expires_delta=access_token_expires,
    )

    refresh_token = create_refresh_token(
        data={"sub": user.user_id, "email": user.email, "scopes": user.scopes}
    )

    logger.info(f"User logged in: {user.email}")

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # In seconds
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(request: RefreshTokenRequest) -> Token:
    """
    Refresh access token using refresh token.

    Args:
        request: Refresh token request

    Returns:
        New JWT tokens
    """
    try:
        # Decode refresh token
        token_data = decode_token(request.refresh_token)

        # Create new tokens
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": token_data.user_id, "email": token_data.email, "scopes": token_data.scopes},
            expires_delta=access_token_expires,
        )

        refresh_token = create_refresh_token(
            data={"sub": token_data.user_id, "email": token_data.email, "scopes": token_data.scopes}
        )

        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing token: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)) -> UserResponse:
    """
    Get current user information.

    Requires authentication.

    Args:
        current_user: Current authenticated user

    Returns:
        User information
    """
    return UserResponse(
        user_id=current_user.user_id,
        email=current_user.email,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        scopes=current_user.scopes,
    )


# API Key Management
@router.post("/api-keys", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_active_user),
) -> APIKeyResponse:
    """
    Create new API key.

    Requires authentication. The full API key is only shown once.

    Args:
        key_data: API key creation data
        current_user: Current authenticated user

    Returns:
        Created API key with full key
    """
    try:
        full_key, api_key = create_user_api_key(
            user_id=current_user.user_id,
            name=key_data.name,
            scopes=key_data.scopes,
            expires_in_days=key_data.expires_in_days,
        )

        logger.info(f"API key created: {api_key.name} for user {current_user.email}")

        return APIKeyResponse(
            key_id=api_key.key_id,
            name=api_key.name,
            key=full_key,  # Only shown once!
            key_prefix=api_key.key_prefix,
            scopes=api_key.scopes,
            created_at=api_key.created_at.isoformat(),
            expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
            is_active=api_key.is_active,
        )

    except Exception as e:
        logger.error(f"Error creating API key: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key",
        )


@router.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(current_user: User = Depends(get_current_active_user)) -> List[APIKeyResponse]:
    """
    List user's API keys.

    Requires authentication. Does not show full keys.

    Args:
        current_user: Current authenticated user

    Returns:
        List of API keys
    """
    keys = []

    for key_data in API_KEYS_DB.values():
        if key_data["user_id"] == current_user.user_id:
            keys.append(
                APIKeyResponse(
                    key_id=key_data["key_id"],
                    name=key_data["name"],
                    key_prefix=key_data["key_prefix"],
                    scopes=key_data["scopes"],
                    created_at=key_data["created_at"].isoformat(),
                    expires_at=key_data["expires_at"].isoformat() if key_data.get("expires_at") else None,
                    is_active=key_data["is_active"],
                )
            )

    return keys


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """
    Revoke API key.

    Requires authentication. Can only revoke own keys.

    Args:
        key_id: API key ID
        current_user: Current authenticated user
    """
    # Find key
    found = False
    for full_key, key_data in API_KEYS_DB.items():
        if key_data["key_id"] == key_id:
            # Check ownership
            if key_data["user_id"] != current_user.user_id and not current_user.is_admin:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot revoke another user's API key",
                )

            # Revoke
            key_data["is_active"] = False
            found = True
            logger.info(f"API key revoked: {key_data['name']} by {current_user.email}")
            break

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )


# Admin Endpoints
@router.get("/users", response_model=List[UserResponse])
async def list_users(current_user: User = Depends(get_current_admin_user)) -> List[UserResponse]:
    """
    List all users.

    Requires admin privileges.

    Args:
        current_user: Current admin user

    Returns:
        List of users
    """
    users = []

    for user_data in USERS_DB.values():
        users.append(
            UserResponse(
                user_id=user_data["user_id"],
                email=user_data["email"],
                full_name=user_data.get("full_name"),
                is_active=user_data.get("is_active", True),
                is_admin=user_data.get("is_admin", False),
                scopes=user_data.get("scopes", []),
            )
        )

    return users


@router.patch("/users/{user_id}/activate")
async def activate_user(
    user_id: str,
    current_user: User = Depends(get_current_admin_user),
) -> Dict[str, str]:
    """
    Activate user account.

    Requires admin privileges.

    Args:
        user_id: User ID
        current_user: Current admin user

    Returns:
        Success message
    """
    # Find user
    found = False
    for user_data in USERS_DB.values():
        if user_data["user_id"] == user_id:
            user_data["is_active"] = True
            found = True
            logger.info(f"User activated: {user_data['email']} by {current_user.email}")
            break

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return {"message": "User activated successfully"}


@router.patch("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: str,
    current_user: User = Depends(get_current_admin_user),
) -> Dict[str, str]:
    """
    Deactivate user account.

    Requires admin privileges.

    Args:
        user_id: User ID
        current_user: Current admin user

    Returns:
        Success message
    """
    # Find user
    found = False
    for user_data in USERS_DB.values():
        if user_data["user_id"] == user_id:
            if user_data["user_id"] == current_user.user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot deactivate your own account",
                )

            user_data["is_active"] = False
            found = True
            logger.info(f"User deactivated: {user_data['email']} by {current_user.email}")
            break

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return {"message": "User deactivated successfully"}


@router.get("/health")
async def auth_health_check() -> Dict[str, str]:
    """Health check for authentication service."""
    return {
        "status": "healthy",
        "service": "authentication",
        "version": "1.0.0",
    }
