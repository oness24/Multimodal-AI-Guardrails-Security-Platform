"""
Authentication and authorization system.

Implements JWT-based authentication and API key management for securing the platform.
"""
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from backend.core.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# JWT settings
SECRET_KEY = settings.secret_key if hasattr(settings, "secret_key") else secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
REFRESH_TOKEN_EXPIRE_DAYS = 30


# Models
class Token(BaseModel):
    """JWT token response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """JWT token payload."""

    user_id: Optional[str] = None
    email: Optional[str] = None
    scopes: list[str] = []


class User(BaseModel):
    """User model."""

    user_id: str
    email: str
    full_name: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False
    scopes: list[str] = []


class APIKey(BaseModel):
    """API key model."""

    key_id: str
    name: str
    key_prefix: str  # First 8 chars for display
    user_id: str
    scopes: list[str] = []
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_active: bool = True


# In-memory stores (in production, use database)
USERS_DB: Dict[str, Dict[str, Any]] = {
    "admin@adversarialshield.ai": {
        "user_id": "admin-001",
        "email": "admin@adversarialshield.ai",
        "full_name": "Admin User",
        "hashed_password": pwd_context.hash("admin123"),  # Change in production!
        "is_active": True,
        "is_admin": True,
        "scopes": ["admin", "read", "write", "scan", "attack", "guardrails"],
    }
}

API_KEYS_DB: Dict[str, Dict[str, Any]] = {}


# Password utilities
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password."""
    return pwd_context.hash(password)


# JWT utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT access token.

    Args:
        data: Token payload data
        expires_delta: Token expiration time

    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """
    Create JWT refresh token.

    Args:
        data: Token payload data

    Returns:
        Encoded refresh token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> TokenData:
    """
    Decode and validate JWT token.

    Args:
        token: JWT token string

    Returns:
        Token data

    Raises:
        HTTPException: If token is invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        email: str = payload.get("email")
        scopes: list = payload.get("scopes", [])

        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return TokenData(user_id=user_id, email=email, scopes=scopes)

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# API Key utilities
def generate_api_key() -> tuple[str, str]:
    """
    Generate API key.

    Returns:
        Tuple of (full_key, key_prefix)
    """
    # Generate secure random key
    full_key = f"advshield_{secrets.token_urlsafe(32)}"
    key_prefix = full_key[:16]  # First 16 chars for display

    return full_key, key_prefix


def validate_api_key(api_key: str) -> Optional[APIKey]:
    """
    Validate API key.

    Args:
        api_key: API key string

    Returns:
        API key object if valid, None otherwise
    """
    # In production, hash the key and lookup in database
    key_data = API_KEYS_DB.get(api_key)

    if not key_data:
        return None

    # Check if expired
    if key_data.get("expires_at"):
        if datetime.utcnow() > key_data["expires_at"]:
            return None

    # Check if active
    if not key_data.get("is_active", True):
        return None

    # Update last used
    key_data["last_used"] = datetime.utcnow()

    return APIKey(**key_data)


# Authentication dependencies
async def get_current_user_from_token(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> User:
    """
    Get current user from JWT token.

    Args:
        credentials: HTTP authorization credentials

    Returns:
        User object

    Raises:
        HTTPException: If authentication fails
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = decode_token(credentials.credentials)

    # Get user from database
    user_data = None
    for email, data in USERS_DB.items():
        if data["user_id"] == token_data.user_id:
            user_data = data
            break

    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user_data.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    return User(
        user_id=user_data["user_id"],
        email=user_data["email"],
        full_name=user_data.get("full_name"),
        is_active=user_data.get("is_active", True),
        is_admin=user_data.get("is_admin", False),
        scopes=user_data.get("scopes", []),
    )


async def get_current_user_from_api_key(
    api_key: str = Security(api_key_header),
) -> User:
    """
    Get current user from API key.

    Args:
        api_key: API key from header

    Returns:
        User object

    Raises:
        HTTPException: If authentication fails
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )

    key_obj = validate_api_key(api_key)

    if not key_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    # Get user associated with API key
    user_data = None
    for email, data in USERS_DB.items():
        if data["user_id"] == key_obj.user_id:
            user_data = data
            break

    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return User(
        user_id=user_data["user_id"],
        email=user_data["email"],
        full_name=user_data.get("full_name"),
        is_active=user_data.get("is_active", True),
        is_admin=user_data.get("is_admin", False),
        scopes=key_obj.scopes,  # Use API key scopes
    )


async def get_current_user(
    token_user: Optional[User] = Depends(get_current_user_from_token),
    api_key_user: Optional[User] = Depends(get_current_user_from_api_key),
) -> User:
    """
    Get current user from either JWT token or API key.

    Tries JWT token first, then falls back to API key.

    Args:
        token_user: User from JWT token
        api_key_user: User from API key

    Returns:
        User object

    Raises:
        HTTPException: If both authentication methods fail
    """
    # Try token first
    try:
        if token_user:
            return token_user
    except HTTPException:
        pass

    # Fall back to API key
    try:
        if api_key_user:
            return api_key_user
    except HTTPException:
        pass

    # Both failed
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated. Provide either Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Get current active user.

    Args:
        current_user: Current user

    Returns:
        User object

    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    return current_user


async def get_current_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Get current admin user.

    Args:
        current_user: Current active user

    Returns:
        User object

    Raises:
        HTTPException: If user is not admin
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


def require_scope(required_scope: str):
    """
    Dependency to require specific scope.

    Args:
        required_scope: Required scope string

    Returns:
        Dependency function
    """

    async def scope_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if required_scope not in current_user.scopes and "admin" not in current_user.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{required_scope}' required",
            )
        return current_user

    return scope_checker


# User management functions
def authenticate_user(email: str, password: str) -> Optional[User]:
    """
    Authenticate user with email and password.

    Args:
        email: User email
        password: User password

    Returns:
        User object if authenticated, None otherwise
    """
    user_data = USERS_DB.get(email)

    if not user_data:
        return None

    if not verify_password(password, user_data["hashed_password"]):
        return None

    return User(
        user_id=user_data["user_id"],
        email=user_data["email"],
        full_name=user_data.get("full_name"),
        is_active=user_data.get("is_active", True),
        is_admin=user_data.get("is_admin", False),
        scopes=user_data.get("scopes", []),
    )


def create_user(email: str, password: str, full_name: Optional[str] = None, scopes: list[str] = None) -> User:
    """
    Create new user.

    Args:
        email: User email
        password: User password
        full_name: User full name
        scopes: User scopes

    Returns:
        Created user

    Raises:
        ValueError: If user already exists
    """
    if email in USERS_DB:
        raise ValueError("User already exists")

    user_id = f"user-{secrets.token_urlsafe(8)}"

    user_data = {
        "user_id": user_id,
        "email": email,
        "full_name": full_name,
        "hashed_password": get_password_hash(password),
        "is_active": True,
        "is_admin": False,
        "scopes": scopes or ["read", "scan"],
    }

    USERS_DB[email] = user_data

    return User(
        user_id=user_id,
        email=email,
        full_name=full_name,
        is_active=True,
        is_admin=False,
        scopes=user_data["scopes"],
    )


def create_user_api_key(
    user_id: str, name: str, scopes: list[str] = None, expires_in_days: Optional[int] = None
) -> tuple[str, APIKey]:
    """
    Create API key for user.

    Args:
        user_id: User ID
        name: API key name
        scopes: API key scopes
        expires_in_days: Expiration in days

    Returns:
        Tuple of (full_key, APIKey object)
    """
    full_key, key_prefix = generate_api_key()

    key_id = f"key-{secrets.token_urlsafe(8)}"

    expires_at = None
    if expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    key_data = {
        "key_id": key_id,
        "name": name,
        "key_prefix": key_prefix,
        "user_id": user_id,
        "scopes": scopes or ["read", "scan"],
        "created_at": datetime.utcnow(),
        "expires_at": expires_at,
        "last_used": None,
        "is_active": True,
    }

    # Store full key as lookup (in production, hash this)
    API_KEYS_DB[full_key] = key_data

    return full_key, APIKey(**key_data)
