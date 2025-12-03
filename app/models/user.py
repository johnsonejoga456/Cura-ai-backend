from typing import Optional
from sqlmodel import Field, SQLModel
from datetime import datetime

class UserBase(SQLModel):
    email: str = Field(unique=True, index=True)
    is_active: bool = True
    is_superuser: bool = False
    full_name: Optional[str] = None

class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: Optional[str] = None  # Optional for OAuth users
    
    # Email verification
    is_email_verified: bool = Field(default=False)
    
    # OAuth fields
    google_id: Optional[str] = Field(default=None, unique=True, index=True)
    oauth_provider: Optional[str] = None  # 'google', 'facebook', etc.
    
    # Profile
    avatar_url: Optional[str] = None
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(UserBase):
    password: str

class UserRegister(SQLModel):
    """
    User registration schema - only fields the user can set during signup.
    is_active and is_superuser are set automatically by the backend.
    """
    email: str
    password: str
    confirm_password: str
    full_name: str  # Required for registration


class UserRead(UserBase):
    id: int

