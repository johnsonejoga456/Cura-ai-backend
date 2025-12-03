from typing import Optional
from sqlmodel import Field, SQLModel
from sqlalchemy import ForeignKey, Column, Integer
from datetime import datetime, timedelta


class EmailVerificationBase(SQLModel):
    email: str = Field(index=True, max_length=255)
    otp_code: str = Field(max_length=6)


class EmailVerification(EmailVerificationBase, table=True):
    """
    Email verification with OTP code.
    Stores 6-digit codes for email verification during registration.
    """
    __tablename__ = "email_verifications"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(
        default=None,
        sa_column=Column(Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=True)
    )
    email: str = Field(index=True, max_length=255)
    otp_code: str = Field(max_length=6)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    
    # Status
    is_used: bool = Field(default=False)
    verified_at: Optional[datetime] = None
    
    @classmethod
    def create_otp(cls, email: str, otp_code: str, expiry_minutes: int = 10) -> "EmailVerification":
        """Helper method to create OTP with expiration"""
        return cls(
            email=email,
            otp_code=otp_code,
            expires_at=datetime.utcnow() + timedelta(minutes=expiry_minutes)
        )
    
    def is_expired(self) -> bool:
        """Check if OTP has expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if OTP is valid (not expired, not used)"""
        return not self.is_expired() and not self.is_used


class EmailVerificationCreate(EmailVerificationBase):
    pass


class EmailVerificationRead(EmailVerificationBase):
    id: int
    created_at: datetime
    expires_at: datetime
    is_used: bool
    verified_at: Optional[datetime]
