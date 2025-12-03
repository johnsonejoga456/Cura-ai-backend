from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Body, Query
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from datetime import datetime, timedelta
import secrets

from app.api import deps
from app.core import security
from app.core.config import settings
from app.core.database import get_session
from app.models.user import User, UserCreate, UserRead, UserRegister
from app.models.email_verification import EmailVerification
from app.services.email_service import email_service
from app.services.oauth_service import google_oauth_service
from pydantic import BaseModel, EmailStr
import structlog

logger = structlog.get_logger()
router = APIRouter()


# Request/Response Models
class VerifyEmailRequest(BaseModel):
    email: EmailStr
    otp_code: str


class ResendOTPRequest(BaseModel):
    email: EmailStr


class GoogleTokenRequest(BaseModel):
    id_token: str  # For mobile apps


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserRead


# ============================================================================
# SIGN UP ENDPOINTS
# ============================================================================

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserRegister,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """
    Register new user and send OTP for email verification.
    
    Steps:
    1. Validate input
    2. Check if email already exists
    3. Create user (unverified)
    4. Generate and send OTP
    5. Return success message
    """
    # Validate password match
    if user_in.password != user_in.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )
    
    # Check if user already exists
    result = await session.execute(select(User).where(User.email == user_in.email))
    existing_user = result.scalars().first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )
    
    # Create new user
    user = User(
        email=user_in.email,
        hashed_password=security.get_password_hash(user_in.password),
        full_name=user_in.full_name,
        is_email_verified=False,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    
    # Generate OTP
    otp_code = security.generate_otp(settings.OTP_LENGTH)
    
    # Save OTP to database
    email_verification = EmailVerification.create_otp(
        email=user_in.email,
        otp_code=otp_code,
        expiry_minutes=settings.OTP_EXPIRY_MINUTES
    )
    email_verification.user_id = user.id
    session.add(email_verification)
    await session.commit()
    
    # Send verification email
    try:
        await email_service.send_verification_email(
            email=user_in.email,
            full_name=user_in.full_name,
            otp_code=otp_code
        )
        logger.info("Verification email sent", email=user_in.email)
    except Exception as e:
        logger.error("Failed to send verification email", email=user_in.email, error=str(e))
        # Don't fail registration if email fails
    
    return {
        "message": "Registration successful! Please check your email for verification code.",
        "email": user_in.email,
        "expires_in_minutes": settings.OTP_EXPIRY_MINUTES
    }


@router.post("/verify-email", response_model=TokenResponse)
async def verify_email(
    verify_data: VerifyEmailRequest,
    session: AsyncSession = Depends(get_session)
) -> Any:
    """
    Verify email with OTP code.
    Returns access and refresh tokens upon successful verification.
    """
    # Get user
    result = await session.execute(select(User).where(User.email == verify_data.email))
    user = result.scalars().first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified"
        )
    
    # Get latest OTP for this email
    result_otp = await session.execute(
        select(EmailVerification)
        .where(EmailVerification.email == verify_data.email)
        .where(EmailVerification.is_used == False)
        .order_by(EmailVerification.created_at.desc())
    )
    email_verification = result_otp.scalars().first()
    
    if not email_verification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No verification code found. Please request a new one."
        )
    
    # Check if OTP is expired
    if email_verification.is_expired():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired. Please request a new one."
        )
    
    # Verify OTP
    if email_verification.otp_code != verify_data.otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
    
    # Mark email as verified
    user.is_email_verified = True
    user.updated_at = datetime.utcnow()
    
    # Mark OTP as used
    email_verification.is_used = True
    email_verification.verified_at = datetime.utcnow()
    
    await session.commit()
    await session.refresh(user)
    
    # Send welcome email
    try:
        await email_service.send_welcome_email(
            email=user.email,
            full_name=user.full_name or "User"
        )
    except Exception as e:
        logger.error("Failed to send welcome email", email=user.email, error=str(e))
    
    # Generate tokens
    access_token = security.create_access_token(user.id)
    refresh_token = security.create_refresh_token(user.id)
    
    logger.info("Email verified successfully", email=user.email, user_id=user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserRead.from_orm(user)
    )


@router.post("/resend-otp")
async def resend_otp(
    resend_data: ResendOTPRequest,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """
    Resend OTP verification code.
    Rate limited to prevent spam.
    """
    # Get user
    result = await session.execute(select(User).where(User.email == resend_data.email))
    user = result.scalars().first()
    
    # Save new OTP
    email_verification = EmailVerification.create_otp(
        email=resend_data.email,
        otp_code=otp_code,
        expiry_minutes=settings.OTP_EXPIRY_MINUTES
    )
    email_verification.user_id = user.id
    session.add(email_verification)
    await session.commit()
    
    # Send email
    try:
        await email_service.send_verification_email(
            email=resend_data.email,
            full_name=user.full_name or "User",
            otp_code=otp_code
        )
        logger.info("OTP resent", email=resend_data.email)
    except Exception as e:
        logger.error("Failed to resend OTP", email=resend_data.email, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email"
        )
    
    return {
        "message": "Verification code sent! Please check your email.",
        "expires_in_minutes": settings.OTP_EXPIRY_MINUTES
    }




# ============================================================================
# SIGN IN ENDPOINTS
# ============================================================================

@router.post("/login", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session)
) -> Any:
    """
    OAuth2 compatible token login with email and password.
    Returns access token and refresh token.
    """
    # Get user by email (username field contains email)
    result = await session.execute(select(User).where(User.email == form_data.username))
    user = result.scalars().first()
    
    # Check if user exists and password is correct
    if not user or not user.hashed_password or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
    
    # Check if email is verified
    if not user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email address first"
        )
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    # Generate tokens
    access_token = security.create_access_token(user.id)
    refresh_token = security.create_refresh_token(user.id)
    
    logger.info("User logged in", email=user.email, user_id=user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserRead.from_orm(user)
    )


# ============================================================================
# GOOGLE OAUTH ENDPOINTS
# ============================================================================

@router.get("/google")
async def google_login():
    """
    Initiate Google OAuth flow.
    Redirects user to Google consent screen.
    """
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    
    # Get authorization URL
    authorization_url = google_oauth_service.get_authorization_url(state=state)
    
    # In production, store state in session/redis for verification
    # For now, we'll skip state verification in callback
    
    return RedirectResponse(url=authorization_url)


@router.get("/google/callback")
async def google_callback(
    code: str = Query(...),
    state: str = Query(None),
    session: AsyncSession = Depends(get_session)
):
    """
    Google OAuth callback endpoint.
    Handles the authorization code and creates/logs in user.
    """
    try:
        # Exchange code for tokens
        token_response = await google_oauth_service.exchange_code_for_token(code)
        access_token = token_response["access_token"]
        
        # Get user info from Google
        user_info = await google_oauth_service.get_user_info(access_token)
        
        google_id = user_info["id"]
        email = user_info["email"]
        name = user_info.get("name", "")
        picture = user_info.get("picture", "")
        
        # Check if user exists with this Google ID
        result = await session.execute(select(User).where(User.google_id == google_id))
        user = result.scalars().first()
        
        if not user:
            # Check if user exists with this email
            result_email = await session.execute(select(User).where(User.email == email))
            user = result_email.scalars().first()
            
            if user:
                # Link Google account to existing user
                user.google_id = google_id
                user.oauth_provider = "google"
                user.avatar_url = picture
                user.is_email_verified = True  # Google emails are pre-verified
            else:
                # Create new user
                user = User(
                    email=email,
                    full_name=name,
                    google_id=google_id,
                    oauth_provider="google",
                    avatar_url=picture,
                    is_email_verified=True,
                    is_active=True,
                    hashed_password=None  # No password for OAuth users
                )
                session.add(user)
            
            await session.commit()
            await session.refresh(user)
        
        # Generate tokens
        access_token_jwt = security.create_access_token(user.id)
        refresh_token_jwt = security.create_refresh_token(user.id)
        
        logger.info("Google OAuth login successful", email=user.email, user_id=user.id)
        
        # Redirect to frontend with tokens (or return JSON for API-only flow)
        # For web: redirect to frontend with tokens in URL params (not recommended for production)
        # For production: use a more secure flow with session/cookie
        return {
            "access_token": access_token_jwt,
            "refresh_token": refresh_token_jwt,
            "token_type": "bearer",
            "user": UserRead.from_orm(user)
        }
        
    except Exception as e:
        logger.error("Google OAuth failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google authentication failed: {str(e)}"
        )


@router.post("/google/token", response_model=TokenResponse)
async def google_token_login(
    token_data: GoogleTokenRequest,
    session: AsyncSession = Depends(get_session)
) -> Any:
    """
    Login with Google ID token (for mobile apps).
    Mobile apps use Google Sign-In SDK and send the ID token directly.
    """
    try:
        # Verify ID token
        token_info = await google_oauth_service.verify_id_token(token_data.id_token)
        
        google_id = token_info["sub"]
        email = token_info["email"]
        name = token_info.get("name", "")
        picture = token_info.get("picture", "")
        
        # Check if user exists
        result = await session.execute(select(User).where(User.google_id == google_id))
        user = result.scalars().first()
        
        if not user:
            # Check by email
            result_email = await session.execute(select(User).where(User.email == email))
            user = result_email.scalars().first()
            
            if user:
                # Link Google account
                user.google_id = google_id
                user.oauth_provider = "google"
                user.avatar_url = picture
                user.is_email_verified = True
            else:
                # Create new user
                user = User(
                    email=email,
                    full_name=name,
                    google_id=google_id,
                    oauth_provider="google",
                    avatar_url=picture,
                    is_email_verified=True,
                    is_active=True,
                    hashed_password=None
                )
                session.add(user)
            
            await session.commit()
            await session.refresh(user)
        
        # Generate tokens
        access_token = security.create_access_token(user.id)
        refresh_token = security.create_refresh_token(user.id)
        
        logger.info("Google token login successful", email=user.email, user_id=user.id)
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            user=UserRead.from_orm(user)
        )
        
    except Exception as e:
        logger.error("Google token login failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google authentication failed: {str(e)}"
        )


# ============================================================================
# USER INFO ENDPOINT
# ============================================================================

@router.get("/me", response_model=UserRead)
async def read_users_me(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Get current authenticated user.
    """
    return current_user
