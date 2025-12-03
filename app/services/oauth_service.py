import httpx
from app.core.config import settings
import structlog

logger = structlog.get_logger()


class GoogleOAuthService:
    """
    Service for Google OAuth authentication.
    """
    
    def __init__(self):
        self.client_id = settings.GOOGLE_CLIENT_ID
        self.client_secret = settings.GOOGLE_CLIENT_SECRET
        self.redirect_uri = settings.GOOGLE_REDIRECT_URI
        
        # OAuth endpoints
        self.authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_endpoint = "https://oauth2.googleapis.com/token"
        self.userinfo_endpoint = "https://www.googleapis.com/oauth2/v2/userinfo"
        
        # OAuth scopes
        self.scopes = [
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]
    
    def get_authorization_url(self, state: str = None) -> str:
        """
        Generate Google OAuth authorization URL.
        
        Args:
            state: CSRF protection state parameter
        
        Returns:
            Authorization URL for redirecting user
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "access_type": "offline",
            "prompt": "consent"
        }
        
        if state:
            params["state"] = state
        
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{self.authorization_endpoint}?{query_string}"
    
    async def exchange_code_for_token(self, code: str) -> dict:
        """
        Exchange authorization code for access token.
        
        Args:
            code: Authorization code from Google
        
        Returns:
            Token response containing access_token, id_token, etc.
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_endpoint,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": self.redirect_uri
                }
            )
            response.raise_for_status()
            return response.json()
    
    async def get_user_info(self, access_token: str) -> dict:
        """
        Get user information from Google.
        
        Args:
            access_token: OAuth access token
        
        Returns:
            User information (email, name, picture, etc.)
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            return response.json()
    
    async def verify_id_token(self, id_token: str) -> dict:
        """
        Verify Google ID token (for mobile apps).
        Mobile apps can use Google Sign-In SDK and send the ID token directly.
        
        Args:
            id_token: Google ID token from mobile app
        
        Returns:
            Decoded token payload
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
            )
            response.raise_for_status()
            token_info = response.json()
            
            # Verify audience (client ID)
            if token_info.get("aud") != self.client_id:
                raise ValueError("Invalid token audience")
            
            # Verify issuer
            if token_info.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
                raise ValueError("Invalid token issuer")
            
            return token_info


# Singleton instance
google_oauth_service = GoogleOAuthService()
