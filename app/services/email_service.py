import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from app.core.config import settings
import structlog

logger = structlog.get_logger()


class EmailService:
    """
    Service for sending emails via SMTP.
    Supports HTML templates using Jinja2.
    """
    
    def __init__(self):
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = settings.FROM_EMAIL
        self.from_name = settings.FROM_NAME
        
        # Setup Jinja2 for email templates
        template_dir = Path(__file__).parent.parent / "templates" / "email"
        template_dir.mkdir(parents=True, exist_ok=True)
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str = None
    ) -> bool:
        """
        Send an email via SMTP.
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML content of email
            text_content: Plain text alternative (optional)
        
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email
            
            # Add text and HTML parts
            if text_content:
                text_part = MIMEText(text_content, "plain")
                message.attach(text_part)
            
            html_part = MIMEText(html_content, "html")
            message.attach(html_part)
            
            # Send email
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True
            )
            
            logger.info("Email sent successfully", to=to_email, subject=subject)
            return True
            
        except Exception as e:
            logger.error("Failed to send email", to=to_email, error=str(e))
            return False
    
    async def send_verification_email(
        self,
        email: str,
        full_name: str,
        otp_code: str
    ) -> bool:
        """
        Send email verification OTP to user.
        
        Args:
            email: User's email address
            full_name: User's full name
            otp_code: 6-digit OTP code
        
        Returns:
            True if email sent successfully
        """
        subject = f"Verify your email - {settings.APP_NAME}"
        
        # HTML version
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }}
                .otp-code {{
                    font-size: 32px;
                    font-weight: bold;
                    letter-spacing: 10px;
                    text-align: center;
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 20px 0;
                    color: #667eea;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 20px;
                    font-size: 12px;
                    color: #666;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to {settings.APP_NAME}!</h1>
                </div>
                <div class="content">
                    <p>Hi {full_name},</p>
                    <p>Thank you for signing up! Please verify your email address using the code below:</p>
                    
                    <div class="otp-code">{otp_code}</div>
                    
                    <p>This code will expire in {settings.OTP_EXPIRY_MINUTES} minutes.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                    
                    <p>Best regards,<br>The {settings.APP_NAME} Team</p>
                </div>
                <div class="footer">
                    <p>This is an automated email. Please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version
        text_content = f"""
        Welcome to {settings.APP_NAME}!
        
        Hi {full_name},
        
        Thank you for signing up! Please verify your email address using this code:
        
        {otp_code}
        
        This code will expire in {settings.OTP_EXPIRY_MINUTES} minutes.
        
        If you didn't request this, please ignore this email.
        
        Best regards,
        The {settings.APP_NAME} Team
        """
        
        return await self.send_email(email, subject, html_content, text_content)
    
    async def send_welcome_email(
        self,
        email: str,
        full_name: str
    ) -> bool:
        """
        Send welcome email after successful verification.
        """
        subject = f"Welcome to {settings.APP_NAME}!"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to {settings.APP_NAME}!</h1>
                </div>
                <div style="padding: 30px; background: #f9f9f9; margin-top: 20px; border-radius: 10px;">
                    <p>Hi {full_name},</p>
                    <p>Your email has been verified successfully! 🎉</p>
                    <p>You can now start using {settings.APP_NAME} - your caring AI companion.</p>
                    <p>If you have any questions, feel free to reach out to our support team.</p>
                    <p>Best regards,<br>The {settings.APP_NAME} Team</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
        Welcome to {settings.APP_NAME}!
        
        Hi {full_name},
        
        Your email has been verified successfully!
        
        You can now start using {settings.APP_NAME} - your caring AI companion.
        
        Best regards,
        The {settings.APP_NAME} Team
        """
        
        return await self.send_email(email, subject, html_content, text_content)


# Singleton instance
email_service = EmailService()
