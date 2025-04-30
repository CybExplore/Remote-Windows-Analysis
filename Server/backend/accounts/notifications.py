import logging
from django.core.mail import send_mail
from django.conf import settings
from django.utils.timezone import now as timezone_now
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

logger = logging.getLogger(__name__)

SITE_NAME = getattr(settings, 'SITE_NAME', 'Windows Security Management')
SUPPORT_EMAIL = getattr(settings, 'SUPPORT_EMAIL', 'support@example.com')
SUPPORT_PHONE = getattr(settings, 'SUPPORT_PHONE', '')
SITE_URL = getattr(settings, 'SITE_URL', 'https://example.com')

def send_password_change_email(user, request):
    """Send a password change notification email to the user."""
    try:
        subject = "Your Password Has Been Changed"
        message = build_password_change_email_message(user, request)
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        logger.info(f"Password change email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send password change email to {user.email}: {str(e)}")

def build_password_change_email_message(user, request):
    """Construct a detailed password change notification email."""
    timestamp = timezone_now().strftime('%Y-%m-%d at %H:%M %Z')
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'unknown device')

    return f"""
Security Notification: Password Changed

Dear {user.get_full_name() or 'User'},

Your password for {SITE_NAME} was successfully changed on {timestamp}.

Change Details:
- Account: {user.email}
- Changed From: {ip_address}
- Device: {user_agent}

If you didn't make this change:
1. Contact our security team immediately at {SUPPORT_EMAIL}.
2. Change your password again using the 'Forgot Password' feature.
3. Check your account for any unauthorized activity.

Security Recommendations:
✓ Use a unique password for this service.
✓ Enable two-factor authentication.
✓ Regularly update your passwords (every 90 days).
✓ Never share your credentials with anyone.
✓ Be cautious of phishing attempts.

For your protection:
• This is an automated message - please do not reply.
• We will never ask for your password via email.
• Review your recent activity at {SITE_URL}/account/activity.

Thank you for helping us maintain account security.

The {SITE_NAME} Team
{SITE_URL}
{SUPPORT_PHONE}

--------------------------------------------------
For security reasons, this email cannot be replied to.
If you need assistance, please contact {SUPPORT_EMAIL}.
"""

def send_verification_email(user):
    """Send a verification email to the user with a secure token."""
    try:
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verification_link = f"{settings.FRONTEND_URL}/verify-email/{uid}/{token}/"
        send_mail(
            subject="Verify Your Email",
            message=f"Dear {user.full_name or 'User'},\n\nClick the link to verify your email:\n\n{verification_link}\n\nRegards,\n{SITE_NAME}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        logger.info(f"Verification email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")

def get_client_ip(request):
    """Return the client's real IP address."""
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded.split(',')[0] if x_forwarded else request.META.get('REMOTE_ADDR')



