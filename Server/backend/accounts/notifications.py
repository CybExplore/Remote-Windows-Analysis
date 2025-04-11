from django.core.mail import send_mail
from django.conf import settings
from django.utils.timezone import now as timezone_now

def send_password_change_email(user, request):
    """
    Sends a password change notification email to the user.
    """
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
    except Exception as e:
        raise e  # Propagate the exception for logging in the view


def build_password_change_email_message(user, request):
    """
    Constructs a detailed password change notification email.
    """
    timestamp = timezone_now().strftime('%Y-%m-%d at %H:%M %Z')
    ip_address = request.META.get('REMOTE_ADDR', 'unknown IP')
    user_agent = request.META.get('HTTP_USER_AGENT', 'unknown device')

    return f"""
    Security Notification: Password Changed

    Dear {user.get_full_name() or 'User'},

    Your password for {settings.SITE_NAME} was successfully changed on {timestamp}.

    Change Details:
    - Account: {user.email}
    - Changed From: {ip_address}
    - Device: {user_agent}

    If you didn't make this change:
    1. Contact our security team immediately at {settings.SUPPORT_EMAIL}.
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
    • Review your recent activity at {settings.SITE_URL}/account/activity.

    Thank you for helping us maintain account security.

    The {settings.SITE_NAME} Team
    {settings.SITE_URL}
    {settings.SUPPORT_PHONE}

    --------------------------------------------------
    For security reasons, this email cannot be replied to.
    If you need assistance, please contact {settings.SUPPORT_EMAIL}.
    """

