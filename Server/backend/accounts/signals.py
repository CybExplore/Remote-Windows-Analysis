import logging
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from accounts.models import CustomUser, UserProfile
from accounts.notifications import get_client_ip

logger = logging.getLogger(__name__)

@receiver(post_save, sender=CustomUser)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """
    Create or update a UserProfile whenever a CustomUser is created or updated.
    Skip profile creation if one already exists to avoid duplicate key errors.
    Send a welcome email for new users with verified emails.
    """
    if created:
        # Check if a UserProfile already exists to avoid duplicate creation
        if not hasattr(instance, 'profile') or instance.profile is None:
            logger.debug(f"Creating UserProfile for user {instance.sid}")
            UserProfile.objects.create(user=instance)
        else:
            logger.debug(f"UserProfile already exists for user {instance.sid}, skipping creation")
        
        if instance.email_verified and instance.email:
            def send_welcome_email():
                try:
                    send_mail(
                        subject="Welcome to Windows Security Management",
                        message=f"Hi {instance.full_name or 'User'},\n\nWelcome to our system! We're glad to have you onboard.",
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[instance.email],
                        fail_silently=False,
                    )
                    logger.info(f"Welcome email sent to {instance.email}")
                except Exception as e:
                    logger.error(f"Error sending welcome email to {instance.email}: {str(e)}")
            transaction.on_commit(send_welcome_email)
    else:
        if hasattr(instance, 'profile'):
            instance.profile.save()
            logger.debug(f"Updated UserProfile for user {instance.sid}")

@receiver(user_logged_in, sender=CustomUser)
def update_login_info(sender, user, request, **kwargs):
    """Update last_login_ip and logon_count on user login."""
    if hasattr(user, 'profile'):
        profile = user.profile
        profile.last_login_ip = get_client_ip(request)
        profile.logon_count += 1
        profile.last_logon = timezone.now()
        profile.save()
        logger.debug(f"Updated login info for user {user.sid}: IP={profile.last_login_ip}, Logon Count={profile.logon_count}")

