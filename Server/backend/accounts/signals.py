from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in
from accounts.models import CustomUser, UserProfile
from django.utils import timezone


@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    """Automatically create a UserProfile when a CustomUser is created."""
    if created:
        UserProfile.objects.create(user=instance)
        # Optionally set initial values
        instance.profile.time_zone = 'UTC'  # Default time zone
        instance.profile.preferences = {'theme': 'light', 'notifications': 'email'}
        instance.profile.save()
        


@receiver(post_save, sender=CustomUser)
def save_user_profile(sender, instance, **kwargs):
    """Ensure the UserProfile is saved when CustomUser is updated."""
    if hasattr(instance, 'profile'):
        instance.profile.save()


@receiver(user_logged_in, sender=CustomUser)
def update_login_info(sender, user, request, **kwargs):
    """Update last_login_ip and logon_count on user login."""
    if hasattr(user, 'profile'):
        profile = user.profile
        # Get client IP from request
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        profile.last_login_ip = ip
        profile.logon_count += 1
        profile.last_logon = timezone.now()
        profile.save()

