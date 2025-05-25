from django.contrib.auth.models import UserManager
from django.core.validators import RegexValidator

class CustomUserManager(UserManager):
    """Custom manager to handle user creation with SID instead of username."""

    def create_user(self, sid, email, password=None, **extra_fields):
        """
        Create a regular user with SID, email, and password.
        The first user created is automatically granted staff and superuser privileges
        unless explicitly overridden in extra_fields.
        """
        if not self.model.objects.exists():
            extra_fields.setdefault('is_staff', True)
            extra_fields.setdefault('is_superuser', True)
        return self._create_user(sid, email, password, **extra_fields)

    def create_superuser(self, sid, email, password=None, **extra_fields):
        """Create a superuser with SID, email, and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(sid, email, password, **extra_fields)

    def _create_user(self, sid, email, password, **extra_fields):
        """Create and save a user with the given SID, email, and password."""
        if not sid:
            raise ValueError('The SID must be set')
        if not email:
            raise ValueError('The Email must be set')

        sid_validator = RegexValidator(
            regex=r'^S-1-5-21-\d+-\d+-\d+-\d+$',
            message="Invalid SID format"
        )
        sid_validator(sid)

        email = self.normalize_email(email)
        user = self.model(sid=sid, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

