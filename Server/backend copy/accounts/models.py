# accounts/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin
from django.core.validators import RegexValidator, validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings
from accounts.manager import CustomUserManager

class CustomUser(AbstractUser, PermissionsMixin):
    """
    Enhanced User model for Windows Security Management System.
    Replaces username with Windows SID as primary identifier.
    """
    # Disable unused default fields
    username = None
    first_name = None
    last_name = None

    full_name = models.CharField(max_length=500)
    
    # Core authentication fields
    sid = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        validators=[
            RegexValidator(
                regex=r'^S-1-5-21-\d+-\d+-\d+-\d+$',
                message="Invalid SID format. Must match Windows SID pattern (e.g., S-1-5-21-<domain>-<RID>).",
            )
        ],
        help_text="Windows Security Identifier (primary key)"
    )
    email = models.EmailField(
        unique=True,
        db_index=True,
        validators=[validate_email],
        help_text="Verified email address (lowercase)"
    )
    password_changed = models.BooleanField(
        default=False,
        help_text="Has the user changed their temporary password?"
    )
    email_verified = models.BooleanField(blank=True, default=False)

    # Windows account metadata
    account_meta = models.JSONField(
        default=dict,
        blank=True,
        help_text="Stores Windows account attributes like sid_type, domain, etc."
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'sid'
    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = "Windows User"
        verbose_name_plural = "Windows Users"
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['sid']),
        ]

    def clean(self):
        """Normalize email to lowercase before saving"""
        if self.email:
            self.email = self.email.lower()
        super().clean()

    def __str__(self):
        return f"{self.sid} ({self.email})"


class UserProfile(models.Model):
    """Extended user attributes and OAuth2 client credentials"""
    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    
    # Security state
    enabled = models.BooleanField(default=True)
    locked_out = models.BooleanField(default=False)
    lockout_time = models.DateTimeField(null=True, blank=True)
    logon_count = models.IntegerField(default=0)
    
    # Password policy
    password_expires = models.DateTimeField(null=True, blank=True)
    password_last_set = models.DateTimeField(null=True, blank=True)
    user_may_change_password = models.BooleanField(default=True)
    
    # OAuth2 client credentials
    client_id = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        null=True,
        blank=True
    )
    client_secret = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )
    
    # Activity tracking
    last_logon = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    # Additional metadata
    meta = models.JSONField(
        default=dict,
        blank=True,
        help_text="Extended profile attributes"
    )

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

    def __str__(self):
        return f"Profile for {self.user.sid}"

    def validate_client_id(self, client_id, request, *args, **kwargs):
        return UserProfile.objects.filter(client_id=client_id).exists()

    def validate_client_secret(self, client_secret, request, *args, **kwargs):
        try:
            profile = UserProfile.objects.get(client_id=request.client.client_id)
            return profile.client_secret == client_secret
        except UserProfile.DoesNotExist:
            return False

class OAuth2Token(models.Model):
    """OAuth2 token storage with enhanced security tracking"""
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='tokens'
    )
    access_token = models.CharField(max_length=255, unique=True)
    refresh_token = models.CharField(max_length=255, null=True, blank=True)
    expires_at = models.DateTimeField()
    scope = models.CharField(max_length=255, default='read write')
    
    # Security context
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    revoked = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['access_token']),
            models.Index(fields=['user', 'expires_at']),
        ]

    @property
    def is_active(self):
        return not self.revoked and not self.is_expired

    @property
    def is_expired(self):
        return timezone.now() >= self.expires_at


class AuditLog(models.Model):
    """System activity log for security monitoring"""
    ACTION_CHOICES = [
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('password_change', 'Password Change'),
        ('token_issued', 'Token Issued'),
    ]

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['user']),
            models.Index(fields=['action']),
            models.Index(fields=['ip_address']),
        ]


class PasswordHistory(models.Model):
    """Password history for security compliance"""
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='password_history'
    )
    hashed_password = models.CharField(max_length=128)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Password Histories"
        ordering = ['-changed_at']
        get_latest_by = 'changed_at'



