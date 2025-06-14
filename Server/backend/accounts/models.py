# accounts/models.py
import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser, PermissionsMixin
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, validate_email
from django.db import models
from django.utils import timezone

from accounts.manager import CustomUserManager


class CustomUser(AbstractUser):
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
                regex=r"^S-1-5-21-\d+-\d+-\d+-\d+$",
                message="Invalid SID format. Must match Windows SID pattern (e.g., S-1-5-21-<domain>-<RID>).",
            )
        ],
        help_text="Windows Security Identifier (primary key)",
    )
    email = models.EmailField(
        unique=True,
        db_index=True,
        validators=[validate_email],
        help_text="Email address (lowercase)",
    )
    password_changed = models.BooleanField(
        default=False, help_text="Has the user changed their temporary password?"
    )
    is_active = models.BooleanField(default=True)
    last_login = models.DateTimeField(blank=True, null=True)
    is_first_login = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    password_changed = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = "sid"
    REQUIRED_FIELDS = ["email"]

    class Meta:
        verbose_name = "Windows User"
        verbose_name_plural = "Windows Users"
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["sid"]),
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
        CustomUser, on_delete=models.CASCADE, related_name="profile"
    )
    locked_out = models.BooleanField(default=False)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    domain = models.CharField(max_length=255, blank=True, null=True)
    account_type = models.IntegerField(
        blank=True, null=True
    )  # e.g., 512 for normal user
    local_account = models.BooleanField(default=True)
    password_changeable = models.BooleanField(default=True)
    password_expires = models.BooleanField(default=False)
    password_required = models.BooleanField(default=True)
    status = models.CharField(max_length=50, blank=True, null=True)  # e.g., "OK"
    groups = models.JSONField(
        default=list, blank=True, null=True
    )  # List of group names
    profile_local_path = models.CharField(max_length=255, blank=True, null=True)
    profile_last_use_time = models.DateTimeField(blank=True, null=True)
    profile_status = models.IntegerField(blank=True, null=True)
    sessions = models.JSONField(
        default=list, blank=True, null=True
    )  # List of session details
    environment = models.JSONField(
        default=dict, blank=True, null=True
    )  # Environment variables

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

    def __str__(self):
        return f"Profile for {self.user.sid}"


class Client(models.Model):
    client_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    secret_id = models.CharField(max_length=128)
    sid = models.CharField(max_length=100, unique=True)
    user_email = models.EmailField()
    full_name = models.CharField(max_length=100)
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="clients"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Client {self.client_id} for {self.user.email}"


class LogEntry(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="logs")
    client = models.ForeignKey(
        Client, on_delete=models.CASCADE, related_name="logs", null=True
    )
    event_type = models.CharField(
        max_length=100
    )  # e.g., "Security", "Application", "System"
    event_id = models.IntegerField(null=True, blank=True)  # Windows Event ID
    source = models.CharField(
        max_length=255, null=True, blank=True
    )  # e.g., "Microsoft-Windows-Security-Auditing"
    timestamp = models.DateTimeField(db_index=True)  # Timestamp of the event
    details = models.JSONField(
        null=True, blank=True
    )  # Additional event details (e.g., user, machine, description)
    anomaly_score = models.FloatField(
        null=True, blank=True
    )  # For storing anomaly detection results
    created_at = models.DateTimeField(
        auto_now_add=True, db_index=True
    )  # When log was received

    class Meta:
        indexes = [
            models.Index(fields=["event_type", "timestamp"]),
            models.Index(fields=["user", "timestamp"]),
            models.Index(fields=["client", "timestamp"]),
        ]
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.event_type} - {self.timestamp} - {self.user.email}"


class PasswordHistory(models.Model):
    """Password history for security compliance"""

    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="password_history"
    )
    hashed_password = models.CharField(max_length=128)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Password Histories"
        ordering = ["-changed_at"]
        get_latest_by = "changed_at"

    def __str__(self):
        return f"Password history for {self.user.email}"
