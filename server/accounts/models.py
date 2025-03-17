from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator


class CustomUser(AbstractUser):
    """Custom User Model with additional fields for system and user information."""

    # Remove default fields from AbstractUser
    username = None
    first_name = None
    last_name = None

    # Track whether the user has changed their password
    password_changed = models.BooleanField(default=False, help_text="Has the user changed their password?")

    # Additional fields from Win32_UserAccount and authentication
    full_name = models.CharField(max_length=255, blank=True, null=True, help_text="Full name of the user")
    email = models.EmailField(
        unique=True,
        db_index=True,
        blank=True,
        null=True,
        help_text="User's email address (optional)"
    )
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
        help_text="Security Identifier (SID) from Windows"
    )
    sid_type = models.CharField(max_length=10, blank=True, null=True, help_text="Type of SID (e.g., '1' for User)")
    domain = models.CharField(max_length=255, blank=True, null=True, help_text="Domain of the user account")
    local_account = models.BooleanField(default=False, help_text="Is this a local account?")
    is_shutting_down = models.BooleanField(default=False, help_text="Is the system shutting down during account creation?")
    account_type = models.CharField(max_length=50, blank=True, null=True, help_text="Account type (e.g., '512' for Normal)")
    status = models.CharField(max_length=50, blank=True, null=True, help_text="Account status (e.g., 'OK', 'Degraded')")
    caption = models.CharField(max_length=255, blank=True, null=True, help_text="Caption from Win32_UserAccount")

    # Timestamps for record creation and updates
    created_at = models.DateTimeField(auto_now_add=True, help_text="When the account was created")
    updated_at = models.DateTimeField(auto_now=True, help_text="When the account was last updated")

    # Use SID as the username field for authentication
    USERNAME_FIELD = 'sid'
    REQUIRED_FIELDS = []

    def save(self, *args, **kwargs):
        """Normalize email to lowercase for case-insensitive lookups."""
        if self.email:
            self.email = self.email.lower()
        super().save(*args, **kwargs)

    def __str__(self):
        """Return the SID as the string representation of the user."""
        return self.sid


class UserProfile(models.Model):
    """User Profile Model extending CustomUser with additional metadata."""

    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='profile')
    image = models.ImageField(
        default="profile/default.png",
        upload_to="profile/",
        blank=True,
        null=True,
        help_text="Profile image for the user"
    )

    # Fields from PowerShell/WMI/AD
    description = models.TextField(blank=True, null=True, help_text="Description of the user account")
    account_expires = models.DateTimeField(blank=True, null=True, help_text="Date the account expires (AD: accountExpires)")
    enabled = models.BooleanField(default=True, help_text="Is the account enabled? (Local: Enabled, AD: userAccountControl)")
    password_changeable_date = models.DateTimeField(
        blank=True, null=True, help_text="When the password can next be changed (calculated from policy)"
    )
    password_expires = models.DateTimeField(blank=True, null=True, help_text="When the password expires (Local: PasswordExpires)")
    user_may_change_password = models.BooleanField(default=True, help_text="Can the user change their password? (AD: userAccountControl)")
    password_required = models.BooleanField(default=True, help_text="Is a password required? (Local: PasswordRequired)")
    password_last_set = models.DateTimeField(blank=True, null=True, help_text="Last password set (Local: PasswordLastSet, AD: pwdLastSet)")
    last_logon = models.DateTimeField(blank=True, null=True, help_text="Last logon time (Local: LastLogon, AD: lastLogon)")
    principal_source = models.CharField(
        max_length=50, blank=True, null=True, help_text="Source of account (e.g., 'Local', 'ActiveDirectory')"
    )
    object_class = models.CharField(max_length=50, blank=True, null=True, help_text="Object class (e.g., 'User' from AD: objectClass)")

    # Basic profile fields
    time_zone = models.CharField(
        max_length=50, blank=True, null=True, help_text="User's time zone (e.g., 'UTC', 'America/New_York')"
    )
    preferences = models.JSONField(
        default=dict, blank=True, null=True, help_text="User-specific settings (e.g., {'theme': 'dark'})"
    )
    last_login_ip = models.GenericIPAddressField(blank=True, null=True, help_text="IP address of last login")
    last_password_change = models.DateTimeField(blank=True, null=True, help_text="Date of last password change in Windows")
    logon_count = models.IntegerField(default=0, help_text="Number of logons tracked by the system")

    # Enhanced fields for security, organization, and Windows integration
    locked_out = models.BooleanField(default=False, help_text="Is the account currently locked out?")
    lockout_time = models.DateTimeField(blank=True, null=True, help_text="Timestamp of last lockout")
    department = models.CharField(max_length=100, blank=True, null=True, help_text="User's department (AD: department)")
    job_title = models.CharField(max_length=100, blank=True, null=True, help_text="User's job title (AD: title)")
    local_groups = models.JSONField(
        default=list, blank=True, null=True, help_text="Local group memberships (e.g., ['Administrators', 'Users'])"
    )

    def __str__(self):
        """Return a string representation of the profile."""
        return f"Profile for {self.user.sid}"

    def sync_from_ad(self, ad_data):
        """Helper method to update profile from AD data."""
        self.description = ad_data.get('description')
        self.account_expires = ad_data.get('account_expires')
        self.enabled = ad_data.get('enabled', True)
        self.password_last_set = ad_data.get('pwd_last_set')
        self.last_logon = ad_data.get('last_logon')
        self.principal_source = ad_data.get('principal_source', 'ActiveDirectory')
        self.object_class = ad_data.get('object_class', 'User')
        self.locked_out = ad_data.get('locked_out', False)
        self.lockout_time = ad_data.get('lockout_time')
        self.department = ad_data.get('department')
        self.job_title = ad_data.get('job_title')
        self.save()

    def sync_from_local(self, local_data):
        """Helper method to update profile from local Windows data."""
        self.description = local_data.get('description')
        self.password_expires = local_data.get('password_expires')
        self.user_may_change_password = local_data.get('user_may_change_password', True)
        self.password_required = local_data.get('password_required', True)
        self.password_last_set = local_data.get('password_last_set')
        self.last_logon = local_data.get('last_logon')
        self.principal_source = local_data.get('principal_source', 'Local')
        self.logon_count = local_data.get('logon_count', 0)
        self.local_groups = local_data.get('local_groups', [])
        self.save()



