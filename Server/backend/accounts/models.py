from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from accounts.manager import CustomUserManager

class CustomUser(AbstractUser, PermissionsMixin):
    """Custom User Model for Windows Security Management System."""
    username = None
    first_name = None
    last_name = None

    objects = CustomUserManager()

    password_changed = models.BooleanField(default=False, help_text="Has the user changed their password?")
    full_name = models.CharField(max_length=255, blank=True, null=True, help_text="Full name of the user")
    email = models.EmailField(
        unique=True,
        db_index=True,
        blank=False,
        null=False,
        help_text="User's email address (required for credentials delivery)"
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
    is_shutting_down = models.BooleanField(default=False, help_text="Was the system shutting down during account creation?")
    account_type = models.CharField(max_length=50, blank=True, null=True, help_text="Account type (e.g., '512' for Normal)")
    status = models.CharField(max_length=50, blank=True, null=True, help_text="Account status (e.g., 'OK', 'Degraded')")
    caption = models.CharField(max_length=255, blank=True, null=True, help_text="Caption from Win32_UserAccount")
    created_at = models.DateTimeField(auto_now_add=True, help_text="When the account was created")
    updated_at = models.DateTimeField(auto_now=True, help_text="When the account was last updated")

    USERNAME_FIELD = 'sid'
    REQUIRED_FIELDS = ['email']

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.lower()
        super().save(*args, **kwargs)

    def __str__(self):
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
    client_id = models.CharField(
        max_length=100, unique=True, blank=True, null=True, db_index=True, help_text="OAuth2 Client ID for this user"
    )
    client_secret = models.CharField(
        max_length=100, blank=True, null=True, help_text="OAuth2 Client Secret"
    )
    account_expires = models.DateTimeField(blank=True, null=True, help_text="Date the account expires")
    enabled = models.BooleanField(default=True, help_text="Is the account enabled?")
    password_changeable_date = models.DateTimeField(blank=True, null=True)
    password_expires = models.DateTimeField(blank=True, null=True)
    user_may_change_password = models.BooleanField(default=True)
    password_required = models.BooleanField(default=True)
    password_last_set = models.DateTimeField(blank=True, null=True)
    last_logon = models.DateTimeField(blank=True, null=True)
    principal_source = models.CharField(max_length=50, blank=True, null=True)
    object_class = models.CharField(max_length=50, blank=True, null=True)
    time_zone = models.CharField(max_length=50, blank=True, null=True)
    preferences = models.JSONField(default=dict, blank=True, null=True)
    last_login_ip = models.GenericIPAddressField(blank=True, null=True)
    last_password_change = models.DateTimeField(blank=True, null=True)
    logon_count = models.IntegerField(default=0)
    locked_out = models.BooleanField(default=False)
    lockout_time = models.DateTimeField(blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    job_title = models.CharField(max_length=100, blank=True, null=True)
    local_groups = models.JSONField(default=list, blank=True, null=True)
    description = models.TextField(blank=True, null=True, help_text="Description of the user account")

    def __str__(self):
        return f"Profile for {self.user.sid}"

    @staticmethod
    def validate_preferences(value):
        if not isinstance(value, dict):
            raise ValidationError("Preferences must be a dictionary")

    @staticmethod
    def validate_local_groups(value):
        if not isinstance(value, list):
            raise ValidationError("Local groups must be a list")

    def sync_from_ad(self, ad_data):
        """Sync user profile data from Active Directory."""
        required_keys = ['description', 'enabled']
        if not all(key in ad_data for key in required_keys):
            raise ValueError("Missing required AD data keys")
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
        """Sync user profile data from local source."""
        required_keys = ['description', 'password_required']
        if not all(key in local_data for key in required_keys):
            raise ValueError("Missing required local data keys")
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

class AuditLog(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

class PasswordHistory(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    password = models.CharField(max_length=128)
    changed_at = models.DateTimeField(auto_now_add=True)


