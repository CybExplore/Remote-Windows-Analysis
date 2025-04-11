# accounts/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.utils import timezone

class CustomUser(AbstractUser):
    """Custom User Model for Windows Security Management System."""
    username = None
    first_name = None
    last_name = None

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
    description = models.TextField(blank=True, null=True, help_text="Description of the user account")
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
        max_length=100, unique=True, blank=True, null=True, help_text="OAuth2 Client ID for this user"
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

    def __str__(self):
        return f"Profile for {self.user.sid}"

    def sync_from_ad(self, ad_data):
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

class ServerInfo(models.Model):
    """Stores system information from client machines."""
    client = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='server_info')
    machine_name = models.CharField(max_length=255)
    os_version = models.CharField(max_length=100)
    processor_count = models.IntegerField()
    timestamp = models.DateTimeField()
    is_64bit = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ServerInfo for {self.client.sid} at {self.timestamp}"

class SecurityEvent(models.Model):
    """Stores Windows security events from client machines."""
    client = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='security_events')
    event_id = models.IntegerField()
    time_created = models.DateTimeField()
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Event {self.event_id} for {self.client.sid} at {self.time_created}"


class SystemUserAccount(models.Model):
    """This models use to store the WinUserAccount object."""
    system_user_account = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name="accounts"
    )
    account_type = models.CharField(max_length=50, blank=True, null=True, help_text="Account type (e.g., '512' for Normal)")
    caption = models.CharField(max_length=255, blank=True, null=True, help_text="Caption from Win32_UserAccount")
    domain = models.CharField(max_length=255, blank=True, null=True, help_text="Domain of the user account")
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
    full_name = models.CharField(max_length=255, blank=True, null=True, help_text="Full name of the user")
    name = models.CharField(max_length=255, blank=True, null=True, help_text="name of the user")
    is_local_account = models.BooleanField(default=False, help_text="Indicates if this is a local account") 


class LoginActivity(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="login_logs")
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=[('success', 'Success'), ('failed', 'Failed')])

    def __str__(self):
        return f"LoginActivity for {self.user.sid} at {self.login_time}"


class NotificationsLog(models.Model):
    recipient = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="notifications")
    email = models.EmailField()
    subject = models.CharField(max_length=255)
    body = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification to {self.recipient.email} - {self.subject}"
