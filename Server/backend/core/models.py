from django.db import models
from django.utils.text import slugify

# Abstract BaseModel for common fields
class BaseModel(models.Model):
    title = models.CharField(max_length=255)  # Human-readable identifier
    description = models.TextField(null=True, blank=True)  # Optional details for context
    slug = models.SlugField(max_length=255, unique=True, blank=True)  # URL-friendly title
    timestamp = models.DateTimeField(auto_now_add=True)  # Common timestamp for all models

    class Meta:
        abstract = True  # This will not create a separate table

    def save(self, *args, **kwargs):
        # Auto-generate slug from title if not provided
        if not self.slug:
            self.slug = slugify(self.title)
        super(BaseModel, self).save(*args, **kwargs)

# 1. Security Log Model
class SecurityLog(BaseModel):
    event_id = models.IntegerField()
    event_type = models.CharField(max_length=255)  # e.g., 'Failed Login', 'Privilege Escalation'
    source = models.CharField(max_length=255)  # e.g., 'Windows Security Log'

    def __str__(self):
        return f"{self.title} (Event ID: {self.event_id})"

# 2. Process Monitoring Model
class ProcessInfo(BaseModel):
    process_id = models.IntegerField()
    name = models.CharField(max_length=255)  # e.g., 'example.exe'
    cpu_usage = models.FloatField()  # In percentage
    memory_usage = models.FloatField()  # In MB
    status = models.CharField(max_length=50)  # e.g., 'Running', 'Stopped'

    def __str__(self):
        return f"{self.title} (PID: {self.process_id})"

# 3. Service Monitoring Model
class ServiceInfo(BaseModel):
    name = models.CharField(max_length=255)  # e.g., 'Windows Defender'
    display_name = models.CharField(max_length=255)  # A more user-friendly name
    status = models.CharField(max_length=50)  # e.g., 'Running', 'Stopped', 'Paused'
    start_type = models.CharField(max_length=50)  # e.g., 'Automatic', 'Manual'

    def __str__(self):
        return self.title

# 4. Network Connection Model
class NetworkConnection(BaseModel):
    local_address = models.GenericIPAddressField()  # Local IP Address
    local_port = models.IntegerField()
    remote_address = models.GenericIPAddressField()  # Remote IP Address
    remote_port = models.IntegerField()
    protocol = models.CharField(max_length=10)  # e.g., 'TCP', 'UDP'
    state = models.CharField(max_length=50)  # e.g., 'Established', 'Listening', 'Closed'

    def __str__(self):
        return f"{self.title} ({self.local_address}:{self.local_port} -> {self.remote_address}:{self.remote_port})"

# 5. System Configuration Model
class SystemConfig(BaseModel):
    hostname = models.CharField(max_length=255)
    os_version = models.CharField(max_length=255)  # e.g., 'Windows 10 Pro'
    cpu_model = models.CharField(max_length=255)  # e.g., 'Intel Core i7'
    total_memory = models.FloatField()  # Total system memory in GB
    available_memory = models.FloatField()  # Available memory in GB

    def __str__(self):
        return self.title

# 6. User Session Monitoring Model
class UserSession(BaseModel):
    username = models.CharField(max_length=255)
    session_start = models.DateTimeField()
    session_end = models.DateTimeField(null=True, blank=True)  # Allows active sessions
    ip_address = models.GenericIPAddressField()

    def __str__(self):
        return f"{self.title} ({self.username})"

# 7. Collected Data Demonstration Model
class CollectedData(BaseModel):
    example_data = models.JSONField(null=True, blank=True)  # Example of data collected for users to see
    source = models.CharField(max_length=255, null=True, blank=True)  # Data origin, e.g., 'Windows Event Log'

    def __str__(self):
        return self.title
