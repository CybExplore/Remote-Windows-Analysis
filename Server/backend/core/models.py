from django.db import models
from django.utils.text import slugify
from accounts.models import CustomUser, UserProfile
# ###### START ###### #

class ServerInfo(models.Model):
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
    client = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='security_events')
    event_id = models.IntegerField()
    time_created = models.DateTimeField()
    description = models.TextField()
    source = models.CharField(max_length=50, default="Security")  # E.g., Security, Defender, Firewall
    logon_type = models.CharField(max_length=50, null=True, blank=True)
    failure_reason = models.CharField(max_length=255, null=True, blank=True)
    target_account = models.CharField(max_length=255, null=True, blank=True)
    group_name = models.CharField(max_length=255, null=True, blank=True)
    privilege_name = models.CharField(max_length=255, null=True, blank=True)
    process_name = models.CharField(max_length=255, null=True, blank=True)
    service_name = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Event {self.event_id} for {self.client.sid} at {self.time_created}"

class FirewallStatus(models.Model):
    client = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='firewall_status')
    is_enabled = models.BooleanField()
    profile = models.CharField(max_length=50)
    timestamp = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Firewall status for {self.client.sid} at {self.timestamp}"

# ##### END ###### #
