from django.db import models
from accounts.models import Client

class SecurityEvent(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=100)
    event_id = models.IntegerField()
    source = models.CharField(max_length=100)
    timestamp = models.DateTimeField()
    details = models.TextField()

    class Meta:
        indexes = [
            models.Index(fields=['client', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.event_type} ({self.client.client_id})"

class ProcessLog(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    pid = models.IntegerField()
    path = models.CharField(max_length=255)
    start_time = models.DateTimeField()

    class Meta:
        indexes = [
            models.Index(fields=['client', 'start_time']),
        ]

    def __str__(self):
        return f"{self.name} ({self.client.client_id})"

class NetworkLog(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    local_address = models.CharField(max_length=100)
    remote_address = models.CharField(max_length=100)
    state = models.CharField(max_length=50)
    timestamp = models.DateTimeField()

    class Meta:
        indexes = [
            models.Index(fields=['client', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.local_address} -> {self.remote_address} ({self.client.client_id})"

class FileLog(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=100)
    path = models.CharField(max_length=255)
    change_type = models.CharField(max_length=50)
    old_path = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField()

    class Meta:
        indexes = [
            models.Index(fields=['client', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.event_type} ({self.path})"

class UserAccount(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    username = models.CharField(max_length=100)
    domain = models.CharField(max_length=100)
    sid = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.username} ({self.client.client_id})"

class UserGroup(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    groups = models.JSONField()

    def __str__(self):
        return f"Groups for {self.client.client_id}"

class UserProfileModel(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    profile_path = models.CharField(max_length=255)
    roaming_profile = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return f"Profile for {self.client.client_id}"

class UserSession(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    session_id = models.IntegerField()
    start_time = models.DateTimeField()

    def __str__(self):
        return f"Session {self.session_id} ({self.client.client_id})"

class EnvironmentInfo(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    os_version = models.CharField(max_length=100)
    machine_name = models.CharField(max_length=100)
    processor_count = models.IntegerField()

    def __str__(self):
        return f"Environment for {self.client.client_id}"