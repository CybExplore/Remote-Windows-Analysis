from django.db import models
from accounts.models import CustomUser

# Create your models here.
# Get-WmiObject -Class Win32_ComputerSystem
class ComputerSystem(models.Model):
    domain = models.CharField(max_length=255, help_text="Domain of the computer")
    manufacturer = models.CharField(max_length=255, help_text="Manufacturer of the computer")
    model = models.CharField(max_length=255, help_text="Model of the computer")
    name = models.CharField(max_length=255, help_text="Computer name")
    primaryowner = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name="computer_systems", 
        null=True, blank=True
        # The primary owner of the computer
    )
    total_physical_memory = models.FloatField(help_text="Total physical memory in GB")

    
# Get-WmiObject -Class Win32_OperatingSystem
class OperatingSystem(models.Model):
    system_directory = models.CharField(max_length=243)
    organization = models.CharField(max_length=234)
    build_number = models.IntegerField()
    registered_users = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name="operating_systems",
        null=True,
        blank=True
        # The owner of the operating system
    )
    serial_number = models.CharField(max_length=400)
    version = models.CharField(max_length=255)
    




class ResourceUsage(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="resource_usages", null=True, blank=True)
    cpu_usage = models.FloatField(help_text="Percentage of CPU usage")
    memory_usage = models.FloatField(help_text="Percentage of memory usage")
    disk_usage = models.FloatField(help_text="Percentage of disk usage")
    network_bandwidth = models.FloatField(help_text="Network bandwidth usage in Mbps")
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ResourceUsage for {self.user.sid} at {self.timestamp}"

# class RemoteDesktopSession(models.Model):
#     user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="remote_desktop_sessions", null=True, blank=True)
#     session_id = models.IntegerField(help_text="Remote Desktop session ID")
#     timestamp = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"RemoteDesktopSession for {self.user.sid} with session ID {self.session_id}"
    
#     def get_duration(self):
#         duration = (self.timestamp - self.timestamp.replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds()
#         return duration // 60 // 60 // 24
    
#     def get_formatted_duration(self):
#         duration = self.get_duration()
#         hours = duration % 24
#         minutes = (duration // 60) % 60
#         seconds = duration % 60
#         return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    



