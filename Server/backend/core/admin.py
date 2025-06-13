from django.contrib import admin

from .models import (
    EnvironmentInfo,
    FileLog,
    NetworkLog,
    ProcessLog,
    SecurityEvent,
    UserAccount,
    UserGroup,
    UserProfileModel,
    UserSession,
)


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ["client", "event_type", "event_id", "timestamp"]
    search_fields = ["client__client_id", "event_type"]


@admin.register(ProcessLog)
class ProcessLogAdmin(admin.ModelAdmin):
    list_display = ["client", "name", "pid", "start_time"]
    search_fields = ["client__client_id", "name"]


@admin.register(NetworkLog)
class NetworkLogAdmin(admin.ModelAdmin):
    list_display = ["client", "local_address", "remote_address", "timestamp"]
    search_fields = ["client__client_id", "local_address"]


@admin.register(FileLog)
class FileLogAdmin(admin.ModelAdmin):
    list_display = ["client", "event_type", "path", "timestamp"]
    search_fields = ["client__client_id", "path"]


@admin.register(UserAccount)
class UserAccountAdmin(admin.ModelAdmin):
    list_display = ["client", "username", "domain"]
    search_fields = ["client__client_id", "username"]


@admin.register(UserGroup)
class UserGroupAdmin(admin.ModelAdmin):
    list_display = ["client"]
    search_fields = ["client__client_id"]


@admin.register(UserProfileModel)
class UserProfileModelAdmin(admin.ModelAdmin):
    list_display = ["client", "profile_path"]
    search_fields = ["client__client_id"]


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ["client", "session_id", "start_time"]
    search_fields = ["client__client_id"]


@admin.register(EnvironmentInfo)
class EnvironmentInfoAdmin(admin.ModelAdmin):
    list_display = ["client", "machine_name", "os_version"]
    search_fields = ["client__client_id", "machine_name"]
