from django.contrib import admin
from core.models import SecurityEvent, ServerInfo, FirewallStatus


admin.site.register(ServerInfo)
admin.site.register(SecurityEvent)
admin.site.register(FirewallStatus)
