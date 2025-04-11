from django.contrib import admin
from .models import SecurityLog, ProcessInfo, ServiceInfo, NetworkConnection, SystemConfig, UserSession

admin.site.register(SecurityLog)
admin.site.register(ProcessInfo)
admin.site.register(ServiceInfo)
admin.site.register(NetworkConnection)
admin.site.register(SystemConfig)
admin.site.register(UserSession)

