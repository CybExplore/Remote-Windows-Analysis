from django.urls import path, include
from rest_framework.routers import DefaultRouter
from core.views import (
    SecurityLogAPIView,
    ProcessInfoAPIView,
    ServiceInfoAPIView,
    NetworkConnectionAPIView,
    SystemConfigAPIView,
    UserSessionAPIView,
)

# Using DefaultRouter to manage URLs
router = DefaultRouter()
router.register(r'security-logs', SecurityLogAPIView, basename='security-logs')
router.register(r'process-info', ProcessInfoAPIView, basename='process-info')
router.register(r'service-info', ServiceInfoAPIView, basename='service-info')
router.register(r'system-config', SystemConfigAPIView, basename='system-config')
router.register(r'network-connections', NetworkConnectionAPIView, basename='network-connections')
router.register(r'user-sessions', UserSessionAPIView, basename='user-sessions')


# Register APIViews with URLs
urlpatterns = [
    path('core/', include(router.urls)),
]

# urlpatterns += router.urls
