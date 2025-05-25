from django.urls import path
from core.views import (
    ServerInfoView, SecurityEventView, FirewallStatusView
)

# Using DefaultRouter to manage URLs


# Register APIViews with URLs
urlpatterns = [
    path('server-info/', ServerInfoView.as_view(), name='server-info'),
    path('events/', SecurityEventView.as_view(), name='security-events'),
    path('firewall-status/', FirewallStatusView.as_view(), name='firewall-status'),
]

# urlpatterns += router.urls
