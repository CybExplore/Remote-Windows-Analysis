# accounts/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from accounts.views import (
    CustomUserCreateView, CustomUserDetailView, LoginView, PasswordChangeView,
    PasswordResetRequestView, PasswordResetConfirmView, ServerInfoView,
    UserViewSet, GroupViewSet
)

# Create a router for ViewSets
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'groups', GroupViewSet, basename='group')

# Define URL patterns
urlpatterns = [
    # Generic Views
    path('create-user/', CustomUserCreateView.as_view(), name='user-create'),  # User registration
    path('user/<str:sid>/', CustomUserDetailView.as_view(), name='user-detail'),  # User detail/update

    # Authentication Views
    path('login/', LoginView.as_view(), name='login'),  # Custom login
    path('password/change/', PasswordChangeView.as_view(), name='password_change'),  # Password change

    # Password Reset Views
    path('password/reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),  # Request reset link
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),  # Confirm reset

    # Server Info View
    path('server-info/', ServerInfoView.as_view(), name='server-info'),  # Server info from C# client

    # ViewSet Routes
    path('', include(router.urls)),  # Include router URLs for UserViewSet and GroupViewSet
]

