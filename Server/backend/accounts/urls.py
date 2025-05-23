# accounts/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from accounts import views as accounts_views

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

# Create a router for ViewSets
router = DefaultRouter()
router.register(r'users', accounts_views.UserViewSet, basename='user')
router.register(r'groups', accounts_views.GroupViewSet, basename='group')

# Define URL patterns
urlpatterns = [
    # Generic Views
    path('create-user/', accounts_views.CustomUserCreateView.as_view(), name='user-create'),  # User registration
    path('user/<str:sid>/', accounts_views.CustomUserDetailView.as_view(), name='user-detail'),  # User detail/update
    path('user-profile/<str:sid>/', accounts_views.UserProfileView.as_view(), name='user-profile'),
    
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # User login
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Authentication Views
    path('api/client/auth/', accounts_views.ClientAuthView.as_view(), name='client_auth'),
    # path('login/', accounts_views.LoginView.as_view(), name='login'), 
    path('logout/', accounts_views.LogoutView.as_view(), name='logout'), 
    
    path('password/sync/', accounts_views.PasswordSyncView.as_view(), name='password-sync'),
    path('password/change/', accounts_views.PasswordChangeView.as_view(), name='password_change'),

    # Password Reset Views
    path('password/reset/request/', accounts_views.PasswordResetRequestView.as_view(), name='password-reset-request'),  # Request reset link
    path('password/reset/confirm/', accounts_views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),  # Confirm reset

    # ViewSet Routes
    path('', include(router.urls)), 
]

