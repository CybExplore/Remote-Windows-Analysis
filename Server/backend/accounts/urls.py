# accounts/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from accounts import views as accounts_views

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
    
    # Authentication Views
    path('login/', accounts_views.LoginView.as_view(), name='login'), 
    path('logout/', accounts_views.LogoutView.as_view(), name='logout'),
    path('send-verification/', accounts_views.SendEmailVerificationView.as_view(), name='send-verification'),
    path('verify-email/', accounts_views.EmailVerificationView.as_view(), name='verify-email'),
    path('verify-email/<uidb64>/<token>/', accounts_views.EmailVerificationRedirectView.as_view(), name='verify-email-redirect'),

    path('password/change/', accounts_views.PasswordChangeView.as_view(), name='password_change'),

    # Password Reset Views
    path('password/reset/request/', accounts_views.PasswordResetRequestView.as_view(), name='password-reset-request'),  # Request reset link
    path('password/reset/confirm/', accounts_views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),  # Confirm reset

    # ViewSet Routes
    path('', include(router.urls)), 
    path('token/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]

