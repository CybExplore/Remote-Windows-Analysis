# accounts/urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    ClientAuthView, LogReceiverView, RotateClientCredentialsView, LogListView, 
    UserProfileView, UserProfileDetailView, ClientRegisterView
)

urlpatterns = [
    path('client/register/', ClientRegisterView.as_view(), name='client_register'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('client/auth/', ClientAuthView.as_view(), name='client_auth'),
    path('logs/', LogReceiverView.as_view(), name='log_receiver'),
    path('logs/list/', LogListView.as_view(), name='log_list'),
    path('client/rotate/', RotateClientCredentialsView.as_view(), name='rotate_credentials'),
    path('user/profile/', UserProfileView.as_view(), name='user_profile'),
    path('user/profile/detail/', UserProfileDetailView.as_view(), name='user_profile_detail'),

]


