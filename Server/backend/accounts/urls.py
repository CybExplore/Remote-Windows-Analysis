# # accounts/urls.py
# from django.urls import path
# from rest_framework_simplejwt.views import (TokenObtainPairView,
#                                             TokenRefreshView)

# from .views import (ClientAuthView, ClientRegisterView, LogListView,
#                     LogReceiverView, RotateClientCredentialsView,
#                     UserProfileDetailView, UserProfileView, UserRegisterView)

# urlpatterns = [
#     path("client/register/", ClientRegisterView.as_view(), name="client_register"),
#     path("user/register/", UserRegisterView.as_view(), name="user_register"),
#     path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
#     path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
#     path("client/auth/", ClientAuthView.as_view(), name="client_auth"),
#     path("logs/", LogReceiverView.as_view(), name="log_receiver"),
#     path("logs/list/", LogListView.as_view(), name="log_list"),
#     path(
#         "client/rotate/",
#         RotateClientCredentialsView.as_view(),
#         name="rotate_credentials",
#     ),
#     path("user/profile/", UserProfileView.as_view(), name="user_profile"),
#     path(
#         "user/profile/detail/",
#         UserProfileDetailView.as_view(),
#         name="user_profile_detail",
#     ),
# ]
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ClientViewSet

router = DefaultRouter()
router.register(r'client', ClientViewSet, basename='client')

urlpatterns = [
    path('', include(router.urls)),
]
