# Semo
from django.urls import include, path

from .views import ClientAuthView, ClientRegisterView, ClientViewSet, UserLoginView

urlpatterns = [
    path("client/", ClientViewSet.as_view({"get": "list"}), name="client-list"),
    path("client/register/", ClientRegisterView.as_view(), name="client-register"),
    path("client/auth/", ClientAuthView.as_view(), name="client-auth"),
    path("auth/login/", UserLoginView.as_view(), name="user-login"),
]
