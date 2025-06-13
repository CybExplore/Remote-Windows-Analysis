from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    FileLogViewSet,
    NetworkLogViewSet,
    ProcessLogViewSet,
    SecurityEventViewSet,
    UserDataViewSet,
)

router = DefaultRouter()
router.register(r"logs", SecurityEventViewSet, basename="logs")
router.register(r"processes", ProcessLogViewSet, basename="processes")
router.register(r"network", NetworkLogViewSet, basename="network")
router.register(r"files", FileLogViewSet, basename="files")
router.register(r"user/profile", UserDataViewSet, basename="user-profile")

urlpatterns = [
    path("", include(router.urls)),
]
