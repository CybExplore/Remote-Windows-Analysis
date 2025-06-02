import logging

from rest_framework import permissions

from accounts.models import UserProfile

logger = logging.getLogger(__name__)


class IsClientAuthenticated(permissions.BasePermission):
    """
    Permission to allow access only if the request has a valid OAuth2 token
    and the client_id is associated with a UserProfile.
    """

    def has_permission(self, request, view):
        if not request.auth:
            logger.warning("No authentication token provided")
            return False
        client_id = request.auth.application.client_id
        if not UserProfile.objects.filter(client_id=client_id).exists():
            logger.warning(f"Invalid client_id: {client_id}")
            return False
        return True


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission to allow:
    - Authenticated users to perform safe methods (GET, HEAD, OPTIONS).
    - Staff or the object owner to perform non-safe methods (POST, PUT, DELETE).
    """

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        return request.user.is_staff or obj == request.user


class AllowCreateOrAuthenticatedRead(permissions.BasePermission):
    """
    Permission to allow:
    - Anyone to access the POST (create) method.
    - Only authenticated users to access GET, HEAD, OPTIONS, PUT, DELETE methods.
    """

    def has_permission(self, request, view):
        if request.method == "POST":
            return True
        return request.user and request.user.is_authenticated
