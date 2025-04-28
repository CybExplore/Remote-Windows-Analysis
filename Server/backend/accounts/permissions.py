from rest_framework import permissions
from oauth2_provider.contrib.rest_framework import TokenHasScope
from accounts.models import UserProfile

class IsClientAuthenticated(permissions.BasePermission):
    def has_permission(self, request, view):
        # Check if the request has a valid OAuth2 token
        if not request.auth:
            return False
        try:
            print("\t\t\t Test \t\t\t")
            # Get client_id from the token
            client_id = request.auth.application.client_id
            print(client_id)
            # Verify client_id exists in CustomUser
            UserProfile.objects.get(client_id=client_id)
            return True
        except UserProfile.DoesNotExist:
            return False

class IsOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        return request.user.is_staff or obj == request.user

