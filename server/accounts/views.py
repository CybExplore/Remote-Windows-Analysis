from django.shortcuts import render
from django.contrib.auth.models import Group
from django.contrib.auth import authenticate, update_session_auth_hash
from django_filters.rest_framework import DjangoFilterBackend
from accounts.models import CustomUser

from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework.views import APIView, status
from rest_framework.generics import (
    RetrieveUpdateDestroyAPIView, ListAPIView,
    ListCreateAPIView, CreateAPIView, RetrieveAPIView, RetrieveDestroyAPIView, 
    RetrieveUpdateAPIView, UpdateAPIView, DestroyAPIView
)

from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope, TokenHasScope


from accounts.serializers import (
    CustomUserSerializer, GroupSerializer, PasswordChangeSerializer
)

class IsOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # Allow safe methods (GET, HEAD, OPTIONS) if user is authenticated
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        # Allow admin full access, or allow users to edit their own profile
        return request.user.is_staff or obj == request.user
    

class UserList(ListCreateAPIView):
    permission_classes = [permissions.IsAdminUser, TokenHasReadWriteScope]
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

class UserDetails(RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

# ViewSets define the view behavior.
class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.

    Permissions:
    - Requires authentication for all actions.
    - Only active users are included in the queryset.
    """
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    lookup_field = 'sid'
    permission_classes = [IsOwnerOrAdmin]

class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.

    Permissions:
    - Requires admin access for all actions.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    # permission_classes = [permissions.IsAdminUser]


class GroupList(ListAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasScope]
    required_scopes = ['groups']
    queryset = Group.objects.all()
    serializer_class = GroupSerializer

class PasswordChangeView(APIView):
    """Handles password changes for a user."""

    permission_classes = [permissions.IsAuthenticated] 

    def get(self, request):
        user = request.user
        serializer = PasswordChangeSerializer(data=request.data)
        return Response(data=request.data, status=status.HTTP_200_OK)

    def post(self, request):
        user = request.user
        serializer = PasswordChangeSerializer(data=request.data)

        if serializer.is_valid():
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']

            # Check if the old password is correct
            if not user.check_password(old_password):
                return Response({"old_password": "Incorrect password"}, status=status.HTTP_400_BAD_REQUEST)

            # Update the user's password
            user.set_password(new_password)
            user.save()

            # Update session to prevent the user from being logged out after password change
            update_session_auth_hash(request, user)

            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


