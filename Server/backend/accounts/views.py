# accounts/views.py
from rest_framework import generics, status, permissions # type: ignore
from rest_framework.response import Response # type: ignore
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope
from accounts.models import CustomUser
from accounts.serializers import CustomUserSerializer, PasswordChangeSerializer
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import update_session_auth_hash
from django.utils import timezone
from django.contrib.auth.models import Group
import logging

logger = logging.getLogger(__name__)


from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework.views import APIView, status




from accounts.serializers import (
    CustomUserSerializer, GroupSerializer, PasswordChangeSerializer
)

import logging

logger = logging.getLogger(__name__)



class IsOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # Allow safe methods (GET, HEAD, OPTIONS) if user is authenticated
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        # Allow admin full access, or allow users to edit their own profile
        return request.user.is_staff or obj == request.user
    

# accounts/views.py
from rest_framework import generics, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope
from accounts.models import CustomUser
from accounts.serializers import CustomUserSerializer, PasswordChangeSerializer
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import update_session_auth_hash
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

class CustomUserCreateView(generics.CreateAPIView):
    """API endpoint to create a new CustomUser and send credentials via email."""
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [] 

    def perform_create(self, serializer):
        user = serializer.save()
        password = self.request.data.get('password')
        client_id = self.request.data.get('client_id')
        client_secret = self.request.data.get('client_secret')
        message = (
            f"Dear {user.full_name or 'User'},\n\n"
            f"Your account has been created successfully. Here are your credentials:\n"
            f"SID: {user.sid}\n"
            f"Password: {password}\n"
            f"Client ID: {client_id}\n"
            f"Client Secret: {client_secret}\n\n"
            f"Please log in and change your password as soon as possible.\n"
            f"Login URL: {self.request.build_absolute_uri('/login/')}\n\n"
            f"Regards,\nRemote Windows Security Management System"
        )
        try:
            send_mail(subject="Your New Account Credentials", message=message, from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[user.email])
            logger.info(f"Credentials email sent to {user.email} for user {user.sid}")
        except Exception as e:
            logger.error(f"Failed to send email to {user.email}: {str(e)}")


class CustomUserDetailView(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    lookup_field = 'sid'
    permission_classes = [TokenHasReadWriteScope]

class PasswordChangeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            new_password = serializer.validated_data['new_password']
            user.set_password(new_password)
            user.password_changed = True

            if hasattr(user, 'profile'):
                user.profile.last_password_change = timezone.now()
                user.profile.save()

            user.save()

            # Keep user logged in (for React frontend)
            update_session_auth_hash(request, user)

            try:
                subject = "Password Changed Successfully"
                message = (
                    f"Dear {user.full_name or 'User'},\n\n"
                    f"Your password has been changed successfully on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}.\n"
                    f"If you did not initiate this change, please contact support immediately.\n\n"
                    f"Regards,\nRemote Windows Security Management System"
                )
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                logger.info(f"Password change email sent to {user.email} for user {user.sid}")
            except Exception as e:
                logger.error(f"Failed to send password change email: {str(e)}")
            
            # Return user data for frontend
            user_serializer = CustomUserSerializer(user)
            return Response({
                "message": "Password changed successfully",
                "user": user_serializer.data
            }, status=status.HTTP_200_OK)
        

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



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
    # permission_classes = [IsOwnerOrAdmin]

class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.

    Permissions:
    - Requires admin access for all actions.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    # permission_classes = [permissions.IsAdminUser]


class PasswordChangeView(APIView):
    """Handles password changes for a user."""

    permission_classes = [permissions.IsAuthenticated] 

    def get(self, request):
        user = request.user
        serializer = PasswordChangeSerializer(data=request.data)
        return Response(data=request.data, status=status.HTTP_200_OK)

    def post(self, request):
        user = request.user
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})

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

            try:
                subject = "Password Changed Successfully"
                message = (
                    f"Dear {user.full_name or 'User'},\n\n"
                    f"Your password has been changed successfully on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}.\n"
                    f"If you did not initiate this change, please contact support immediately.\n\n"
                    f"Regards,\nRemote Windows Security Management System"
                )
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                logger.info(f"Password change email sent to {user.email} for user {user.sid}")
            except Exception as e:
                logger.error(f"Failed to send password change email to {user.email}: {str(e)}")

            # Return user data for frontend
            user_serializer = CustomUserSerializer(user)
            return Response({
                "message": "Password changed successfully",
                "user": user_serializer.data
            }, status=status.HTTP_200_OK)
        

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class ServerInfoView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        data = request.data
        logger.info(f"Received server info from {request.user.sid}: {data}")
        return Response({"message": "Server info received"}, status=status.HTTP_200_OK)
    


