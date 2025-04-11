# accounts/views.py
from rest_framework import generics, status, permissions, viewsets
from accounts.notifications import send_password_change_email
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import login
from django.utils.timezone import now
from datetime import timedelta
import random
import logging

from oauth2_provider.models import AccessToken, Application
from oauth2_provider.settings import oauth2_settings

from .serializers import LoginSerializer, CustomUserSerializer
from .models import CustomUser

logger = logging.getLogger(__name__)

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.utils.timezone import now as timezone_now
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope

from accounts.models import *
from accounts.serializers import *
from django.contrib.auth.models import Group
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import login, update_session_auth_hash, logout
from django.utils import timezone

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model

from oauth2_provider.models import AccessToken, Application
from oauth2_provider.settings import oauth2_settings

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from accounts.permissions_a import IsOwnerOrReadOnly
from datetime import timedelta
import logging
import random

logger = logging.getLogger(__name__)

class IsOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        return request.user.is_staff or obj == request.user

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
            raise  # Re-raise to trigger a 500 response in post()

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            self.perform_create(serializer)
            user_serializer = CustomUserSerializer(serializer.instance)
            return Response({
                "message": "User created successfully",
                "user": user_serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            print(serializer.errors)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





class LoginView(APIView):
    """Custom login endpoint for users with SID or email address and password."""
    permission_classes = [AllowAny]  # Allow all requests to this endpoint
    serializer_class = LoginSerializer

    def post(self, request):
        # Validate the incoming data using the serializer
        serializer = self.serializer_class(data=request.data, context={'request': request})

        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)  # Log the user in

            try:
                # Get or create OAuth2 application for React Frontend
                app, created = Application.objects.get_or_create(
                    name="React Frontend",
                    defaults={
                        'client_id': 'react_client_id',
                        'client_secret': 'react_client_secret',
                        'client_type': Application.CLIENT_CONFIDENTIAL,  # Confidential client type
                        'authorization_grant_type': Application.GRANT_PASSWORD,  # Password grant type
                    }
                )

                if created:
                    logger.info(f"OAuth application '{app.name}' created successfully.")

                # Generate access token
                token = AccessToken.objects.create(
                    user=user,
                    application=app,
                    scope='read write',
                    expires=now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS),
                    token=''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=40))
                )

                # Serialize user data
                user_serializer = CustomUserSerializer(user)
                response_data = {
                    "message": "Login successful",
                    "access_token": token.token,
                    "token_type": "Bearer",
                    "expires_in": oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
                    "scope": token.scope,
                    "user": user_serializer.data,
                }

                # Log successful login
                logger.info(f"User {user.sid} logged in successfully.")
                return Response(response_data, status=status.HTTP_200_OK)

            except Exception as e:
                # Log any token generation errors
                logger.error(f"Error generating token for user {user.sid}: {str(e)}")
                return Response(
                    {"error": "Internal server error. Please try again later."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        # Handle validation errors
        logger.warning(f"Login failed due to validation errors: {serializer.errors}")
        return Response(
            {"error": serializer.errors, "message": "Validation failed."},
            status=status.HTTP_400_BAD_REQUEST,
        )

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

@api_view(['GET'])
def restricted_view(request):
    if not request.user.password_changed:
        return Response({"error": "Please change your password first."}, status=status.HTTP_403_FORBIDDEN)
    # Proceed with the normal logic
    return Response({"message": "Access granted!"}, status=status.HTTP_200_OK)


class CustomUserDetailView(generics.RetrieveUpdateAPIView):
    """API endpoint to retrieve or update a CustomUser."""
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    lookup_field = 'sid'
    # permission_classes = [TokenHasReadWriteScope]
    permission_classes = [permissions.IsAuthenticated]


    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            "message": "User retrieved successfully",
            "user": serializer.data
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response({
                "message": "User updated successfully",
                "user": serializer.data
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserViewSet(viewsets.ModelViewSet):
    """API endpoint that allows users to be viewed or edited."""
    queryset = CustomUser.objects.filter(is_active=True)
    serializer_class = CustomUserSerializer
    lookup_field = 'sid'

    permission_classes = [IsOwnerOrAdmin]
    # permission_classes = [IsOwnerOrAdmin, IsOwnerOrReadOnly]
    # permission_classes = [permissions.IsAuthenticatedOrReadOnly,
    #                   IsOwnerOrReadOnly]
    # permission_classes = [permissions.IsAuthenticated]

    # def list(self, request, *args, **kwargs):
    #     queryset = self.filter_queryset(self.get_queryset())
    #     serializer = self.get_serializer(queryset, many=True)
    #     return Response({
    #         "message": "Users retrieved successfully",
    #         "users": serializer.data
    #     }, status=status.HTTP_200_OK)

    # def retrieve(self, request, *args, **kwargs):
    #     instance = self.get_object()
    #     serializer = self.get_serializer(instance)
    #     return Response({
    #         "message": "User retrieved successfully",
    #         "user": serializer.data
    #     }, status=status.HTTP_200_OK)

    # def create(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     if serializer.is_valid():
    #         self.perform_create(serializer)
    #         return Response({
    #             "message": "User created successfully",
    #             "user": serializer.data
    #         }, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # def update(self, request, *args, **kwargs):
    #     partial = kwargs.pop('partial', False)
    #     instance = self.get_object()
    #     serializer = self.get_serializer(instance, data=request.data, partial=partial)
    #     if serializer.is_valid():
    #         self.perform_update(serializer)
    #         return Response({
    #             "message": "User updated successfully",
    #             "user": serializer.data
    #         }, status=status.HTTP_200_OK)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # def destroy(self, request, *args, **kwargs):
    #     instance = self.get_object()
    #     self.perform_destroy(instance)
    #     return Response({"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

class GroupViewSet(viewsets.ModelViewSet):
    """API endpoint that allows groups to be viewed or edited."""
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAdminUser]

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "message": "Groups retrieved successfully",
            "groups": serializer.data
        }, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            "message": "Group retrieved successfully",
            "group": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            self.perform_create(serializer)
            return Response({
                "message": "Group created successfully",
                "group": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response({
                "message": "Group updated successfully",
                "group": serializer.data
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Group deleted successfully"}, status=status.HTTP_204_NO_CONTENT)




logger = logging.getLogger(__name__)

class PasswordChangeView(APIView):
    """Secure password change endpoint with audit logging."""
    permission_classes = [permissions.IsAuthenticated]
    throttle_scope = 'password_change'

    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'request': request}
        )
        
        # Check if serializer is valid
        if not serializer.is_valid():
            logger.warning(
                f"Password change validation failed for user {request.user.id}: "
                f"{serializer.errors}"
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        data = serializer.validated_data

        # Change user's password
        user.set_password(data['new_password'])
        user.password_changed = True
        user.save()

        # Maintain session
        update_session_auth_hash(request, user)

        # Log password change
        logger.info(f"User {user.id} successfully changed their password.")

        # Send email notification
        try:
            send_password_change_email(user, request)
        except Exception as e:
            logger.error(f"Failed to send password change email: {str(e)}", exc_info=True)

        return Response(
            {
                'message': 'Password changed successfully',
                'next_steps': [
                    'You have been automatically logged in with your new password.',
                    'Update any other devices/systems where you use this password.'
                ]
            },
            status=status.HTTP_200_OK
        )


class PasswordResetRequestView(APIView):
    """Request a password reset link via email."""
    permission_classes = []
    serializer_class = PasswordResetRequestSerializer

    def get(self, request):
        # snippests = CustomUser.objects.all()
        serializer = self.serializer_class()
        return Response(data=serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.context['user']
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

            # Use FRONTEND_URL for the reset link
            reset_url = f"{settings.FRONTEND_URL}/password/reset/confirm/{uidb64}/{token}/"

            try:
                subject = "Password Reset Request"
                message = (
                    f"Dear {user.full_name or 'User'},\n\n"
                    f"You have requested to reset your password. Click the link below to proceed:\n"
                    f"{reset_url}\n\n"
                    f"If you did not request this, please ignore this email or contact support.\n\n"
                    f"Regards,\nRemote Windows Security Management System"
                )
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                logger.info(f"Password reset email sent to {user.email} for user {user.sid}")
                return Response({"message": "Password reset link sent to your email"}, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
                return Response({"error": "Failed to send reset email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    """Confirm password reset with token and set new password."""
    permission_classes = []
    # serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            uidb64 = serializer.validated_data['uidb64']
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']

            try:
                # Decode user ID
                uid = urlsafe_base64_decode(uidb64).decode()
                user = CustomUser.objects.get(pk=uid)

                # Check token validity
                if default_token_generator.check_token(user, token):
                    # Set new password
                    user.set_password(new_password)
                    user.save()
                    subject = "Password Reset Successful"
                    message = (
                        f"Dear {user.full_name or 'User'},\n\n"
                        f"Your password has been reset successfully on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}.\n"
                        f"If you did not perform this action, please contact support immediately.\n\n"
                        f"Regards,\nRemote Windows Security Management System"
                    )
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
                
                    return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)
                
                else:
                    return Response(
                        {"error": "Invalid or expired token."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except (CustomUser.DoesNotExist, ValueError, TypeError):
                return Response(
                    {"error": "Invalid user."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ServerInfoView(APIView):
    """Receive server info from authenticated clients."""
    parser_classes = [IsOwnerOrAdmin]
    # permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def post(self, request):
        data = request.data
        logger.info(f"Received server info from {request.user.sid}: {data}")
        return Response({"message": "Server info received", "data": data}, status=status.HTTP_200_OK)

class LogoutView(APIView):
    """Logout endpoint to invalidate the user's token."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            # Delete the user's access token (OAuth2)
            AccessToken.objects.filter(user=request.user, token=request.auth).delete()
            logout(request)  # Clear session if used
            logger.info(f"User {request.user.sid} logged out successfully")
            return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during logout for {request.user.sid}: {str(e)}")
            return Response({"error": "Failed to logout"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class ServerInfoView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ServerInfoSerializer(data=request.data)
        if serializer.is_valid():
            try:
                client = CustomUser.objects.get(sid=serializer.validated_data["client"].sid)
                serializer.save(client=client)
                return Response({"message": "Server info saved"}, status=status.HTTP_201_CREATED)
            except CustomUser.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SecurityEventView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = SecurityEventSerializer(data=request.data)
        if serializer.is_valid():
            try:
                client = CustomUser.objects.get(sid=serializer.validated_data["client"].sid)
                serializer.save(client=client)
                return Response({"message": "Event saved"}, status=status.HTTP_201_CREATED)
            except CustomUser.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

