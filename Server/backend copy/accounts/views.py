import logging,json
import secrets
from datetime import timedelta
from django.conf import settings
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
# from oauth2_provider.models import AccessToken, Application
# from oauth2_provider.settings import oauth2_settings
from rest_framework import generics, status, permissions, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from django.db.utils import IntegrityError
from accounts.models import CustomUser, UserProfile
from accounts.serializers import (
    CustomUserSerializer, UserProfileSerializer, GroupSerializer,
    LoginSerializer, PasswordChangeSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer
)
from accounts.permissions import IsClientAuthenticated, IsOwnerOrAdmin
from accounts.notifications import send_password_change_email, get_client_ip
from .oauth_validators import BasicOAuthValidator

logger = logging.getLogger(__name__)

class UserProfileView(APIView):
    permission_classes = [IsClientAuthenticated]

    def get(self, request, sid):
        try:
            profile = CustomUser.objects.select_related('profile').get(sid=sid).profile
            serializer = UserProfileSerializer(profile)
            return Response({"message": "Profile retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"message": "Profile not found", "errors": ["User not found"]}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        try:
            user = CustomUser.objects.get(sid=request.data.get('sid'))
            profile = user.profile
            serializer = UserProfileSerializer(profile, data=request.data.get('profile', {}), partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Profile updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found", "errors": ["User not found"]}, status=status.HTTP_404_NOT_FOUND)

# class CustomUserCreateView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         logger.debug(f"Received create user request: {request.data}")
#         serializer = CustomUserSerializer(data=request.data)
#         if serializer.is_valid():
#             try:
#                 temp_password = secrets.token_urlsafe(16)
#                 request.data['password'] = temp_password
#                 user = serializer.save()
#                 profile_data = request.data.get('profile', {})
#                 client_id = profile_data.get('client_id')

#                 token_generator = PasswordResetTokenGenerator()
#                 token = token_generator.make_token(user)
#                 uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
#                 reset_url = f"{settings.FRONTEND_URL}/password/reset/confirm/{uidb64}/{token}/"

#                 message = (
#                     f"Dear {user.full_name or 'User'},\n\n"
#                     f"Your account has been created. Please reset your password:\n"
#                     f"Reset URL: {reset_url}\n\n"
#                     f"Client ID: {client_id}\n\n"
#                     f"Regards,\nRemote Windows Security Management System"
#                 )
#                 send_mail(
#                     subject="Your New Account",
#                     message=message,
#                     from_email=settings.DEFAULT_FROM_EMAIL,
#                     recipient_list=[user.email],
#                     fail_silently=False,
#                 )
#                 logger.info(f"Account creation email sent to {user.email} for user {user.sid}")
#                 return Response({
#                     "message": "User created successfully",
#                     "data": {
#                         "sid": user.sid,
#                         "email": user.email,
#                         "client_id": user.profile.client_id if user.profile else None
#                     }
#                 }, status=status.HTTP_201_CREATED)
#             except IntegrityError as e:
#                 logger.error(f"Database integrity error during user creation: {str(e)}")
#                 return Response({
#                     "message": "User creation failed",
#                     "errors": ["A profile for this user already exists or another database conflict occurred"]
#                 }, status=status.HTTP_400_BAD_REQUEST)
#             except Exception as e:
#                 logger.error(f"Error creating user: {str(e)}")
#                 return Response({"message": "User creation failed", "errors": [str(e)]}, status=status.HTTP_400_BAD_REQUEST)
#         logger.warning(f"User creation validation failed: {serializer.errors}")
#         return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from .serializers import CustomUserSerializer
import logging
import secrets

logger = logging.getLogger(__name__)

class CustomUserCreateView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logger.debug(f"Received create user request: {request.data}")
        print(f"Received create user request: {request.data}")
        # Generate temp_password once
        temp_password = secrets.token_urlsafe(16)
        data = request.data.copy()  # Make mutable copy
        data['password'] = temp_password  # Set password for serializer

        serializer = CustomUserSerializer(data=data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                profile_data = request.data.get('profile', {})
                client_id = profile_data.get('client_id', '')
                client_secret = profile_data.get('client_secret', '')

                # Send email with temp_password
                message = (
                    f"Dear {user.full_name or 'User'},\n\n"
                    f"Your account has been created.\n"
                    f"Email: {user.email}\n"
                    f"Temporary Password: {temp_password}\n"
                    f"Client ID: {client_id}\n"
                    f"Client Secret: {client_secret}\n\n"
                    f"Please use these credentials to log in and change your password.\n\n"
                    f"Regards,\nRemote Windows Security Management System"
                )
                send_mail(
                    subject="Your New Account",
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                logger.info(f"Account creation email sent to {user.email} for user {user.sid}")
                print(f"Account creation email sent to {user.email} for user {user.sid}")
                return Response({
                    "message": "User created successfully",
                    "data": {
                        "sid": user.sid,
                        "email": user.email,
                        "client_id": user.profile.client_id if user.profile else None
                    }
                }, status=status.HTTP_201_CREATED)
            except IntegrityError as e:
                logger.error(f"Database integrity error during user creation: {str(e)}")
                print(f"Database integrity error during user creation: {str(e)}")
                return Response({
                    "message": "User creation failed",
                    "errors": ["A profile for this user already exists or another database conflict occurred"]
                }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Error creating user: {str(e)}")
                print(f"Error creating user: {str(e)}")
                return Response({"message": "User creation failed", "errors": [str(e)]}, status=status.HTTP_400_BAD_REQUEST)
        logger.warning(f"User creation validation failed: {serializer.errors}")
        print(f"User creation validation failed: {serializer.errors}")
        return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['GET'])
def restricted_view(request):
    if not request.user.password_changed:
        return Response({"message": "Access denied", "errors": ["Please change your password first"]}, status=status.HTTP_403_FORBIDDEN)
    return Response({"message": "Access granted", "data": {}}, status=status.HTTP_200_OK)

class CustomUserDetailView(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    lookup_field = 'sid'
    permission_classes = [permissions.IsAuthenticated]

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({"message": "User retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response({"message": "User updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class UserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.filter(is_active=True).select_related('profile')
    serializer_class = CustomUserSerializer
    lookup_field = 'sid'
    permission_classes = [IsOwnerOrAdmin]

class GroupViewSet(viewsets.ModelViewSet):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAdminUser]

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response({"message": "Groups retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({"message": "Group retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            self.perform_create(serializer)
            return Response({"message": "Group created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response({"message": "Group updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Group deleted successfully", "data": {}}, status=status.HTTP_204_NO_CONTENT)

# class LoginView(APIView):
#     permission_classes = []
#     serializer_class = LoginSerializer
#     # throttle_scope = 'login'

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data, context={'request': request})
#         if serializer.is_valid():
#             user = serializer.validated_data['user']
#             login(request, user)
#             try:
#                 profile = user.profile
#                 profile.last_logon = timezone.now()
#                 profile.last_login_ip = get_client_ip(request)
#                 profile.logon_count += 1
#                 profile.save()

#                 # app, created = Application.objects.get_or_create(
#                 #     name="React Frontend",
#                 #     defaults={
#                 #         'client_id': 'react_client_id',
#                 #         'client_secret': 'react_client_secret',
#                 #         'client_type': Application.CLIENT_CONFIDENTIAL,
#                 #         'authorization_grant_type': Application.GRANT_PASSWORD,
#                 #     }
#                 # )
#                 # if created:
#                 #     logger.info(f"OAuth application '{app.name}' created successfully.")

#                 # token = AccessToken.objects.create(
#                 #     user=user,
#                 #     application=app,
#                 #     scope='read write',
#                 #     expires=timezone.now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS),
#                 #     # token=generate_token()
#                 # )

#                 user_serializer = CustomUserSerializer(user)
#                 profile_serializer = UserProfileSerializer(profile)
#                 response_data = {
#                     "message": "Login successful",
#                     "data": {
#                         "access_token": token.token,
#                         "token_type": "Bearer",
#                         "expires_in": oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
#                         "scope": token.scope,
#                         "user": {
#                             **user_serializer.data,
#                             "profile": profile_serializer.data
#                         }
#                     }
#                 }
#                 logger.info(f"User {user.sid} logged in successfully.")
#                 return Response(response_data, status=status.HTTP_200_OK)
#             except Exception as e:
#                 logger.error(f"Error generating token for user {user.sid}: {str(e)}")
#                 return Response(
#                     {"message": "Internal server error", "errors": ["Please try again later"]},
#                     status=status.HTTP_500_INTERNAL_SERVER_ERROR
#                 )
#         logger.warning(f"Login failed due to validation errors: {serializer.errors}")
#         return Response(
#             {"message": "Validation failed", "errors": serializer.errors},
#             status=status.HTTP_400_BAD_REQUEST
#         )


# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from oauthlib.oauth2 import WebApplicationServer
from .oauth_validators import BasicOAuthValidator
from .serializers import LoginSerializer

class LoginView(APIView):
    permission_classes = []  # Allow unauthenticated access
    serializer_class = LoginSerializer

    def __init__(self):
        self.oauth_server = WebApplicationServer(BasicOAuthValidator())

    def post(self, request):
        # Validate credentials
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if not serializer.is_valid():
            return Response({
                "message": "Login failed",
                "errors": serializer.errors
            }, status=400)

        user = serializer.validated_data['user']

        # Generate OAuth2 token
        token = self.oauth_server.create_token_response(
            uri=request.build_absolute_uri(),
            http_method='POST',
            body={
                'grant_type': 'password',
                'username': user.sid,  # Always use SID for token generation
                'password': request.data['password'],
                'client_id': request.data.get('client_id', 'unsecured_client'),  # From C# client
                'client_secret': request.data.get('client_secret', 'unsecured_secret')  # From C# client
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        return Response({
            "message": "Login successful",
            "data": {
                "access_token": token['access_token'],
                "token_type": "Bearer",
                "expires_in": 3600,
                "sid": user.sid,  # For C# client
                "email": user.email  # For React frontend
            }
        })
    


class PasswordSyncView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        try:
            # Note: Storing plain password is insecure; consider a secure token-based approach
            return Response({
                "message": "Password retrieved successfully",
                "password": user.password  # This is a placeholder; actual implementation needs security
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error syncing password for user {user.sid}: {str(e)}")
            return Response({"message": "Password sync failed", "errors": [str(e)]}, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    throttle_scope = 'password_change'

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            logger.warning(f"Password change validation failed for user {request.user.sid}: {serializer.errors}")
            return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        serializer.save()
        update_session_auth_hash(request, user)
        logger.info(f"User {user.sid} successfully changed their password.")

        try:
            send_password_change_email(user, request)
        except Exception as e:
            logger.error(f"Failed to send password change email: {str(e)}")

        return Response({
            "message": "Password changed successfully",
            "data": {
                "next_steps": [
                    "You have been automatically logged in with your new password.",
                    "Update any other devices/systems where you use this password."
                ]
            }
        }, status=status.HTTP_200_OK)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer
    throttle_scope = 'password_reset'

    def get(self, request):
        serializer = self.serializer_class()
        return Response({"message": "Password reset form", "data": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.context['user']
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = f"{settings.FRONTEND_URL}/password/reset/confirm/{uidb64}/{token}/"

            try:
                send_mail(
                    subject="Password Reset Request",
                    message=(
                        f"Dear {user.full_name or 'User'},\n\n"
                        f"You have requested to reset your password. Click the link below to proceed:\n"
                        f"{reset_url}\n\n"
                        f"If you did not request this, please ignore this email or contact support.\n\n"
                        f"Regards,\nRemote Windows Security Management System"
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                logger.info(f"Password reset email sent to {user.email} for user {user.sid}")
                return Response({"message": "Password reset link sent to your email", "data": {}}, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
                return Response({"message": "Failed to send reset email", "errors": [str(e)]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            uidb64 = serializer.validated_data['uidb64']
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            try:
                uid = urlsafe_base64_decode(uidb64).decode()
                user = CustomUser.objects.get(pk=uid)
            except CustomUser.DoesNotExist:
                return Response({"message": "Invalid user", "errors": ["User not found"]}, status=status.HTTP_400_BAD_REQUEST)
            except (ValueError, TypeError):
                return Response({"message": "Invalid UID", "errors": ["Invalid UID format"]}, status=status.HTTP_400_BAD_REQUEST)

            if default_token_generator.check_token(user, token):
                user.set_password(new_password)
                user.save()
                try:
                    send_mail(
                        subject="Password Reset Successful",
                        message=(
                            f"Dear {user.full_name or 'User'},\n\n"
                            f"Your password has been reset successfully on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}.\n"
                            f"If you did not perform this action, please contact support immediately.\n\n"
                            f"Regards,\nRemote Windows Security Management System"
                        ),
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
                    logger.info(f"Password reset confirmation email sent to {user.email}")
                except Exception as e:
                    logger.error(f"Failed to send password reset confirmation email: {str(e)}")
                return Response({"message": "Password reset successful", "data": {}}, status=status.HTTP_200_OK)
            return Response({"message": "Invalid token", "errors": ["Invalid or expired token"]}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            AccessToken.objects.filter(user=request.user, token=request.auth).delete()
            logout(request)
            logger.info(f"User {request.user.sid} logged out successfully")
            return Response({"message": "Logged out successfully", "data": {}}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during logout for {request.user.sid}: {str(e)}")
            return Response({"message": "Failed to logout", "errors": [str(e)]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# TOKEN
from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from django.http import JsonResponse
from django.views import View

from .oauth_validators import BasicOAuthValidator

class TokenView(View):
    def __init__(self, **kwargs):
        self.validator = BasicOAuthValidator()
        self.server = WebApplicationServer(self.validator)
        super().__init__(**kwargs)

    def post(self, request):
        uri = request.build_absolute_uri()
        headers = request.headers
        body = request.body.decode('utf-8')
        token_response, headers, status_code = self.server.create_token_response(
            uri=uri,
            http_method='POST',
            body=body,
            headers=headers
        )
        return JsonResponse(json.loads(token_response), status=status_code)



