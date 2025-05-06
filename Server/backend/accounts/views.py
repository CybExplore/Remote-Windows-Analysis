# accounts/views.py
import logging
import secrets
from datetime import timedelta
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from oauth2_provider.models import AccessToken, Application
from oauth2_provider.settings import oauth2_settings
from datetime import timedelta
from django.conf import settings
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.generic.base import RedirectView
from oauth2_provider.models import AccessToken, Application
from oauth2_provider.settings import oauth2_settings
from rest_framework import generics, status, permissions, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework.decorators import api_view
from django.db.utils import IntegrityError
from accounts.models import CustomUser, UserProfile
from accounts.serializers import (
    CustomUserSerializer, UserProfileSerializer, GroupSerializer,
    LoginSerializer, PasswordChangeSerializer, EmailVerificationSerializer,
    PasswordResetConfirmSerializer, PasswordResetRequestSerializer
)
from accounts.permissions import IsClientAuthenticated, IsOwnerOrAdmin
from accounts.notifications import send_password_change_email, send_verification_email, get_client_ip

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

class CustomUserCreateView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logger.debug(f"Received create user request: {request.data}")
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                temp_password = secrets.token_urlsafe(16)
                request.data['password'] = temp_password
                user = serializer.save()
                profile_data = request.data.get('profile', {})
                client_id = profile_data.get('client_id')
                client_secret = profile_data.get('client_secret')

                token_generator = PasswordResetTokenGenerator()
                token = token_generator.make_token(user)
                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                reset_url = f"{settings.FRONTEND_URL}/password/reset/confirm/{uidb64}/{token}/"

                message = (
                    f"Dear {user.full_name or 'User'},\n\n"
                    f"Your account has been created. Please reset your password:\n"
                    f"Reset URL: {reset_url}\n\n"
                    f"Client ID: {client_id}\n"
                    f"Client Secret: {client_secret}\n"
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
                return Response({
                    "message": "User creation failed",
                    "errors": ["A profile for this user already exists or another database conflict occurred"]
                }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Error creating user: {str(e)}")
                return Response({"message": "User creation failed", "errors": [str(e)]}, status=status.HTTP_400_BAD_REQUEST)
        logger.warning(f"User creation validation failed: {serializer.errors}")
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




class LoginView(APIView):
    permission_classes = []
    serializer_class = LoginSerializer
    throttle_scope = 'login'

    @transaction.atomic
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if not serializer.is_valid():
            return Response(
                {"message": "Validation failed", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.validated_data['user']
        
        try:
            # Update user profile login info
            if hasattr(user, 'profile'):
                profile = user.profile
                profile.last_logon = timezone.now()
                profile.last_login_ip = request.META.get('REMOTE_ADDR', '')
                profile.logon_count += 1
                profile.save()

            # Get or create OAuth application
            app, created = Application.objects.get_or_create(
                name="React Frontend",
                defaults={
                    'client_id': 'react_client_id',
                    'client_secret': 'react_client_secret',
                    'client_type': Application.CLIENT_CONFIDENTIAL,
                    'authorization_grant_type': Application.GRANT_PASSWORD,
                }
            )

            # Delete existing tokens to prevent duplicates
            AccessToken.objects.filter(user=user, application=app).delete()
            
            # Generate secure token
            token = secrets.token_urlsafe(50)
            
            # Create new access token
            access_token = AccessToken.objects.create(
                user=user,
                application=app,
                token=token,
                expires=timezone.now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS),
                scope='read write'
            )

            return Response({
                "message": "Login successful",
                "data": {
                    "access_token": access_token.token,
                    "token_type": "Bearer",
                    "expires_in": oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
                    "user": {
                        "sid": user.sid,
                        "email": user.email,
                        "full_name": user.full_name
                    }
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Login error for {user.sid}: {str(e)}", exc_info=True)
            return Response(
                {"message": "Login failed", "errors": ["Internal server error"]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request):
        return Response(
            {"detail": "POST method required for login"},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )
    

# class PasswordChangeView(APIView):
#     permission_classes = [permissions.IsAuthenticated]
#     throttle_scope = 'password_change'

#     def post(self, request):
#         serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
#         if not serializer.is_valid():
#             logger.warning(f"Password change validation failed for user {request.user.sid}: {serializer.errors}")
#             return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

#         user = request.user
#         serializer.save()
#         update_session_auth_hash(request, user)
#         logger.info(f"User {user.sid} successfully changed their password.")

#         try:
#             send_password_change_email(user, request)
#         except Exception as e:
#             logger.error(f"Failed to send password change email: {str(e)}")

#         return Response({
#             "message": "Password changed successfully",
#             "data": {
#                 "next_steps": [
#                     "You have been automatically logged in with your new password.",
#                     "Update any other devices/systems where you use this password."
#                 ]
#             }
#         }, status=status.HTTP_200_OK)


from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.schemas import get_schema_view
from django.contrib.auth import update_session_auth_hash
from django.utils import timezone
from .serializers import PasswordChangeSerializer
import logging
from django.urls import reverse

logger = logging.getLogger(__name__)

class PasswordChangeView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    throttle_scope = 'password_change'
    renderer_classes = [JSONRenderer, TemplateHTMLRenderer]
    template_name = 'rest_framework/password_change.html'  # DRF's default template

    def get(self, request):
        user = request.user
        context = {
            'user': {
                'email': user.email,
                'full_name': user.full_name,
                'can_change_password': getattr(user.profile, 'user_may_change_password', False)
            },
            'password_policy': {
                'min_length': 8,
                'requires_upper': True,
                'requires_lower': True,
                'requires_number': True,
                'requires_special': True
            },
            'post_url': reverse('password_change'),
            'method': 'POST',
            'csrf_token': request.META.get('CSRF_COOKIE', '')
        }

        if request.accepted_renderer.format == 'html':
            return Response(context)
        
        return Response({
            'form': {
                'fields': [
                    {'name': 'old_password', 'type': 'password', 'required': True},
                    {'name': 'new_password', 'type': 'password', 'required': True},
                    {'name': 'confirm_password', 'type': 'password', 'required': True}
                ],
                'action': context['post_url'],
                'method': context['method']
            },
            'user': context['user'],
            'password_policy': context['password_policy']
        })

    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if not serializer.is_valid():
            logger.warning(f"Password change failed for {request.user.email}")
            
            if request.accepted_renderer.format == 'html':
                return Response(
                    {'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response(
                {'status': 'error', 'errors': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = request.user
            serializer.save()
            update_session_auth_hash(request, user)
            
            if hasattr(user, 'profile'):
                user.profile.password_last_set = timezone.now()
                user.profile.save()

            if request.accepted_renderer.format == 'html':
                return Response(
                    {'success': 'Password changed successfully'},
                    template_name='rest_framework/password_change_success.html'
                )
            
            return Response({
                'status': 'success',
                'message': 'Password changed successfully'
            })
            
        except Exception as e:
            logger.error(f"Password change error: {str(e)}")
            if request.accepted_renderer.format == 'html':
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            return Response(
                {'status': 'error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class SendEmailVerificationView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found", "errors": ["No user found with this email"]}, status=status.HTTP_400_BAD_REQUEST)

        send_verification_email(user)
        return Response({"message": "Verification email sent", "data": {}}, status=status.HTTP_200_OK)

class EmailVerificationView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.context['user']
            user.is_active = True
            user.email_verified = True
            user.save()
            return Response({"message": "Email successfully verified", "data": {}}, status=status.HTTP_200_OK)
        return Response({"message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class EmailVerificationRedirectView(RedirectView):
    permanent = False

    def get_redirect_url(self, *args, **kwargs):
        uidb64 = kwargs.get('uidb64')
        token = kwargs.get('token')
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                user.is_active = True
                user.email_verified = True
                user.save()
                return f"{settings.FRONTEND_URL}/email-verified/success"
        except Exception:
            pass
        return f"{settings.FRONTEND_URL}/email-verified/failure"

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


