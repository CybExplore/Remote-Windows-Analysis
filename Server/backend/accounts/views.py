import logging,json
import secrets, uuid
from datetime import timedelta
from django.conf import settings
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import generics, status, permissions, viewsets
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from django.db.utils import IntegrityError
from accounts.models import CustomUser, UserProfile, Client, LogEntry
from accounts.serializers import (
    CustomUserSerializer, UserProfileSerializer, GroupSerializer,
    LoginSerializer, PasswordChangeSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer
)
from accounts.permissions import IsClientAuthenticated, IsOwnerOrAdmin
from accounts.notifications import send_password_change_email, get_client_ip

from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password, make_password

from .tasks import detect_anomalies
from django.utils import timezone


logger = logging.getLogger(__name__)


class ClientRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        client_id = request.data.get('client_id')
        secret_id = request.data.get('secret_id')
        sid = request.data.get('sid')
        user_email = request.data.get('user_email')

        if not all([client_id, secret_id, sid, user_email]):
            return Response({'error': 'Missing required fields'}, status=400)

        try:
            user = CustomUser.objects.get(email=user_email)
            client, created = Client.objects.get_or_create(
                client_id=client_id,
                sid=sid,
                user=user,
                defaults={'secret_id': Client().set_secret_id(secret_id)}
            )
            if not created:
                return Response({'error': 'Client with this client_id or sid already exists'}, status=400)

            return Response({
                'status': 'success',
                'client_id': str(client.client_id),
                'sid': client.sid,
                'user_email': user.email
            })
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=400)



class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        client_id = request.data.get('client_id')
        user_data = request.data.get('user_data', {})
        try:
            client = Client.objects.get(client_id=client_id, user=request.user)
            user = request.user
            profile, created = UserProfile.objects.get_or_create(user=user)

            # Update profile with user data
            account_info = user_data.get('account_info', {})
            profile.domain = account_info.get('Domain')
            profile.account_type = account_info.get('AccountType')
            profile.local_account = account_info.get('LocalAccount', True)
            profile.password_changeable = account_info.get('PasswordChangeable', True)
            profile.password_expires = account_info.get('PasswordExpires', False)
            profile.password_required = account_info.get('PasswordRequired', True)
            profile.status = account_info.get('Status')
            profile.groups = user_data.get('groups', [])
            profiles = user_data.get('profiles', [])
            if profiles:
                profile.profile_local_path = profiles[0].get('LocalPath')
                profile_last_use_time = profiles[0].get('LastUseTime')
                profile.profile_last_use_time = timezone.datetime.fromisoformat(profile_last_use_time) if profile_last_use_time else None
                profile.profile_status = profiles[0].get('Status')
            profile.sessions = user_data.get('sessions', [])
            profile.environment = user_data.get('environment', {})
            profile.save()

            # Update CustomUser fields
            user.sid = account_info.get('SID')
            user.full_name = account_info.get('FullName')
            user.save()

            return Response({
                'status': 'success',
                'message': 'Profile updated' if not created else 'Profile created'
            })
        except Client.DoesNotExist:
            return Response({'error': 'Client not found'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=400)


# accounts/views.py
class UserProfileDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = request.user.profile
        return Response({
            'email': request.user.email,
            'sid': request.user.sid,
            'full_name': request.user.full_name,
            'domain': profile.domain,
            'account_type': profile.account_type,
            'groups': profile.groups,
            'sessions': profile.sessions,
            'profile_local_path': profile.profile_local_path,
            'profile_last_use_time': profile.profile_last_use_time.isoformat() if profile.profile_last_use_time else None
        })


class ClientAuthView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        client_id = request.data['client_id']
        secret_id = request.data['secret_id']
        sid = request.data['sid']

        try:
            client = Client.objects.get(client_id=client_id, sid=sid)
            if check_password(secret_id, client.secret_id):
                refresh = RefreshToken.for_user(client.user)
                return Response({
                    'user': client.user,
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                })
            return Response({'error': 'Invalid credentials'}, status=401)
        except Client.DoesNotExist:
            return Response({'error': 'Client not found'}, status=404)


class LogReceiverView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logs = request.data.get('logs', [])
        client_id = request.data.get('client_id')
        # Process and store logs (e.g., save to database)
        try:
            client = Client.objects.get(client_id=client_id, user=request.user) if client_id else None
            log_entries = [
                LogEntry(
                    user=request.user,
                    client=client,
                    event_type=log.get('event_type'),
                    event_id=log.get('event_id'),
                    source=log.get('source'),
                    timestamp=log.get('timestamp'),
                    details=log.get('details', {})
                )
                for log in logs
            ]
            LogEntry.objects.bulk_create(log_entries)
            # Trigger anomaly detection task
            end_time = timezone.now()
            start_time = end_time - timezone.timedelta(minutes=15)  # Analyze last 15 minutes
            detect_anomalies.delay(
                user_id=request.user.id,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                client_id=client_id
            )
            
            return Response({'status': 'success', 'count': len(logs)})
        except Client.DoesNotExist:
            return Response({'error': 'Client not found'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=400)
        

class RotateClientCredentialsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        client_id = request.data.get('client_id')
        try:
            client = Client.objects.get(client_id=client_id, user=request.user)
            client.client_id = uuid.uuid4()  # Generate new client_id
            client.set_secret_id(uuid.uuid4().hex)  # Generate and hash new secret_id
            client.save()
            return Response({
                'new_client_id': str(client.client_id),
                'new_secret_id': client.secret_id,  # Return unhashed for one-time use
            })
        except Client.DoesNotExist:
            return Response({'error': 'Client not found'}, status=404)
        


from django.db.models import Count
from math import log2

def calculate_entropy(user, start_time, end_time):
    logs = LogEntry.objects.filter(user=user, timestamp__range=(start_time, end_time))
    event_counts = logs.values('event_type').annotate(count=Count('event_type'))
    total = logs.count()
    if total == 0:
        return 0
    entropy = -sum((item['count'] / total) * log2(item['count'] / total) for item in event_counts)
    return entropy

from scipy.stats import gaussian_kde
import numpy as np

def detect_density_anomalies(user, start_time, end_time):
    logs = LogEntry.objects.filter(user=user, timestamp__range=(start_time, end_time))
    timestamps = np.array([log.timestamp.timestamp() for log in logs])
    if len(timestamps) < 2:
        return []
    kde = gaussian_kde(timestamps)
    densities = kde(timestamps)
    threshold = np.percentile(density, 95)  # Flag top 5% as anomalies
    anomalies = [log for log, d in zip(logs, density) if d > threshold]
    for log in anomalies:
        log.anomaly_score = d
        log.save()
    return anomalies


# views.py
class LogListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        event_type = request.query_params.get('event_type')
        start_time = request.query_params.get('start_time')
        end_time = request.query_params.get('end_time')
        logs = LogEntry.objects.filter(user=request.user)
        if event_type:
            logs = logs.filter(event_type=event_type)
        if start_time and end_time:
            logs = logs.filter(timestamp__range=(start_time, end_time))
        return Response([{
            'id': log.id,
            'event_type': log.event_type,
            'event_id': log.event_id,
            'source': log.source,
            'timestamp': log.timestamp,
            'details': log.details,
            'anomaly_score': log.anomaly_score
        } for log in logs])


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


# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import LoginSerializer

class LoginView(APIView):
    permission_classes = []  # Allow unauthenticated access
    serializer_class = LoginSerializer


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



