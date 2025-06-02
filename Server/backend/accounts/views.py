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
    CustomUserSerializer, UserProfileSerializer, GroupSerializer, ClientRegisterSerializer, UserRegisterSerializer,
    LoginSerializer, PasswordChangeSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer
)
from accounts.permissions import IsClientAuthenticated, IsOwnerOrAdmin
from accounts.notifications import send_password_change_email, get_client_ip

from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password, make_password

from .tasks import detect_anomalies
from django.utils import timezone



logger = logging.getLogger(__name__)


# class ClientRegisterView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         client_id = request.data.get('client_id')
#         secret_id = request.data.get('secret_id')
#         sid = request.data.get('sid')
#         user_email = request.data.get('user_email')

#         if not all([client_id, secret_id, sid, user_email]):
#             return Response({'error': 'Missing required fields'}, status=400)

#         try:
#             user = CustomUser.objects.get(email=user_email)
#             client, created = Client.objects.get_or_create(
#                 client_id=client_id,
#                 sid=sid,
#                 user=user,
#                 defaults={'secret_id': Client().set_secret_id(secret_id)}
#             )
#             if not created:
#                 return Response({'error': 'Client with this client_id or sid already exists'}, status=400)

#             return Response({
#                 'status': 'success',
#                 'client_id': str(client.client_id),
#                 'sid': client.sid,
#                 'user_email': user.email
#             })
#         except CustomUser.DoesNotExist:
#             return Response({'error': 'User not found'}, status=404)
#         except Exception as e:
#             return Response({'error': str(e)}, status=400)

from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from accounts.models import Client
from accounts.serializers import ClientRegisterSerializer
import logging

logger = logging.getLogger(__name__)

class ClientRegisterView(CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = ClientRegisterSerializer

    def perform_create(self, serializer):
        client = serializer.save()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response({
            'status': 'success',
            'client_id': str(serializer.instance.client_id),
            'sid': serializer.instance.sid,
            'user_email': serializer.instance.user.email
        }, status=status.HTTP_201_CREATED)


class UserRegisterView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserRegisterSerializer


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

