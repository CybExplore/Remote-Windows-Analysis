from rest_framework.views import APIView
from rest_framework import generics, status, permissions, viewsets

from rest_framework.response import Response
from rest_framework import status
from core.models import SecurityLog, ProcessInfo, ServiceInfo, NetworkConnection, SystemConfig, UserSession
from core.serializers import SecurityLogSerializer, ProcessInfoSerializer, ServiceInfoSerializer, NetworkConnectionSerializer, SystemConfigSerializer, UserSessionSerializer

# APIView for SecurityLog
class SecurityLogAPIView(viewsets.ModelViewSet):
    queryset = SecurityLog.objects.all()
    serializer_class = SecurityLogSerializer
    lookup_field = 'slug'


# APIView for ProcessInfo
class ProcessInfoAPIView(viewsets.ModelViewSet):
    queryset = ProcessInfo.objects.all()
    serializer_class = ProcessInfoSerializer
    lookup_field = 'slug'
   

# APIView for ServiceInfo
class ServiceInfoAPIView(viewsets.ModelViewSet):
    queryset = ServiceInfo.objects.all()
    serializer_class = ServiceInfoSerializer
    lookup_field = 'slug'

# APIView for NetworkConnection
class NetworkConnectionAPIView(viewsets.ModelViewSet):
    queryset = NetworkConnection.objects.all()
    serializer_class = NetworkConnectionSerializer
    lookup_field = 'slug'

# APIView for SystemConfig
class SystemConfigAPIView(viewsets.ModelViewSet):
    queryset = SystemConfig.objects.all()
    serializer_class = SystemConfigSerializer
    lookup_field = 'slug'

# APIView for UserSession
class UserSessionAPIView(viewsets.ModelViewSet):
    queryset = UserSession.objects.all()
    serializer_class = UserSessionSerializer
    lookup_field = 'slug'

