from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import SecurityEvent, ProcessLog, NetworkLog, FileLog, UserAccount, UserGroup, UserProfileModel, UserSession, EnvironmentInfo
from .serializers import (
    SecurityEventSerializer, ProcessLogSerializer, NetworkLogSerializer, FileLogSerializer,
    UserDataSerializer, UserAccountSerializer, UserGroupSerializer, UserProfileModelSerializer,
    UserSessionSerializer, EnvironmentInfoSerializer, BulkDataSerializer
)
from accounts.models import Client

class SecurityEventViewSet(viewsets.ModelViewSet):
    queryset = SecurityEvent.objects.all()
    serializer_class = SecurityEventSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = BulkDataSerializer(data=request.data)
        if serializer.is_valid():
            client_id = serializer.validated_data['client_id']
            try:
                client = Client.objects.get(client_id=client_id)
                for log in serializer.validated_data['logs']:
                    SecurityEvent.objects.create(client=client, **log)
                return Response({"status": "Logs saved"}, status=status.HTTP_201_CREATED)
            except Client.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProcessLogViewSet(viewsets.ModelViewSet):
    queryset = ProcessLog.objects.all()
    serializer_class = ProcessLogSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = BulkDataSerializer(data=request.data)
        if serializer.is_valid():
            client_id = serializer.validated_data['client_id']
            try:
                client = Client.objects.get(client_id=client_id)
                for log in serializer.validated_data['logs']:
                    ProcessLog.objects.create(client=client, **log)
                return Response({"status": "Logs saved"}, status=status.HTTP_201_CREATED)
            except Client.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class NetworkLogViewSet(viewsets.ModelViewSet):
    queryset = NetworkLog.objects.all()
    serializer_class = NetworkLogSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = BulkDataSerializer(data=request.data)
        if serializer.is_valid():
            client_id = serializer.validated_data['client_id']
            try:
                client = Client.objects.get(client_id=client_id)
                for log in serializer.validated_data['logs']:
                    NetworkLog.objects.create(client=client, **log)
                return Response({"status": "Logs saved"}, status=status.HTTP_201_CREATED)
            except Client.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FileLogViewSet(viewsets.ModelViewSet):
    queryset = FileLog.objects.all()
    serializer_class = FileLogSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = BulkDataSerializer(data=request.data)
        if serializer.is_valid():
            client_id = serializer.validated_data['client_id']
            try:
                client = Client.objects.get(client_id=client_id)
                for log in serializer.validated_data['logs']:
                    FileLog.objects.create(client=client, **log)
                return Response({"status": "Logs saved"}, status=status.HTTP_201_CREATED)
            except Client.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserDataViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = UserDataSerializer(data=request.data['user_data'])
        if serializer.is_valid():
            client_id = request.data.get('client_id')
            try:
                client = Client.objects.get(client_id=client_id)
                UserAccount.objects.create(client=client, **serializer.validated_data['account_info'])
                UserGroup.objects.create(client=client, **serializer.validated_data['groups'])
                UserProfileModel.objects.create(client=client, **serializer.validated_data['profiles'])
                for session in serializer.validated_data['sessions']:
                    UserSession.objects.create(client=client, **session)
                EnvironmentInfo.objects.create(client=client, **serializer.validated_data['environment'])
                return Response({"status": "User data saved"}, status=status.HTTP_201_CREATED)
            except Client.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)