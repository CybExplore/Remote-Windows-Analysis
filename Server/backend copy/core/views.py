from rest_framework.views import APIView
from rest_framework import generics, status, permissions, viewsets

from rest_framework.response import Response
from rest_framework import status
from core.models import SecurityEvent, ServerInfo, FirewallStatus
from core.serializers import SecurityEventSerializer, ServerInfoSerializer, FirewallStatusSerializer
from accounts.permissions import IsClientAuthenticated
from accounts.models import CustomUser, UserProfile



# Security Tables
class ServerInfoView(APIView):
    permission_classes = [IsClientAuthenticated]

    def post(self, request):
        serializer = ServerInfoSerializer(data=request.data)
        if serializer.is_valid():
            try:
                client = CustomUser.objects.get(sid=serializer.validated_data['client']['sid'])
                serializer.save(client=client)
                return Response({"message": "Server info saved"}, status=status.HTTP_201_CREATED)
            except CustomUser.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        client = request.user
        user_profile = UserProfile.objects.get(
            user=request.user,
        )
        print(user_profile.client_id)
        # client_id = request.user
        # client_id = request.auth.application.client_id
        # print(client_id)
        server_infos = ServerInfo.objects.filter(client=client)
        serializer = ServerInfoSerializer(server_infos, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SecurityEventView(APIView):
    permission_classes = [IsClientAuthenticated]

    def post(self, request):
        serializer = SecurityEventSerializer(data=request.data)
        if serializer.is_valid():
            try:
                client = CustomUser.objects.get(sid=serializer.validated_data['client']['sid'])
                serializer.save(client=client)
                return Response({"message": "Security event saved"}, status=status.HTTP_201_CREATED)
            except CustomUser.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        client = request.user
        events = SecurityEvent.objects.filter(client=client)
        serializer = SecurityEventSerializer(events, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class FirewallStatusView(APIView):
    permission_classes = [IsClientAuthenticated]

    def post(self, request):
        serializer = FirewallStatusSerializer(data=request.data)
        if serializer.is_valid():
            try:
                client = CustomUser.objects.get(sid=serializer.validated_data['client']['sid'])
                serializer.save(client=client)
                return Response({"message": "Firewall status saved"}, status=status.HTTP_201_CREATED)
            except CustomUser.DoesNotExist:
                return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        client = request.user
        statuses = FirewallStatus.objects.filter(client=client)
        serializer = FirewallStatusSerializer(statuses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)



