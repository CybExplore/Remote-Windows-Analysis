import logging
from django.utils import timezone
from datetime import timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from core.models import SecurityEvent, ServerInfo, FirewallStatus
from core.serializers import SecurityEventSerializer, ServerInfoSerializer, FirewallStatusSerializer
from accounts.permissions import IsClientAuthenticated

logger = logging.getLogger(__name__)

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

class ServerInfoView(APIView):
    permission_classes = [IsClientAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['machine_name', 'os_version', 'is_64bit']
    ordering_fields = ['timestamp', 'created_at']
    ordering = ['-timestamp']

    def post(self, request):
        serializer = ServerInfoSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            try:
                serializer.save()
                user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
                logger.info(f"Server info saved for user {user_sid}")
                return Response(
                    {"message": "Server info saved", "data": serializer.data},
                    status=status.HTTP_201_CREATED
                )
            except Exception as e:
                user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
                logger.error(f"Error saving server info for user {user_sid}: {str(e)}")
                return Response(
                    {"message": "Failed to save server info", "errors": [str(e)]},
                    status=status.HTTP_400_BAD_REQUEST
                )
        user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
        logger.warning(f"Invalid server info data from user {user_sid}: {serializer.errors}")
        return Response(
            {"message": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

    def get(self, request):
        if not request.user or not request.user.is_authenticated:
            logger.warning("Unauthenticated request to server-info")
            return Response(
                {"message": "Authentication required"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        server_infos = ServerInfo.objects.filter(client=request.user).select_related('client')
        filterset = self.filter_backends[0]().filter_queryset(request, server_infos, self)
        ordering = self.filter_backends[1]().filter_queryset(request, filterset, self)
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(ordering, request)
        serializer = ServerInfoSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class SecurityEventView(APIView):
    permission_classes = [IsClientAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['event_id', 'source', 'logon_type', 'target_account']
    ordering_fields = ['time_created', 'event_id']
    ordering = ['-time_created']

    def post(self, request):
        serializer = SecurityEventSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            try:
                serializer.save()
                user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
                logger.info(f"Security event saved for user {user_sid}")
                return Response(
                    {"message": "Security event saved", "data": serializer.data},
                    status=status.HTTP_201_CREATED
                )
            except Exception as e:
                user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
                logger.error(f"Error saving security event for user {user_sid}: {str(e)}")
                return Response(
                    {"message": "Failed to save security event", "errors": [str(e)]},
                    status=status.HTTP_400_BAD_REQUEST
                )
        user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
        logger.warning(f"Invalid security event data from user {user_sid}: {serializer.errors}")
        return Response(
            {"message": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

    def get(self, request):
        if not request.user or not request.user.is_authenticated:
            logger.warning("Unauthenticated request to security-events")
            return Response(
                {"message": "Authentication required"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        events = SecurityEvent.objects.filter(client=request.user).select_related('client')
        filterset = self.filter_backends[0]().filter_queryset(request, events, self)
        ordering = self.filter_backends[1]().filter_queryset(request, filterset, self)
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(ordering, request)
        serializer = SecurityEventSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class FirewallStatusView(APIView):
    permission_classes = [IsClientAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['is_enabled', 'profile']
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']

    def post(self, request):
        serializer = FirewallStatusSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            try:
                serializer.save()
                user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
                logger.info(f"Firewall status saved for user {user_sid}")
                return Response(
                    {"message": "Firewall status saved", "data": serializer.data},
                    status=status.HTTP_201_CREATED
                )
            except Exception as e:
                user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
                logger.error(f"Error saving firewall status for user {user_sid}: {str(e)}")
                return Response(
                    {"message": "Failed to save firewall status", "errors": [str(e)]},
                    status=status.HTTP_400_BAD_REQUEST
                )
        user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
        logger.warning(f"Invalid firewall status data from user {user_sid}: {serializer.errors}")
        return Response(
            {"message": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

    def get(self, request):
        if not request.user or not request.user.is_authenticated:
            logger.warning("Unauthenticated request to firewall-status")
            return Response(
                {"message": "Authentication required"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        statuses = FirewallStatus.objects.filter(client=request.user).select_related('client')
        filterset = self.filter_backends[0]().filter_queryset(request, statuses, self)
        ordering = self.filter_backends[1]().filter_queryset(request, filterset, self)
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(ordering, request)
        serializer = FirewallStatusSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class DashboardView(APIView):
    permission_classes = [IsClientAuthenticated]

    def get(self, request):
        if not request.user or not request.user.is_authenticated:
            logger.warning("Unauthenticated request to dashboard")
            return Response(
                {"message": "Authentication required"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        try:
            client = request.user
            recent_events = SecurityEvent.objects.filter(
                client=client,
                time_created__gte=timezone.now() - timedelta(hours=24)
            ).select_related('client')[:5]
            event_serializer = SecurityEventSerializer(recent_events, many=True)

            server_infos = ServerInfo.objects.filter(client=client).select_related('client').order_by('machine_name', '-timestamp').distinct('machine_name')[:5]
            server_serializer = ServerInfoSerializer(server_infos, many=True)

            firewall_status = FirewallStatus.objects.filter(client=client).select_related('client').order_by('-timestamp').first()
            firewall_serializer = FirewallStatusSerializer(firewall_status) if firewall_status else None

            event_count = SecurityEvent.objects.filter(client=client).count()
            server_count = ServerInfo.objects.filter(client=client).values('machine_name').distinct().count()
            firewall_enabled = FirewallStatus.objects.filter(client=client, is_enabled=True).exists()

            response_data = {
                "message": "Dashboard data retrieved successfully",
                "data": {
                    "recent_events": event_serializer.data,
                    "server_infos": server_serializer.data,
                    "firewall_status": firewall_serializer.data if firewall_serializer else None,
                    "stats": {
                        "total_events": event_count,
                        "total_servers": server_count,
                        "firewall_enabled": firewall_enabled,
                    }
                }
            }
            user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
            logger.info(f"Dashboard data retrieved for user {user_sid}")
            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as e:
            user_sid = request.user.sid if request.user and hasattr(request.user, 'sid') else 'unknown'
            logger.error(f"Error retrieving dashboard data for user {user_sid}: {str(e)}")
            return Response(
                {"message": "Failed to retrieve dashboard data", "errors": [str(e)]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
