# accounts/middleware.py
import json
import logging

from django.conf import settings
from django.urls import Resolver404, resolve
from django.utils import timezone

from .models import AuditLog, CustomUser

logger = logging.getLogger(__name__)


class AuditLogMiddleware:
    """
    Logs all requests to the audit system with security context.
    Skips static files and OPTIONS requests by default.
    """

    SKIP_METHODS = ["OPTIONS"]
    SKIP_PATHS = ["/static/", "/media/", "/favicon.ico"]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip logging for certain requests
        if self._should_skip(request):
            return self.get_response(request)

        # Capture request data before processing
        request.start_time = timezone.now()
        response = self.get_response(request)

        # Log after response is ready
        self._log_request(request, response)
        return response

    def _should_skip(self, request):
        """Determine if request should be skipped"""
        return request.method in self.SKIP_METHODS or any(
            request.path.startswith(path) for path in self.SKIP_PATHS
        )

    def _log_request(self, request, response):
        """Create audit log entry"""
        try:
            user = request.user if request.user.is_authenticated else None
            view_name = self._get_view_name(request)

            # Sanitize sensitive data from request body
            body = self._sanitize_body(request)

            AuditLog.objects.create(
                user=user,
                action=f"{request.method}:{view_name}",
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
                metadata={
                    "path": request.path,
                    "method": request.method,
                    "status": response.status_code,
                    "processing_time_ms": self._get_processing_time_ms(request),
                    "view": view_name,
                    "params": dict(request.GET),
                    "body": body,
                    "response_size": (
                        len(response.content) if hasattr(response, "content") else 0
                    ),
                },
            )
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}", exc_info=True)

    def _get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        return (
            x_forwarded_for.split(",")[0].strip()
            if x_forwarded_for
            else request.META.get("REMOTE_ADDR")
        )

    def _get_view_name(self, request):
        """Get the resolved view name or path"""
        try:
            return resolve(request.path).view_name
        except Resolver404:
            return request.path

    def _get_processing_time_ms(self, request):
        """Calculate request processing time"""
        if hasattr(request, "start_time"):
            return (timezone.now() - request.start_time).total_seconds() * 1000
        return 0

    def _sanitize_body(self, request):
        """Remove sensitive data from request body"""
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body = request.body.decode("utf-8")[:2000]  # Limit size
                if "password" in body.lower():
                    data = json.loads(body)
                    for key in list(data.keys()):
                        if "password" in key.lower():
                            data[key] = "******"
                    return data
                return body
            except:
                return "[binary data]"
        return None
