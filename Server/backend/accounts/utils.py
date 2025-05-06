# accounts/utils.py
import secrets
import logging

logger = logging.getLogger(__name__)

def custom_token_generator(request=None):
    """Generate secure OAuth2 tokens"""
    return secrets.token_urlsafe(50)

def get_client_ip(request):
    """Extract client IP from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
