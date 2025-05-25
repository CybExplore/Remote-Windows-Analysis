from oauthlib.oauth2 import RequestValidator
from accounts.models import UserProfile
# accounts/oauth_validators.py
from oauthlib.oauth2 import RequestValidator
from django.contrib.auth import authenticate
from datetime import timedelta
from django.utils import timezone
from accounts.models import UserProfile, OAuth2Token

class BasicOAuthValidator(RequestValidator):
    # Client Validation (Basic - No security yet)
    def validate_client_id(self, client_id, request, *args, **kwargs):
        return True  # Accept any client_id for now

    def validate_client_secret(self, client_secret, request, *args, **kwargs):
        return True  # Accept any client_secret for now

    # User Authentication (SID/email + password)
    def validate_user(self, username, password, client, request, *args, **kwargs):
        """
        Authenticate using either SID or email (case-insensitive for email).
        """
        user = authenticate(
            request=None,
            identifier=username,  # Can be SID or email
            password=password
        )
        if user:
            request.user = user  # Attach user to the request
            return True
        return False

    # Token Settings
    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return ["read", "write"]

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return True  # Accept all scopes

    # Token Storage (Stateless for now)
    def save_bearer_token(self, token, request, *args, **kwargs):
            expires_at = timezone.now() + timedelta(seconds=token.get('expires_in', 3600))
            OAuth2Token.objects.create(
                user=request.user,
                access_token=token['access_token'],
                refresh_token=token.get('refresh_token'),
                expires_at=expires_at,
                scope=' '.join(token.get('scope', ['read', 'write']))
            )

    # Required stubs
    def authenticate_client(self, request, *args, **kwargs):
        return True  # Skip client auth
    
    def validate_bearer_token(self, token, scopes, request):
        try:
            token_obj = OAuth2Token.objects.get(access_token=token)
            if token_obj.is_expired():
                return False
            request.user = token_obj.user
            return True
        except OAuth2Token.DoesNotExist:
            return False
    
    
