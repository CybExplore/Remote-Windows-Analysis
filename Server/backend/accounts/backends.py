# accounts/backends.py
import logging
from django.contrib.auth.backends import BaseBackend, RemoteUserBackend as DjangoRemoteUserBackend
from django.db.models import Q
from accounts.models import CustomUser

logger = logging.getLogger(__name__)


class DualAuthBackend(BaseBackend):
    """Custom authentication backend to allow login using SID or email with password."""
    def authenticate(self, request, identifier=None, password=None, **kwargs):
        """
        Authenticate a user using either their SID or email (case-insensitive) and password.
        """
        if not identifier or not password or not identifier.strip():
            logger.warning("Authentication attempt with missing or empty credentials")
            return None

        try:
            user = CustomUser.objects.filter(
                Q(sid=identifier) | Q(email__iexact=identifier)
            ).first()

            if not user:
                logger.info(f"No user found for identifier: {identifier}")
                return None

            if user.check_password(password):
                if not user.is_active:
                    logger.warning(f"User {user.sid} is inactive")
                    return None
                if hasattr(user, 'profile') and user.profile.locked_out:
                    logger.warning(f"User {user.sid} is locked out")
                    return None
                client_ip = request.META.get('REMOTE_ADDR', 'unknown') if request else 'unknown'
                logger.info(f"User {user.sid} authenticated successfully from IP: {client_ip}")
                return user
            
            logger.info(f"Invalid password for user with identifier: {identifier}")
            return None

        except CustomUser.DoesNotExist:
            logger.info(f"No user found for identifier: {identifier}")
            return None
        except Exception as e:
            logger.error(f"Authentication error for identifier {identifier}: {str(e)}", exc_info=True)
            return None

    def get_user(self, user_id):
        """Retrieve a user by their primary key (ID)."""
        try:
            user = CustomUser.objects.get(pk=user_id)
            if not user.is_active or (hasattr(user, 'profile') and user.profile.locked_out):
                logger.warning(f"User {user.sid} retrieved but is inactive or locked out")
                return None
            return user
        except CustomUser.DoesNotExist:
            logger.info(f"No user found for ID: {user_id}")
            return None
        except Exception as e:
            logger.error(f"Error retrieving user ID {user_id}: {str(e)}", exc_info=True)
            return None


class CustomRemoteUserBackend(DjangoRemoteUserBackend):
    """Customized RemoteUserBackend to authenticate existing users only via REMOTE_USER."""

    create_unknown_user = False  # Do not create users if they don’t exist

    def authenticate(self, request, remote_user):
        """
        Authenticate an existing user using the REMOTE_USER header, matching SID, email, or caption.

        Args:
            request: HTTP request object.
            remote_user: Value from REMOTE_USER header (e.g., 'DOMAIN\\username', SID, or email).

        Returns:
            CustomUser instance if authenticated and exists, None otherwise.
        """
        if not remote_user:
            logger.warning("No REMOTE_USER provided")
            return None

        try:
            # Normalize remote_user
            identifier = remote_user.strip()

            # Look for an existing user by SID, email, or caption (e.g., DOMAIN\username)
            user = CustomUser.objects.filter(
                Q(sid=identifier) |              # Match SID directly
                Q(email__iexact=identifier) |    # Match email case-insensitively
                Q(caption=identifier)            # Match caption (e.g., 'DOMAIN\\username')
            ).first()

            if not user:
                logger.info(f"No existing user found for REMOTE_USER: {identifier}")
                return None

            # Check account status
            if not user.is_active:
                logger.warning(f"User {user.sid} is inactive")
                return None
            if hasattr(user, 'profile') and user.profile.locked_out:
                logger.warning(f"User {user.sid} is locked out")
                return None

            # Log successful authentication
            client_ip = request.META.get('REMOTE_ADDR', 'unknown') if request else 'unknown'
            logger.info(f"User {user.sid} authenticated via REMOTE_USER from IP: {client_ip}")
            return user

        except Exception as e:
            logger.error(f"Error in RemoteUserBackend for REMOTE_USER {remote_user}: {str(e)}", exc_info=True)
            return None

    def get_user(self, user_id):
        """Retrieve a user by their primary key (ID)."""
        try:
            user = CustomUser.objects.get(pk=user_id)
            if not user.is_active or (hasattr(user, 'profile') and user.profile.locked_out):
                logger.warning(f"User {user.sid} retrieved but is inactive or locked out")
                return None
            return user
        except CustomUser.DoesNotExist:
            logger.info(f"No user found for ID: {user_id}")
            return None
        except Exception as e:
            logger.error(f"Error retrieving user ID {user_id}: {str(e)}", exc_info=True)
            return None

        
              

