import logging

from django.contrib.auth.backends import BaseBackend
from django.db.models import Q

from accounts.models import CustomUser

logger = logging.getLogger(__name__)


class DualAuthBackend(BaseBackend):
    """
    Custom authentication backend to allow login using SID or email with password.
    """

    def authenticate(self, request, identifier=None, password=None, **kwargs):
        """
        Authenticate a user using either their SID or email (case-insensitive) and password.
        """
        if not identifier or not password or not identifier.strip():
            logger.warning("Authentication attempt with missing or empty credentials")
            return None

        try:
            # Try to fetch user using either SID or email (case-insensitive)
            user = CustomUser.objects.filter(
                Q(sid=identifier) | Q(email__iexact=identifier)
            ).first()

            if not user:
                logger.info(f"No user found for identifier: {identifier}")
                return None

            # Check the password
            if user.check_password(password):
                if not user.is_active:
                    logger.warning(f"User {user.sid} is inactive")
                    return None
                if hasattr(user, "profile") and user.profile.locked_out:
                    logger.warning(f"User {user.sid} is locked out")
                    return None

                # Log successful authentication
                client_ip = (
                    request.META.get("REMOTE_ADDR", "unknown") if request else "unknown"
                )
                logger.info(
                    f"User {user.sid} authenticated successfully from IP: {client_ip}"
                )
                return user

            # Invalid password case
            logger.info(f"Invalid password for user with identifier: {identifier}")
            return None

        except Exception as e:
            logger.error(
                f"Authentication error for identifier {identifier}: {str(e)}",
                exc_info=True,
            )
            return None

    def get_user(self, user_id):
        """Retrieve a user by their primary key (ID)."""
        try:
            user = CustomUser.objects.get(pk=user_id)
            # Ensure the user is active and not locked out
            if not user.is_active or (
                hasattr(user, "profile") and user.profile.locked_out
            ):
                logger.warning(
                    f"User {user.sid} retrieved but is inactive or locked out"
                )
                return None
            return user
        except CustomUser.DoesNotExist:
            logger.info(f"No user found for ID: {user_id}")
            return None
        except Exception as e:
            logger.error(f"Error retrieving user ID {user_id}: {str(e)}", exc_info=True)
            return None
