# accounts/middleware.py
from django.shortcuts import redirect
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch
from django.conf import settings

class PasswordChangeMiddleware:
    """Middleware to redirect authenticated users to change their password if not yet changed."""

    def __init__(self, get_response):
        """Initialize the middleware and cache the password change URL."""
        self.get_response = get_response
        try:
            self.password_change_url = reverse('password_change')
        except NoReverseMatch:
            raise ValueError(
                "URL pattern 'password_change' not found. Ensure it is defined in your project's urls.py."
            )
       

    def __call__(self, request):
        """
        Process the request and redirect to the password change page if necessary.

        Args:
            request: The HTTP request object.

        Returns:
            A redirect response or the next middleware/response in the chain.
        """
        # Skip redirect for specific paths (e.g., password change page, logout, API)
        excluded_paths = {self.password_change_url}
        try:
            excluded_paths.add(reverse('logout'))
        except NoReverseMatch:
            pass

        # Exclude API paths (adjust prefix based on your URL configuration)
        if request.path.startswith('/api/'):
            return self.get_response(request)

        if (
            request.user.is_authenticated
            and not request.user.password_changed
            and request.path not in excluded_paths
        ):
            return redirect(self.password_change_url)

        return self.get_response(request)
    
