from django.test import TestCase
# Create your tests here.
from rest_framework.test import APITestCase

from accounts.models import CustomUser


class LoginViewTest(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            sid="S-1-5-21-123-456-789-1000",
            email="test@example.com",
            password="testpassword",
        )

    def test_login_success(self):
        response = self.client.post(
            "/api/login/",
            {"identifier": "test@example.com", "password": "testpassword"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.data["data"])
