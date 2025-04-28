from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from django.core.validators import RegexValidator
from django.utils import timezone

class CustomUserManager(UserManager):
    """Custom manager to handle user creation with sid instead of username."""
    def create_user(self, sid, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(sid, email, password, **extra_fields)

    def create_superuser(self, sid, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(sid, email, password, **extra_fields)

    def _create_user(self, sid, email, password, **extra_fields):
        if not sid:
            raise ValueError('The SID must be set')
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(sid=sid, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


