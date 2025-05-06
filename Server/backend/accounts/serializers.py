from rest_framework import serializers
from django.contrib.auth import password_validation, authenticate
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.db import transaction
import logging
from accounts.models import CustomUser, UserProfile, AuditLog, PasswordHistory
from oauth2_provider.models import Application

logger = logging.getLogger(__name__)

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = [
            'user', 'image', 'client_id', 'client_secret', 'account_expires', 'enabled',
            'password_changeable_date', 'password_expires', 'user_may_change_password',
            'password_required', 'password_last_set', 'last_logon', 'principal_source',
            'object_class', 'time_zone', 'preferences', 'last_login_ip', 'last_password_change',
            'logon_count', 'locked_out', 'lockout_time', 'department', 'job_title', 'local_groups',
            'description'
        ]
        extra_kwargs = {
            'user': {'required': False},
            'image': {'required': False},
            'client_id': {'required': False},
            'client_secret': {'required': False},
        }

class CustomUserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(required=False)

    class Meta:
        model = CustomUser
        fields = [
            'sid', 'email', 'password', 'password_changed', 'full_name',
            'sid_type', 'domain', 'local_account', 'is_shutting_down', 'account_type',
            'status', 'caption', 'created_at', 'updated_at', 'profile'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
            'sid': {'required': True},
        }

    @transaction.atomic
    def create(self, validated_data):
        """Create a user with associated profile and OAuth2 application."""
        profile_data = validated_data.pop('profile', {})
        password = validated_data.pop('password')
        user = self._create_user(validated_data, password)
        self._create_user_profile(user, profile_data)
        return user

    def _create_user(self, validated_data, password):
        """Create and save the CustomUser instance."""
        logger.debug(f"Creating CustomUser with SID: {validated_data.get('sid')}")
        return CustomUser.objects.create_user(password=password, **validated_data)

    def _create_user_profile(self, user, profile_data):
        """Create or update the UserProfile instance if it doesn't exist."""
        if not profile_data:
            logger.debug(f"No profile data provided for user {user.sid}, skipping profile creation")
            return

        # Check if UserProfile already exists to avoid duplicate creation
        if hasattr(user, 'profile') and user.profile:
            logger.debug(f"UserProfile already exists for user {user.sid}, updating instead")
            profile = user.profile
            for key, value in profile_data.items():
                setattr(profile, key, value)
            profile.save()
        else:
            logger.debug(f"Creating UserProfile for user {user.sid}")
            profile = UserProfile.objects.create(
                user=user,
                client_id=profile_data.get('client_id', ''),
                client_secret=profile_data.get('client_secret', ''),
                account_expires=profile_data.get('account_expires'),
                enabled=profile_data.get('enabled', True),
                password_changeable_date=profile_data.get('password_changeable_date'),
                password_expires=profile_data.get('password_expires'),
                user_may_change_password=profile_data.get('user_may_change_password', True),
                password_required=profile_data.get('password_required', True),
                password_last_set=profile_data.get('password_last_set'),
                last_logon=profile_data.get('last_logon'),
                principal_source=profile_data.get('principal_source', 'Local'),
                object_class=profile_data.get('object_class', 'User'),
                time_zone=profile_data.get('time_zone', ''),
                preferences=profile_data.get('preferences', {}),
                last_login_ip=profile_data.get('last_login_ip'),
                last_password_change=profile_data.get('last_password_change'),
                logon_count=profile_data.get('logon_count', 0),
                locked_out=profile_data.get('locked_out', False),
                lockout_time=profile_data.get('lockout_time'),
                department=profile_data.get('department', ''),
                job_title=profile_data.get('job_title', ''),
                local_groups=profile_data.get('local_groups', []),
                description=profile_data.get('description', '')
            )
        self._create_oauth_application(user, profile_data)

    def _create_oauth_application(self, user, profile_data):
        """Create or update an OAuth2 Application for the user."""
        client_id = profile_data.get('client_id')
        client_secret = profile_data.get('client_secret')
        if client_id and client_secret:
            logger.debug(f"Creating/updating OAuth2 Application for user {user.sid}")
            Application.objects.update_or_create(
                user=user,
                defaults={
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'client_type': 'confidential',
                    'authorization_grant_type': 'client-credentials',
                    'name': f"Client for {user.sid}"
                }
            )

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def validate(self, data):
        user = self.context['request'].user
        if hasattr(user, 'profile') and not user.profile.user_may_change_password:
            raise serializers.ValidationError({'non_field_errors': 'Password changes are not allowed for this user'})
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not user.check_password(old_password):
            raise serializers.ValidationError({'old_password': 'Old password is incorrect'})
        if new_password != confirm_password:
            raise serializers.ValidationError({'confirm_password': 'New passwords do not match'})
        password_validation.validate_password(new_password, user)

        old_passwords = PasswordHistory.objects.filter(user=user).order_by('-changed_at')[:5]
        for history in old_passwords:
            if check_password(new_password, history.password):
                raise serializers.ValidationError({'new_password': 'You have used this password before.'})

        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        PasswordHistory.objects.create(user=user, password=user.password)

class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        identifier = data.get('identifier')
        password = data.get('password')
        request = self.context.get('request')

        user = authenticate(request=request, identifier=identifier, password=password)
        if not user:
            raise serializers.ValidationError({'non_field_errors': 'Invalid credentials'})
        if not user.is_active:
            raise serializers.ValidationError({'non_field_errors': 'This account is inactive'})
        if hasattr(user, 'profile') and user.profile.locked_out:
            raise serializers.ValidationError({'non_field_errors': 'This account is locked out'})

        data['user'] = user
        return data

class PasswordResetRequestSerializer(serializers.Serializer):
    identifier = serializers.CharField()

    def validate_identifier(self, value):
        user = CustomUser.objects.filter(sid=value).first() or CustomUser.objects.filter(email__iexact=value).first()
        if not user:
            raise serializers.ValidationError("No user found with this SID or email.")
        if not user.is_active:
            raise serializers.ValidationError("This account is inactive.")
        if hasattr(user, 'profile') and user.profile.locked_out:
            raise serializers.ValidationError("This account is locked out.")
        self.context['user'] = user
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        try:
            uid = force_str(urlsafe_base64_decode(data.get('uidb64')))
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            raise serializers.ValidationError({'uidb64': 'Invalid UID'})

        if not default_token_generator.check_token(user, data.get('token')):
            raise serializers.ValidationError({'token': 'Invalid or expired token'})
        if data.get('new_password') != data.get('confirm_password'):
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match'})
        if user.check_password(data.get('new_password')):
            raise serializers.ValidationError({'new_password': 'New password must be different from the old one'})
        password_validation.validate_password(data.get('new_password'), user)

        self.context['user'] = user
        return data

