# accounts/serializers.py
from rest_framework import serializers
from rest_framework import serializers
from django.contrib.auth import password_validation

from accounts.models import (
    CustomUser, UserProfile, SecurityEvent, ServerInfo,
    FirewallStatus
)
from oauth2_provider.models import Application
from django.contrib.auth import authenticate
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = [
            'client_id', 'client_secret', 'image', 'account_expires', 'enabled',
            'password_changeable_date', 'password_expires', 'user_may_change_password',
            'password_required', 'password_last_set', 'last_logon', 'principal_source',
            'object_class', 'time_zone', 'preferences', 'last_login_ip',
            'last_password_change', 'logon_count', 'locked_out', 'lockout_time',
            'department', 'job_title', 'local_groups'
        ]

class CustomUserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(required=False)

    class Meta:
        model = CustomUser
        fields = [
            'sid', 'email', 'password', 'password_changed', 'full_name',
            'sid_type', 'domain', 'local_account', 'is_shutting_down',
            'account_type', 'status', 'caption', 'description',
            'created_at', 'updated_at', 'profile'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
            'sid': {'required': True},
        }

    def create(self, validated_data):
        profile_data = validated_data.pop('profile', {})
        try:
            user = CustomUser.objects.create_user(
                sid=validated_data['sid'],
                email=validated_data['email'],
                password=validated_data['password'],
                **{k: v for k, v in validated_data.items() if k not in ['sid', 'email', 'password']}
            )
        except Exception as e:
            raise serializers.ValidationError({"error": str(e)})
        
        client_id = profile_data.get('client_id')
        client_secret = profile_data.get('client_secret')
        if client_id and client_secret:
            # Check if UserProfile already exists
            if hasattr(user, 'profile') and user.profile:
                # Update existing UserProfile
                user.profile.client_id = client_id
                user.profile.client_secret = client_secret
                user.profile.save()
            else:
                # Create new UserProfile
                UserProfile.objects.create(
                    user=user,
                    client_id=client_id,
                    client_secret=client_secret
                )

            # Create or update OAuth2 Application
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
        return user
    

# Generate GroupSerializer

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'
        extra_kwargs = {
            'name': {'required': True},
            'description': {'required': False},
        }


class PasswordChangeSerializer(serializers.Serializer):
    """Secure password change serializer with comprehensive validation."""
    old_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        trim_whitespace=True  # Use trim_whitespace=True for better handling of user input
    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        trim_whitespace=True,  # Updated to True for consistent handling
        min_length=12  # Enforce minimum length for stronger password security
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        trim_whitespace=True  # Updated to True for consistent handling
    )

    def validate_new_password(self, value):
        """
        Validate the new password against Django's password validation framework.
        Ensures compliance with strong password policies.
        """
        try:
            password_validation.validate_password(
                value, 
                user=self.context['request'].user
            )
        except Exception as e:
            raise serializers.ValidationError(e.messages)  # Directly raise validation errors
        return value

    def validate(self, data):
        """
        Cross-field validation to ensure coherence among fields.
        """
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match.'
            })

        if data['old_password'] == data['new_password']:
            raise serializers.ValidationError({
                'new_password': 'New password must be different from the old password.'
            })

        # Verify the old password is correct
        user = self.context['request'].user
        if not user.check_password(data.get('old_password')):
            raise serializers.ValidationError({
                'old_password': 'Incorrect current password.'
            })

        return data


class LoginSerializer(serializers.Serializer):
    """Custom Login serializer using sid or email address and password to login."""
    identifier = serializers.CharField(
        required=True,
        help_text="SID or email address.",
        label="SID or email address"
    )
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        identifier = attrs.get('identifier')
        password = attrs.get('password')
        
        # Ensure request context is available
        request = self.context.get('request')
        if not request:
            raise serializers.ValidationError("Request context is required for authentication")

        # Authenticate the user using the custom backend
        user = authenticate(request=request, identifier=identifier, password=password)
        
        if not user:
            raise serializers.ValidationError({"non_field_errors": "Invalid credentials"})
        if not user.is_active:
            raise serializers.ValidationError({"non_field_errors": "Account is inactive"})
        if hasattr(user, 'profile') and user.profile.locked_out:
            raise serializers.ValidationError({"non_field_errors": "Account is locked out"})
        
        attrs['user'] = user
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    identifier = serializers.CharField(required=True, help_text="SID or email of the user")

    def validate_identifier(self, value):
        user = CustomUser.objects.filter(sid=value).first() or CustomUser.objects.filter(email__iexact=value).first()
        if not user:
            raise serializers.ValidationError("No user found with this SID or email")
        if not user.is_active:
            raise serializers.ValidationError("This account is inactive")
        if hasattr(user, 'profile') and user.profile.locked_out:
            raise serializers.ValidationError("This account is locked out")
        self.context['user'] = user
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for validating password reset confirmation inputs."""
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        """
        Validate the uidb64 and token provided in the request.
        """
        # Validate that new_password matches confirm_password
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if new_password != confirm_password:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."}
            )

        # Optionally enforce additional password rules (e.g., minimum length)
        if len(new_password) < 8:
            raise serializers.ValidationError(
                {"new_password": "Password must be at least 8 characters long."}
            )

        return data
    
        # uidb64 = data.get('uidb64')
        # token = data.get('token')
        # new_password = data.get('new_password')
        # confirm_password = data.get('confirm_password')

        # # Decode UID and fetch user
        # try:
        #     uid = force_str(urlsafe_base64_decode(uidb64))
        #     user = CustomUser.objects.get(pk=uid)
        # except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        #     raise serializers.ValidationError({"uidb64": "Invalid user ID"})

        # # Validate token
        # token_generator = PasswordResetTokenGenerator()
        # if not token_generator.check_token(user, token):
        #     raise serializers.ValidationError({"token": "Invalid or expired token"})

        # # Validate new password
        # if len(new_password) < 8:
        #     raise serializers.ValidationError({"new_password": "Password must be at least 8 characters long"})
        # if new_password != confirm_password:
        #     raise serializers.ValidationError({"confirm_password": "New password and confirmation password do not match"})
        # if user.check_password(new_password):
        #     raise serializers.ValidationError({"new_password": "New password must differ from old password"})

        # data['user'] = user
        # return data
    

# class ServerInfoSerializer(serializers.ModelSerializer):
#     client = CustomUserSerializer()

#     class Meta:
#         model = ServerInfo
#         fields = ['client', 'machine_name', 'os_version', 'processor_count', 'timestamp', 'is_64bit']

#     def validate(self, data):
#         if not data.get('client') or not data['client'].get('sid'):
#             raise serializers.ValidationError("Client SID is required.")
#         return data

class ServerInfoSerializer(serializers.ModelSerializer):
    client = serializers.CharField(source='client.sid')

    class Meta:
        model = ServerInfo
        fields = ['client', 'machine_name', 'os_version', 'processor_count', 'timestamp', 'is_64bit']

    def validate(self, data):
        if not data.get('client'):
            raise serializers.ValidationError("Client SID is required.")
        return data

# class SecurityEventSerializer(serializers.ModelSerializer):
#     client = CustomUserSerializer()

#     class Meta:
#         model = SecurityEvent
#         fields = ['client', 'event_id', 'time_created', 'description', 'source', 'logon_type', 
#                   'failure_reason', 'target_account', 'group_name', 'privilege_name', 
#                   'process_name', 'service_name']

#     def validate(self, data):
#         if not data.get('client') or not data['client'].get('sid'):
#             raise serializers.ValidationError("Client SID is required.")
#         return data

class SecurityEventSerializer(serializers.ModelSerializer):
    client = serializers.CharField(source='client.sid')

    class Meta:
        model = SecurityEvent
        fields = [
            'client', 'event_id', 'time_created', 'description', 'source', 'logon_type',
            'failure_reason', 'target_account', 'group_name', 'privilege_name',
            'process_name', 'service_name'
        ]

    def validate(self, data):
        if not data.get('client'):
            raise serializers.ValidationError("Client SID is required.")
        return data
    
# class FirewallStatusSerializer(serializers.ModelSerializer):
    client = CustomUserSerializer()

    class Meta:
        model = FirewallStatus
        fields = ['client', 'is_enabled', 'profile', 'timestamp']

    def validate(self, data):
        if not data.get('client') or not data['client'].get('sid'):
            raise serializers.ValidationError("Client SID is required.")
        return data

class FirewallStatusSerializer(serializers.ModelSerializer):
    client = serializers.CharField(source='client.sid')

    class Meta:
        model = FirewallStatus
        fields = ['client', 'is_enabled', 'profile', 'timestamp']

    def validate(self, data):
        if not data.get('client'):
            raise serializers.ValidationError("Client SID is required.")
        return data


