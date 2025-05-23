# accounts/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import Group, User
from django.contrib.auth import authenticate
from django.utils import timezone
from accounts.models import (
    CustomUser, 
    UserProfile,
    AuditLog,
    PasswordHistory
)
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'groups']


class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['url', 'email']

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            'sid', 
            'email',
            'is_active',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['is_active', 'created_at', 'updated_at']

class UserProfileSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'user',
            'enabled',
            'locked_out',
            'client_id',
            'last_logon',
            'last_login_ip',
            'logon_count'
        ]
        read_only_fields = [
            'last_logon',
            'last_login_ip',
            'logon_count'
        ]


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(
        required=True,
        help_text="User's SID or email address"
    )
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    client_id = serializers.CharField(
        required=False,
        help_text="OAuth2 Client ID (optional for initial setup)"
    )
    client_secret = serializers.CharField(
        required=False,
        help_text="OAuth2 Client Secret (optional for initial setup)",
        write_only=True
    )

    def validate(self, attrs):
        identifier = attrs.get('identifier')
        password = attrs.get('password')
        
        # Authenticate using SID or email
        user = authenticate(
            request=self.context.get('request'),
            identifier=identifier,
            password=password
        )
        
        if not user:
            raise serializers.ValidationError(
                "Invalid SID/email or password",
                code='authorization'
            )
            
        if not user.is_active:
            raise serializers.ValidationError(
                "User account is disabled",
                code='authentication'
            )
            
        if hasattr(user, 'profile') and user.profile.locked_out:
            raise serializers.ValidationError(
                "Account locked due to too many failed attempts",
                code='authentication'
            )
            
        attrs['user'] = user
        return attrs

class TokenResponseSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    token_type = serializers.CharField(default="Bearer")
    expires_in = serializers.IntegerField()
    refresh_token = serializers.CharField(required=False)
    scope = serializers.CharField(default="read write")
    sid = serializers.CharField(source='user.sid')
    email = serializers.CharField(source='user.email')

class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

    def validate_current_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        return value

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': "Passwords do not match"
            })
        return data

class AuditLogSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id',
            'user',
            'action',
            'ip_address',
            'timestamp',
            'metadata'
        ]
        read_only_fields = fields

class PasswordResetRequestSerializer(serializers.Serializer):
    identifier = serializers.CharField(
        required=True,
        help_text="User's SID or email address"
    )

class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    token = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': "Passwords do not match"
            })
        return data
    


