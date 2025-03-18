# accounts/serializers.py
from django.contrib.auth.models import Group
from rest_framework import serializers
from accounts.models import CustomUser, UserProfile
from oauth2_provider.models import Application

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = [
            'image', 'account_expires', 'enabled', 'password_changeable_date', 'password_expires',
            'user_may_change_password', 'password_required', 'password_last_set', 'last_logon', 'principal_source',
            'object_class', 'time_zone', 'preferences', 'last_login_ip', 'last_password_change', 'logon_count',
            'locked_out', 'lockout_time', 'department', 'job_title', 'local_groups'
        ]

class CustomUserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(required=False)
    client_id = serializers.CharField(write_only=True)
    client_secret = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        # fields = [
        #     'sid', 'email', 'password', 'full_name', 'domain', 'account_type', 'caption', 'sid_type',
        #     'description', 'status', 'local_account', 'is_shutting_down', 'created_at', 'updated_at', 'profile',
        #     'client_id', 'client_secret'
        # ]
        fields = '__all__'
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True}
        }

    def create(self, validated_data):
        profile_data = validated_data.pop('profile', None)
        client_id = validated_data.pop('client_id')
        client_secret = validated_data.pop('client_secret')

        user = CustomUser(**validated_data)
        user.set_password(validated_data['password'])
        user.save()

        # Register OAuth2 Application
        Application.objects.create(
            user=user,
            client_id=client_id,
            client_secret=client_secret,
            client_type='confidential',
            authorization_grant_type='client-credentials',
            name=f"Client for {user.sid}"
        )

        if profile_data and hasattr(user, 'profile'):
            for key, value in profile_data.items():
                setattr(user.profile, key, value)
            user.profile.save()
        return user
       

class GroupSerializer(
    serializers.ModelSerializer
):
    class Meta:
        model = Group
        fields = "__all__"



class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        user = self.context['request'].user
        # Check old password
        if not user.check_password(self.old_password):
            raise serializers.ValidationError({"old_password": "Incorrect password"})
        
        # Basic password strength (customize as needed)
        if len(self.new_password) < 8:
            raise serializers.ValidationError({"new_password": "Password must be at least 8 characters long"})
        
        # Ensure that the new password and confirm password match
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("New password and confirmation password do not match.")
        return attrs
    
    
