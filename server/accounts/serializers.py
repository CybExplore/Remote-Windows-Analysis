from django.contrib.auth.models import Group
from rest_framework import serializers
from accounts.models import CustomUser, UserProfile


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = [
            'image', 'description', 'account_expires', 'enabled', 'password_changeable_date', 'password_expires',
            'user_may_change_password', 'password_required', 'password_last_set', 'last_logon', 'principal_source',
            'object_class', 'time_zone', 'preferences', 'last_login_ip', 'last_password_change', 'logon_count',
            'locked_out', 'lockout_time', 'department', 'job_title', 'local_groups'
        ]

class CustomUserSerializer(
    serializers.ModelSerializer
):
    profile = UserProfileSerializer(required=False)

    class Meta:
        model = CustomUser
        fields = [
            'sid', 'email', 'password', 'full_name', 'domain', 'account_type', 'caption', 'sid_type',
            'description', 'status', 'local_account', 'is_shutting_down', 'created_at', 'updated_at', 'profile'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'sid': {'read_only': True}, 
            'created_at': {'read_only': True},
            'updated_at': {'read_only': True},
        }
        # exclude = ['groups', 'user_permissions']

    def create(self, validated_data):
        profile_data = validated_data.pop('profile', None)
        user = CustomUser(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
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
        # Ensure that the new password and confirm password match
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("New password and confirmation password do not match.")
        return attrs
    
