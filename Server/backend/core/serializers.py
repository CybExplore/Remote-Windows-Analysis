from rest_framework import serializers
from .models import SecurityEvent, ProcessLog, NetworkLog, FileLog, UserAccount, UserGroup, UserProfileModel, UserSession, EnvironmentInfo

class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = ['event_type', 'event_id', 'source', 'timestamp', 'details']

class ProcessLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProcessLog
        fields = ['name', 'pid', 'path', 'start_time']

class NetworkLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkLog
        fields = ['local_address', 'remote_address', 'state', 'timestamp']

class FileLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileLog
        fields = ['event_type', 'path', 'change_type', 'old_path', 'timestamp']

class UserAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = ['username', 'domain', 'sid']

class UserGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGroup
        fields = ['groups']

class UserProfileModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfileModel
        fields = ['profile_path', 'roaming_profile']

class UserSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSession
        fields = ['session_id', 'start_time']

class EnvironmentInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = EnvironmentInfo
        fields = ['os_version', 'machine_name', 'processor_count']

class UserDataSerializer(serializers.Serializer):
    account_info = UserAccountSerializer()
    groups = UserGroupSerializer()
    profiles = UserProfileModelSerializer()
    sessions = UserSessionSerializer(many=True)
    environment = EnvironmentInfoSerializer()

class BulkDataSerializer(serializers.Serializer):
    client_id = serializers.CharField(max_length=36)
    logs = serializers.ListSerializer(child=serializers.DictField())