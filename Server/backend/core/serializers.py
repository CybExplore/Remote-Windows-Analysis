from rest_framework import serializers
from core.models import SecurityEvent, ServerInfo, FirewallStatus
from accounts.serializers import CustomUserSerializer


class ServerInfoSerializer(serializers.ModelSerializer):
    client = serializers.CharField(source='client.sid')

    class Meta:
        model = ServerInfo
        fields = ['client', 'machine_name', 'os_version', 'processor_count', 'timestamp', 'is_64bit']

    def validate(self, data):
        if not data.get('client'):
            raise serializers.ValidationError("Client SID is required.")
        return data


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
    
class FirewallStatusSerializer(serializers.ModelSerializer):
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



