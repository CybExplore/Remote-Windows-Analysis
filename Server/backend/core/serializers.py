from rest_framework import serializers
from core.models import SecurityEvent, ServerInfo, FirewallStatus
from accounts.models import CustomUser


class ServerInfoSerializer(serializers.ModelSerializer):
    client = serializers.CharField(source='client.sid', write_only=True)

    class Meta:
        model = ServerInfo
        fields = ['id', 'client', 'machine_name', 'os_version', 'processor_count', 'timestamp', 'is_64bit', 'created_at']
        read_only_fields = ['id', 'created_at']

    def validate(self, data):
        client_sid = data.get('client')
        if not client_sid:
            raise serializers.ValidationError("Client SID is required.")

        # Verify the client exists
        try:
            client = CustomUser.objects.get(sid=client_sid)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Client with this SID does not exist.")

        # Check authentication: token or client_id/client_secret
        request = self.context.get('request')
        client_id = request.data.get('client_id')
        client_secret = request.data.get('client_secret')
        if client_id and client_secret:
            # Assuming CustomUser has client_id and client_secret fields
            if not (client.client_id == client_id and client.client_secret == client_secret):
                raise serializers.ValidationError("Invalid client_id or client_secret.")
        elif request.user and request.user.is_authenticated:
            # Token-based authentication: ensure user matches SID
            if request.user.sid != client_sid:
                raise serializers.ValidationError("You are not authorized to submit data for this client.")
        else:
            raise serializers.ValidationError("Authentication required (token or client_id/client_secret).")

        data['client'] = client
        return data

    def create(self, validated_data):
        client = validated_data.pop('client')
        return ServerInfo.objects.create(client=client, **validated_data)


class SecurityEventSerializer(serializers.ModelSerializer):
    client = serializers.CharField(source='client.sid', read_only=True)

    class Meta:
        model = SecurityEvent
        fields = [
            'id', 'client', 'event_id', 'time_created', 'description', 'source', 'logon_type',
            'failure_reason', 'target_account', 'group_name', 'privilege_name',
            'process_name', 'service_name', 'created_at'
        ]
        read_only_fields = ['id', 'client', 'created_at']

    def validate(self, data):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError("Authentication required.")
        data['client'] = request.user
        return data


class FirewallStatusSerializer(serializers.ModelSerializer):
    client = serializers.CharField(source='client.sid', read_only=True)

    class Meta:
        model = FirewallStatus
        fields = ['id', 'client', 'is_enabled', 'profile', 'timestamp', 'created_at']
        read_only_fields = ['id', 'client', 'created_at']

    def validate(self, data):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError("Authentication required.")
        data['client'] = request.user
        return data