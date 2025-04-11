from rest_framework import serializers
from .models import SecurityLog, ProcessInfo, ServiceInfo, NetworkConnection, SystemConfig, UserSession

# Serializer for SecurityLog model
class SecurityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityLog
        fields = '__all__'

# Serializer for ProcessInfo model
class ProcessInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProcessInfo
        fields = '__all__'

# Serializer for ServiceInfo model
class ServiceInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceInfo
        fields = '__all__'

# Serializer for NetworkConnection model
class NetworkConnectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkConnection
        fields = '__all__'

# Serializer for SystemConfig model
class SystemConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemConfig
        fields = '__all__'

# Serializer for UserSession model
class UserSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSession
        fields = '__all__'
