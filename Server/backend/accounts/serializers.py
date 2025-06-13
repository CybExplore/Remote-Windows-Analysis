# accounts/serializers.py
import logging
import secrets
import uuid

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import Group, User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import RegexValidator
from django.utils import timezone
from rest_framework import serializers

from accounts.models import Client, CustomUser, PasswordHistory, UserProfile

logger = logging.getLogger(__name__)


class ClientRegisterSerializer(serializers.Serializer):
    client_id = serializers.UUIDField(
        default=uuid.uuid4, help_text="Unique client ID (UUID)"
    )
    secret_id = serializers.CharField(
        max_length=128, default=secrets.token_urlsafe(32), help_text="Client secret ID"
    )
    sid = serializers.CharField(
        max_length=50,
        validators=[
            RegexValidator(
                regex=r"^S-1-5-21-\d+-\d+-\d+-\d+$", message="Invalid SID format"
            )
        ],
        help_text="Windows Security Identifier",
    )
    user_email = serializers.EmailField(help_text="User email address", label="Email ")
    full_name = serializers.CharField(
        max_length=500, required=False, allow_blank=True, help_text="User full name"
    )

    def validate(self, data):
        user_email = data["user_email"].lower()
        sid = data["sid"]

        # Check if user exists or create one
        user, created = CustomUser.objects.get_or_create(
            email__iexact=user_email,
            defaults={
                "sid": sid,
                "full_name": data.get("full_name") or user_email.split("@")[0],
                "password": make_password(secrets.token_urlsafe(16)),
            },
        )
        if created:
            send_mail(
                subject=f"Welcome to {settings.SITE_NAME}",
                message=f"""
                Welcome to {settings.SITE_NAME}!

                Your account has been created with the following details:
                SID: {sid}
                Email: {user_email}
                Temporary Password: (Check with admin for your temporary password)

                Please log in at {settings.SITE_URL}/login and change your password immediately.

                Thank you,
                The {settings.SITE_NAME} Team
                """,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user_email],
                fail_silently=False,
            )
            logger.info(f"Created new user: {user_email}")

        data["user"] = user
        return data

    def create(self, validated_data):
        user = validated_data.pop("user")
        client_id = validated_data["client_id"]
        secret_id = validated_data["secret_id"]
        sid = validated_data["sid"]

        client, created = Client.objects.get_or_create(
            client_id=client_id,
            sid=sid,
            user=user,
            defaults={"secret_id": make_password(secret_id)},
        )
        if not created:
            raise serializers.ValidationError(
                {"client_id": "Client with this client_id or sid already exists"}
            )

        return client

    def to_representation(self, instance):
        return {
            "status": "success",
            "client_id": str(instance.client_id),
            "sid": instance.sid,
            "user_email": instance.user.email,
        }


class UserRegisterSerializer(serializers.ModelSerializer):
    sid = serializers.CharField(
        max_length=50,
        validators=[
            RegexValidator(
                regex=r"^S-1-5-21-\d+-\d+-\d+-\d+$", message="Invalid SID format"
            )
        ],
    )
    email = serializers.EmailField()
    full_name = serializers.CharField(max_length=500, allow_blank=True)

    class Meta:
        model = CustomUser
        fields = ["sid", "email", "full_name"]

    def validate_email(self, value):
        value = value.lower()
        if CustomUser.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("User with this email already exists")
        return value

    def validate_sid(self, value):
        if CustomUser.objects.filter(sid=value).exists():
            raise serializers.ValidationError("User with this SID already exists")
        return value

    def create(self, validated_data):
        temporary_password = secrets.token_urlsafe(16)
        user = CustomUser.objects.create_user(
            sid=validated_data["sid"],
            email=validated_data["email"].lower(),
            password=temporary_password,
            full_name=validated_data.get("full_name", ""),
        )  # type: ignore
        send_mail(
            subject=f"Welcome to {settings.SITE_NAME}",
            message=f"""
            Welcome to {settings.SITE_NAME}!

            Your account has been created with the following details:
            SID: {validated_data['sid']}
            Email: {validated_data['email']}
            Temporary Password: {temporary_password}

            Please log in at {settings.SITE_URL}/login and change your password immediately.

            Thank you,
            The {settings.SITE_NAME} Team
            """,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[validated_data["email"]],
            fail_silently=False,
        )
        logger.info(f"Created new user: {validated_data['email']}")
        return user


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ["url", "sid", "email", "groups"]


class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ["url", "email"]


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "email", "sid"]


class ClientSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField()

    class Meta:
        model = Client
        fields = ["client_id", "secret_id", "sid", "user_email", "full_name"]
        extra_kwargs = {
            "client_id": {"required": True},
            "secret_id": {"required": True},
            "sid": {"required": True},
            "user_email": {"required": True},
            "full_name": {"required": True},
        }

    # def validate_user_email(self, value):
    #     try:
    #         CustomUser.objects.get(email__iexact=value)
    #     except CustomUser.DoesNotExist:
    #         raise serializers.ValidationError("No user found with this email address.")
    #     return value

    def validate_user_email(self, value):
        return value.lower()

    def validate_client_id(self, value):
        if Client.objects.filter(client_id=value).exists():
            raise serializers.ValidationError(
                "A client with this client_id already exists."
            )
        return value

    def validate_sid(self, value):
        validator = RegexValidator(
            regex=r"^S-1-5-21-\d+-\d+-\d+-\d+$", message="Invalid SID format"
        )
        validator(value)
        return value

    def validate(self, data):
        user_email = data["user_email"]
        sid = data["sid"]
        temporary_password = secrets.token_urlsafe(16)

        user, created = CustomUser.objects.get_or_create(
            email__iexact=user_email,
            defaults={
                "sid": sid,
                "full_name": data.get("full_name") or user_email.split("@")[0],
                "password": make_password(temporary_password),
                "is_first_login": True,
            },
        )
        if created:
            try:
                send_mail(
                    subject=f"Welcome to {settings.SITE_NAME}",
                    message=f"""
                    Welcome to {settings.SITE_NAME}!
                    Your account has been created:
                    SID: {sid}
                    Email: {user_email}
                    Temporary Password: {temporary_password}
                    Please log in at {settings.SITE_URL}/login and change your password.
                    """,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user_email],
                    fail_silently=False,
                )
                logger.info(f"Created new user: {user_email}")
            except Exception as e:
                logger.error(f"Failed to send email to {user_email}: {str(e)}")
                raise serializers.ValidationError("Failed to send registration email.")
        data["user"] = user
        return data

    def create(self, validated_data):
        user = validated_data.pop("user")
        validated_data["secret_id"] = make_password(validated_data["secret_id"])
        client = Client.objects.create(user=user, **validated_data)
        return client


class ClientAuthSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    sid = serializers.CharField(required=False)
    client_id = serializers.CharField(required=True)
    secret_id = serializers.CharField(required=True)

    def validate(self, data):
        if not (data.get("email") or data.get("sid")):
            raise serializers.ValidationError("Either email or sid must be provided.")

        try:
            client = Client.objects.get(client_id=data["client_id"])
            if not check_password(data["client_secret"], client.secret_id):
                raise serializers.ValidationError("Invalid client secret.")

            user = None
            if data.get("email"):
                user = CustomUser.objects.filter(email__iexact=data["email"]).first()
            elif data.get("sid"):
                user = CustomUser.objects.filter(sid=data["sid"]).first()

            if not user or client.user != user:
                raise serializers.ValidationError("Invalid client or user credentials.")
            if not user.is_active or (
                hasattr(user, "profile") and user.profile.locked_out
            ):
                raise serializers.ValidationError("User account is disabled or locked.")

        except Client.DoesNotExist:
            raise serializers.ValidationError("Client not found.")

        data["user"] = user
        return data


class UserLoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ["locked_out", "last_login_ip"]


class AuthSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(
        required=True, help_text="User's SID or email address"
    )
    password = serializers.CharField(write_only=True, style={"input_type": "password"})
    client_id = serializers.CharField(
        required=False, help_text="OAuth2 Client ID (optional for initial setup)"
    )
    client_secret = serializers.CharField(
        required=False,
        help_text="OAuth2 Client Secret (optional for initial setup)",
        write_only=True,
    )

    def validate(self, attrs):
        identifier = attrs.get("identifier")
        password = attrs.get("password")

        # Authenticate using SID or email
        user = authenticate(
            request=self.context.get("request"),
            identifier=identifier,
            password=password,
        )

        if not user:
            raise serializers.ValidationError(
                "Invalid SID/email or password", code="authorization"
            )

        if not user.is_active:
            raise serializers.ValidationError(
                "User account is disabled", code="authentication"
            )

        if hasattr(user, "profile") and user.profile.locked_out:  # type: ignore
            raise serializers.ValidationError(
                "Account locked due to too many failed attempts", code="authentication"
            )

        attrs["user"] = user
        return attrs


class TokenResponseSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    token_type = serializers.CharField(default="Bearer")
    expires_in = serializers.IntegerField()
    refresh_token = serializers.CharField(required=False)
    scope = serializers.CharField(default="read write")
    sid = serializers.CharField(source="user.sid")
    email = serializers.CharField(source="user.email")


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}
    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}
    )

    def validate_current_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        return value

    def validate(self, data):  # type: ignore
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match"}
            )
        return data


class PasswordResetRequestSerializer(serializers.Serializer):
    identifier = serializers.CharField(
        required=True, help_text="User's SID or email address"
    )


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}
    )
    token = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField(write_only=True)

    def validate(self, data):  # type: ignore
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match"}
            )
        return data
