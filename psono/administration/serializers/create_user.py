from django.conf import settings
from rest_framework import serializers, exceptions
from restapi.fields import BooleanField
import bcrypt

from restapi.models import Tenant, User
from .admin_access import AdminCapabilitySerializerMixin


class CreateUserSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "users.create"

    username = serializers.EmailField(
        required=True, error_messages={"invalid": "INVALID_USERNAME_FORMAT"}
    )
    email = serializers.EmailField(
        required=True, error_messages={"invalid": "INVALID_EMAIL_FORMAT"}
    )
    password = serializers.CharField(required=False)
    language = serializers.CharField(required=False, allow_null=True, max_length=16)
    require_password_change = BooleanField(required=False)
    tenant_ids = serializers.ListField(
        child=serializers.UUIDField(), required=False, default=list
    )

    def validate(self, attrs: dict) -> dict:

        email = attrs.get("email", "")
        username = attrs.get("username", "")
        password = attrs.get("password", "")
        tenant_ids = attrs.get("tenant_ids", [])

        if len(tenant_ids) != len(set(tenant_ids)):
            raise exceptions.ValidationError("DUPLICATE_TENANT")
        tenants = list(Tenant.objects.filter(id__in=tenant_ids, is_active=True))
        if len(tenants) != len(set(tenant_ids)):
            raise exceptions.ValidationError("TENANT_NOT_EXIST")
        access = self.validate_administrative_access(tenant_ids=tenant_ids)
        if not access.is_global and not tenant_ids:
            raise exceptions.ValidationError("TENANT_REQUIRED")

        username = username.strip().lower()
        email = email.strip().lower()

        email_bcrypt = (
            bcrypt.hashpw(email.encode(), settings.EMAIL_SECRET_SALT.encode())
            .decode()
            .replace(settings.EMAIL_SECRET_SALT, "", 1)
        )

        if User.objects.filter(email_bcrypt=email_bcrypt).exists():
            msg = "USER_WITH_EMAIL_ALREADY_EXISTS"
            raise exceptions.ValidationError(msg)

        if User.objects.filter(username=username).exists():
            msg = "USER_WITH_USERNAME_ALREADY_EXISTS"
            raise exceptions.ValidationError(msg)

        attrs["username"] = username
        attrs["email"] = email
        attrs["password"] = password
        attrs["tenants"] = tenants

        return attrs
