from rest_framework import exceptions, serializers
from restapi.models import Group, Tenant, User

from .admin_access import AdminCapabilitySerializerMixin


class TenantSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    tenant_id = serializers.UUIDField(required=False)
    name = serializers.CharField(max_length=128, required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    is_active = serializers.BooleanField(required=False)
    page = serializers.IntegerField(required=False, min_value=0)
    page_size = serializers.IntegerField(required=False, min_value=1)
    search = serializers.CharField(required=False, allow_blank=True)
    ordering = serializers.ChoiceField(
        required=False,
        choices=(
            "name",
            "-name",
            "description",
            "-description",
            "is_active",
            "-is_active",
            "user_count",
            "-user_count",
            "group_count",
            "-group_count",
        ),
    )

    def validate(self, attrs):
        self.validate_superuser()
        tenant_id = attrs.get("tenant_id")
        tenant = None
        if tenant_id:
            try:
                tenant = Tenant.objects.get(pk=tenant_id)
                attrs["tenant"] = tenant
            except Tenant.DoesNotExist:
                raise exceptions.ValidationError("NO_PERMISSION_OR_NOT_EXIST")
        if self.context["request"].method == "POST" and not attrs.get("name"):
            raise exceptions.ValidationError({"name": "FIELD_REQUIRED"})
        name = attrs.get("name")
        if name is not None:
            duplicate_names = Tenant.objects.filter(name=name)
            if tenant is not None:
                duplicate_names = duplicate_names.exclude(pk=tenant.pk)
            if duplicate_names.exists():
                raise exceptions.ValidationError({"name": "TENANT_NAME_ALREADY_EXISTS"})
        return attrs


class TenantMembershipSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    tenant_id = serializers.UUIDField(required=True)
    user_id = serializers.UUIDField(required=False)
    group_id = serializers.UUIDField(required=False)

    def validate(self, attrs):
        self.validate_superuser()
        try:
            attrs["tenant"] = Tenant.objects.get(pk=attrs["tenant_id"])
        except Tenant.DoesNotExist:
            raise exceptions.ValidationError("NO_PERMISSION_OR_NOT_EXIST")

        if bool(attrs.get("user_id")) == bool(attrs.get("group_id")):
            raise exceptions.ValidationError("USER_OR_GROUP_REQUIRED")
        if attrs.get("user_id"):
            try:
                attrs["user"] = User.objects.get(pk=attrs["user_id"])
            except User.DoesNotExist:
                raise exceptions.ValidationError("NO_PERMISSION_OR_NOT_EXIST")
        if attrs.get("group_id"):
            try:
                attrs["group"] = Group.objects.get(pk=attrs["group_id"])
            except Group.DoesNotExist:
                raise exceptions.ValidationError("NO_PERMISSION_OR_NOT_EXIST")
        return attrs
