from administration.utils.capabilities import (
    CAPABILITIES,
    capability_is_tenant_scopeable,
)
from rest_framework import exceptions, serializers
from restapi.models import (
    AdministrativeRole,
    AdministrativeRoleAssignment,
    Tenant,
    User,
)

from .admin_access import AdminCapabilitySerializerMixin


class AdministrativeRoleSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    role_id = serializers.UUIDField(required=False)
    name = serializers.CharField(max_length=128, required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    is_active = serializers.BooleanField(required=False)
    capabilities = serializers.ListField(
        child=serializers.CharField(max_length=128), required=False
    )

    def validate(self, attrs):
        self.validate_superuser()
        role_id = attrs.get("role_id")
        role = None
        if role_id:
            try:
                role = AdministrativeRole.objects.get(pk=role_id)
                attrs["role"] = role
            except AdministrativeRole.DoesNotExist:
                raise exceptions.ValidationError("NO_PERMISSION_OR_NOT_EXIST")

        name = attrs.get("name")
        if name is not None:
            duplicate_names = AdministrativeRole.objects.filter(name=name)
            if role is not None:
                duplicate_names = duplicate_names.exclude(pk=role.pk)
            if duplicate_names.exists():
                raise exceptions.ValidationError(
                    {"name": "ADMINISTRATIVE_ROLE_NAME_ALREADY_EXISTS"}
                )

        capabilities = attrs.get("capabilities")
        if capabilities is not None:
            invalid = sorted(set(capabilities) - CAPABILITIES.keys())
            if invalid:
                raise exceptions.ValidationError(
                    {"capabilities": ["INVALID_CAPABILITY", *invalid]}
                )
            attrs["capabilities"] = list(dict.fromkeys(capabilities))
            if (
                role is not None
                and role.assignments.filter(is_global=False).exists()
                and any(
                    not capability_is_tenant_scopeable(capability)
                    for capability in attrs["capabilities"]
                )
            ):
                raise exceptions.ValidationError("ROLE_REQUIRES_GLOBAL_SCOPE")
        if self.context["request"].method == "POST" and not attrs.get("name"):
            raise exceptions.ValidationError({"name": "FIELD_REQUIRED"})
        return attrs


class AdministrativeRoleAssignmentSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    assignment_id = serializers.UUIDField(required=False)
    role_id = serializers.UUIDField(required=False)
    user_id = serializers.UUIDField(required=False)
    is_global = serializers.BooleanField(required=False)
    tenant_ids = serializers.ListField(child=serializers.UUIDField(), required=False)

    def validate(self, attrs):
        self.validate_superuser()
        assignment_id = attrs.get("assignment_id")
        assignment = None
        if assignment_id:
            try:
                assignment = AdministrativeRoleAssignment.objects.select_related(
                    "role", "user"
                ).get(pk=assignment_id)
            except AdministrativeRoleAssignment.DoesNotExist:
                raise exceptions.ValidationError("NO_PERMISSION_OR_NOT_EXIST")
            attrs["assignment"] = assignment

        if assignment is None and self.context["request"].method == "GET":
            return attrs

        role_id = attrs.get("role_id") or (assignment.role_id if assignment else None)
        user_id = attrs.get("user_id") or (assignment.user_id if assignment else None)
        if not role_id or not user_id:
            raise exceptions.ValidationError("ROLE_AND_USER_REQUIRED")
        try:
            role = AdministrativeRole.objects.prefetch_related("capabilities").get(
                pk=role_id, is_active=True
            )
            user = User.objects.get(pk=user_id)
        except (AdministrativeRole.DoesNotExist, User.DoesNotExist):
            raise exceptions.ValidationError("NO_PERMISSION_OR_NOT_EXIST")

        duplicate_assignments = AdministrativeRoleAssignment.objects.filter(
            role=role, user=user
        )
        if assignment is not None:
            duplicate_assignments = duplicate_assignments.exclude(pk=assignment.pk)
        if duplicate_assignments.exists():
            raise exceptions.ValidationError(
                "ADMINISTRATIVE_ROLE_ASSIGNMENT_ALREADY_EXISTS"
            )

        is_global = attrs.get(
            "is_global", assignment.is_global if assignment is not None else False
        )
        tenant_ids = attrs.get("tenant_ids")
        if tenant_ids is None:
            tenant_ids = (
                list(assignment.tenants.values_list("tenant_id", flat=True))
                if assignment is not None
                else []
            )
        if len(tenant_ids) != len(set(tenant_ids)):
            raise exceptions.ValidationError("DUPLICATE_TENANT")
        tenants = list(Tenant.objects.filter(pk__in=tenant_ids, is_active=True))
        if len(tenants) != len(set(tenant_ids)):
            raise exceptions.ValidationError("TENANT_NOT_EXIST")
        if is_global and tenants:
            raise exceptions.ValidationError("GLOBAL_ASSIGNMENT_HAS_TENANTS")
        if not is_global and not tenants:
            raise exceptions.ValidationError("TENANT_REQUIRED")

        role_capabilities = [item.capability for item in role.capabilities.all()]
        if not is_global and (
            role.is_full_access
            or any(
                not capability_is_tenant_scopeable(capability)
                for capability in role_capabilities
            )
        ):
            raise exceptions.ValidationError("ROLE_REQUIRES_GLOBAL_SCOPE")

        attrs.update(
            {
                "role": role,
                "user": user,
                "is_global": is_global,
                "tenants": tenants,
            }
        )
        return attrs
