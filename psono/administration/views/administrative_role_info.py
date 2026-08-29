from django.db.models import Prefetch
from restapi.models import AdministrativeRoleAssignmentTenant


def assignment_tenants_prefetch():
    return Prefetch(
        "tenants",
        queryset=AdministrativeRoleAssignmentTenant.objects.select_related(
            "tenant"
        ).only("id", "assignment_id", "tenant_id", "tenant__id", "tenant__name"),
    )


def assignment_info(assignment):
    if "tenants" in getattr(assignment, "_prefetched_objects_cache", {}):
        tenants = sorted(assignment.tenants.all(), key=lambda item: item.tenant.name)
    else:
        tenants = assignment.tenants.select_related("tenant").order_by("tenant__name")
    return {
        "id": assignment.id,
        "role_id": assignment.role_id,
        "role_name": assignment.role.name,
        "user_id": assignment.user_id,
        "username": assignment.user.username,
        "is_global": assignment.is_global,
        "tenant_ids": [tenant.tenant_id for tenant in tenants],
        "tenants": [
            {"id": tenant.tenant_id, "name": tenant.tenant.name} for tenant in tenants
        ],
    }


def role_info(role, include_assignments=False):
    result = {
        "id": role.id,
        "name": role.name,
        "description": role.description,
        "is_active": role.is_active,
        "is_system": role.is_system,
        "is_full_access": role.is_full_access,
        "capabilities": [item.capability for item in role.capabilities.all()],
    }
    if include_assignments:
        result["assignments"] = [
            assignment_info(assignment)
            for assignment in role.assignments.select_related("role", "user")
            .only(
                "id",
                "role_id",
                "role__name",
                "user_id",
                "user__username",
                "is_global",
            )
            .prefetch_related(assignment_tenants_prefetch())
        ]
    return result
