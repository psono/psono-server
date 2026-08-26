def assignment_info(assignment):
    tenants = list(
        assignment.tenants.values("tenant_id", "tenant__name").order_by("tenant__name")
    )
    return {
        "id": assignment.id,
        "role_id": assignment.role_id,
        "role_name": assignment.role.name,
        "user_id": assignment.user_id,
        "username": assignment.user.username,
        "is_global": assignment.is_global,
        "tenant_ids": [tenant["tenant_id"] for tenant in tenants],
        "tenants": [
            {"id": tenant["tenant_id"], "name": tenant["tenant__name"]}
            for tenant in tenants
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
        "capabilities": list(role.capabilities.values_list("capability", flat=True)),
    }
    if include_assignments:
        result["assignments"] = [
            assignment_info(assignment)
            for assignment in role.assignments.select_related(
                "role", "user"
            ).prefetch_related("tenants")
        ]
    return result
