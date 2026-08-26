from dataclasses import dataclass

from django.db.models import Q
from restapi.models import AdministrativeRoleAssignment

from .capabilities import CAPABILITIES


@dataclass(frozen=True)
class AdministrativeAccess:
    is_global: bool
    tenant_ids: frozenset
    can_access_protected_users: bool = False

    def allows_tenants(self, tenant_ids):
        tenant_ids = {str(tenant_id) for tenant_id in tenant_ids}
        return self.is_global or tenant_ids.issubset(self.tenant_ids)

    def allows_user(self, user):
        if not self.can_access_protected_users and (
            user.is_superuser
            or user.administrative_role_assignments.filter(
                role__is_active=True
            ).exists()
        ):
            return False
        if self.is_global:
            return True
        return user.tenant_memberships.filter(
            tenant_id__in=self.tenant_ids, tenant__is_active=True
        ).exists()

    def allows_group(self, group):
        if self.is_global:
            return True
        return group.tenant_memberships.filter(
            tenant_id__in=self.tenant_ids, tenant__is_active=True
        ).exists()

    def filter_users(self, queryset):
        if not self.can_access_protected_users:
            queryset = queryset.exclude(
                Q(is_superuser=True)
                | Q(administrative_role_assignments__role__is_active=True)
            )
        if self.is_global:
            return queryset.distinct()
        return queryset.filter(
            tenant_memberships__tenant_id__in=self.tenant_ids,
            tenant_memberships__tenant__is_active=True,
        ).distinct()

    def filter_user_relations(
        self, queryset, user_prefix="user__", apply_distinct=True
    ):
        if not self.can_access_protected_users:
            queryset = queryset.exclude(
                Q(**{f"{user_prefix}is_superuser": True})
                | Q(
                    **{
                        f"{user_prefix}administrative_role_assignments__role__is_active": True
                    }
                )
            )
        if self.is_global:
            return queryset
        queryset = queryset.filter(
            **{
                f"{user_prefix}tenant_memberships__tenant_id__in": self.tenant_ids,
                f"{user_prefix}tenant_memberships__tenant__is_active": True,
            }
        )
        return queryset.distinct() if apply_distinct else queryset

    def filter_groups(self, queryset):
        if self.is_global:
            return queryset
        return queryset.filter(
            tenant_memberships__tenant_id__in=self.tenant_ids,
            tenant_memberships__tenant__is_active=True,
        ).distinct()

    def filter_group_relations(self, queryset, group_prefix="group__"):
        if self.is_global:
            return queryset
        return queryset.filter(
            **{
                f"{group_prefix}tenant_memberships__tenant_id__in": self.tenant_ids,
                f"{group_prefix}tenant_memberships__tenant__is_active": True,
            }
        ).distinct()

    def visible_tenant_ids(self, tenant_ids):
        if self.is_global:
            return list(tenant_ids)
        return [
            tenant_id for tenant_id in tenant_ids if str(tenant_id) in self.tenant_ids
        ]


def _capability_assignment_queryset(user, capability):
    return (
        AdministrativeRoleAssignment.objects.filter(
            user=user,
            role__is_active=True,
        )
        .filter(
            Q(role__is_full_access=True) | Q(role__capabilities__capability=capability)
        )
        .select_related("role")
        .prefetch_related("tenants__tenant")
        .distinct()
    )


def resolve_administrative_access(user, capability):
    if not user or not getattr(user, "is_authenticated", False):
        return None
    if user.is_superuser:
        return AdministrativeAccess(
            is_global=True,
            tenant_ids=frozenset(),
            can_access_protected_users=True,
        )
    if capability not in CAPABILITIES:
        return None

    assignments = list(_capability_assignment_queryset(user, capability))
    if not assignments:
        return None
    if any(assignment.is_global for assignment in assignments):
        return AdministrativeAccess(is_global=True, tenant_ids=frozenset())

    tenant_ids = {
        str(scope.tenant_id)
        for assignment in assignments
        for scope in assignment.tenants.all()
        if scope.tenant.is_active
    }
    if not tenant_ids:
        return None
    return AdministrativeAccess(is_global=False, tenant_ids=frozenset(tenant_ids))


def user_has_administrative_capabilities(user):
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True

    assignments = (
        AdministrativeRoleAssignment.objects.filter(user=user, role__is_active=True)
        .filter(
            Q(role__is_full_access=True)
            | Q(role__capabilities__capability__in=CAPABILITIES.keys())
        )
        .prefetch_related("tenants__tenant")
        .distinct()
    )
    for assignment in assignments:
        if assignment.is_global:
            return True
        if any(scope.tenant.is_active for scope in assignment.tenants.all()):
            return True
    return False
