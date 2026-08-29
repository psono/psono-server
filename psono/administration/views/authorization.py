from administration.permissions import AdminPermission
from administration.utils.capabilities import CAPABILITIES
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from restapi.authentication import TokenAuthentication


class AuthorizationView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)

    def get(self, request):
        if request.user.is_superuser:
            return Response(
                {
                    "is_superuser": True,
                    "roles": [],
                    "capabilities": {
                        code: {"global": True, "tenant_ids": []}
                        for code in CAPABILITIES
                    },
                }
            )

        assignments = (
            request.user.administrative_role_assignments.filter(role__is_active=True)
            .select_related("role")
            .prefetch_related("role__capabilities", "tenants__tenant")
        )
        roles = []
        capabilities = {}
        for assignment in assignments:
            tenant_ids = [
                str(scope.tenant_id)
                for scope in assignment.tenants.all()
                if scope.tenant.is_active
            ]
            roles.append(
                {
                    "id": assignment.role_id,
                    "name": assignment.role.name,
                    "is_global": assignment.is_global,
                    "tenant_ids": tenant_ids,
                }
            )
            codes = (
                CAPABILITIES.keys()
                if assignment.role.is_full_access
                else [item.capability for item in assignment.role.capabilities.all()]
            )
            for code in codes:
                if code not in CAPABILITIES:
                    continue
                effective = capabilities.setdefault(
                    code, {"global": False, "tenant_ids": []}
                )
                if assignment.is_global:
                    effective["global"] = True
                    effective["tenant_ids"] = []
                elif not effective["global"]:
                    effective["tenant_ids"] = sorted(
                        set(effective["tenant_ids"]) | set(tenant_ids)
                    )
        return Response(
            {"is_superuser": False, "roles": roles, "capabilities": capabilities}
        )
