from django.db import IntegrityError, transaction
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from restapi.models import (
    AdministrativeRoleAssignment,
    AdministrativeRoleAssignmentTenant,
)
from administration.permissions import AdminPermission
from administration.serializers.administrative_role import (
    AdministrativeRoleAssignmentSerializer,
)
from administration.views.administrative_role_info import (
    assignment_info,
    assignment_tenants_prefetch,
)
from restapi.authentication import TokenAuthentication


class AdministrativeRoleAssignmentView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    serializer_class = AdministrativeRoleAssignmentSerializer

    def get(self, request, assignment_id=None):
        serializer = self.get_serializer(
            data={"assignment_id": assignment_id} if assignment_id else {}
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        if assignment_id:
            return Response(assignment_info(serializer.validated_data["assignment"]))
        assignments = (
            AdministrativeRoleAssignment.objects.select_related("role", "user")
            .only(
                "id",
                "role_id",
                "role__name",
                "user_id",
                "user__username",
                "is_global",
            )
            .prefetch_related(assignment_tenants_prefetch())
        )
        return Response(
            {"assignments": [assignment_info(assignment) for assignment in assignments]}
        )

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            with transaction.atomic():
                assignment = AdministrativeRoleAssignment.objects.create(
                    role=serializer.validated_data["role"],
                    user=serializer.validated_data["user"],
                    is_global=serializer.validated_data["is_global"],
                    created_by=request.user,
                )
                AdministrativeRoleAssignmentTenant.objects.bulk_create(
                    AdministrativeRoleAssignmentTenant(
                        assignment=assignment, tenant=tenant
                    )
                    for tenant in serializer.validated_data["tenants"]
                )
        except IntegrityError:
            return Response(
                {"non_field_errors": ["ADMINISTRATIVE_ROLE_ASSIGNMENT_ALREADY_EXISTS"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(assignment_info(assignment), status=status.HTTP_201_CREATED)

    def put(self, request, assignment_id=None):
        data = dict(request.data)
        data["assignment_id"] = assignment_id or data.get("assignment_id")
        serializer = self.get_serializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        assignment = serializer.validated_data["assignment"]
        try:
            with transaction.atomic():
                assignment.role = serializer.validated_data["role"]
                assignment.user = serializer.validated_data["user"]
                assignment.is_global = serializer.validated_data["is_global"]
                assignment.save()
                assignment.tenants.all().delete()
                AdministrativeRoleAssignmentTenant.objects.bulk_create(
                    AdministrativeRoleAssignmentTenant(
                        assignment=assignment, tenant=tenant
                    )
                    for tenant in serializer.validated_data["tenants"]
                )
        except IntegrityError:
            return Response(
                {"non_field_errors": ["ADMINISTRATIVE_ROLE_ASSIGNMENT_ALREADY_EXISTS"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(assignment_info(assignment))

    def delete(self, request, assignment_id=None):
        data = dict(request.data)
        data["assignment_id"] = assignment_id or data.get("assignment_id")
        serializer = self.get_serializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.validated_data["assignment"].delete()
        return Response({})
