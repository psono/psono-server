from django.db import IntegrityError, transaction
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from restapi.models import AdministrativeRole, AdministrativeRoleCapability
from administration.permissions import AdminPermission
from administration.serializers.administrative_role import AdministrativeRoleSerializer
from administration.views.administrative_role_info import role_info
from restapi.authentication import TokenAuthentication


class AdministrativeRoleView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    serializer_class = AdministrativeRoleSerializer

    def get(self, request, role_id=None):
        serializer = self.get_serializer(data={"role_id": role_id} if role_id else {})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        if role_id:
            return Response(role_info(serializer.validated_data["role"], True))
        roles = AdministrativeRole.objects.prefetch_related("capabilities").order_by(
            "name"
        )
        return Response({"roles": [role_info(role) for role in roles]})

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            with transaction.atomic():
                role = AdministrativeRole.objects.create(
                    name=serializer.validated_data["name"],
                    description=serializer.validated_data.get("description", ""),
                    is_active=serializer.validated_data.get("is_active", True),
                )
                AdministrativeRoleCapability.objects.bulk_create(
                    AdministrativeRoleCapability(role=role, capability=capability)
                    for capability in serializer.validated_data.get("capabilities", [])
                )
        except IntegrityError:
            return Response(
                {"name": ["ADMINISTRATIVE_ROLE_NAME_ALREADY_EXISTS"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(role_info(role), status=status.HTTP_201_CREATED)

    def put(self, request, role_id=None):
        data = dict(request.data)
        data["role_id"] = role_id or data.get("role_id")
        serializer = self.get_serializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        role = serializer.validated_data["role"]
        if role.is_system:
            return Response(
                {"non_field_errors": ["SYSTEM_ROLE_IMMUTABLE"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            with transaction.atomic():
                for field in ("name", "description", "is_active"):
                    if field in serializer.validated_data:
                        setattr(role, field, serializer.validated_data[field])
                role.save()
                if "capabilities" in serializer.validated_data:
                    role.capabilities.all().delete()
                    AdministrativeRoleCapability.objects.bulk_create(
                        AdministrativeRoleCapability(role=role, capability=capability)
                        for capability in serializer.validated_data["capabilities"]
                    )
        except IntegrityError:
            return Response(
                {"name": ["ADMINISTRATIVE_ROLE_NAME_ALREADY_EXISTS"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(role_info(role))

    def delete(self, request, role_id=None):
        data = dict(request.data)
        data["role_id"] = role_id or data.get("role_id")
        serializer = self.get_serializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        role = serializer.validated_data["role"]
        if role.is_system or role.assignments.exists():
            return Response(
                {"non_field_errors": ["ROLE_IN_USE_OR_IMMUTABLE"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        role.delete()
        return Response({})
