from administration.permissions import AdminPermission
from administration.serializers.tenant import TenantSerializer
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db.models import Count
from django.db.models.deletion import ProtectedError
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from restapi.authentication import TokenAuthentication
from restapi.models import Tenant


def tenant_info(tenant, include_members=False):
    user_count = (
        tenant.user_count
        if hasattr(tenant, "user_count")
        else tenant.user_memberships.count()
    )
    group_count = (
        tenant.group_count
        if hasattr(tenant, "group_count")
        else tenant.group_memberships.count()
    )
    result = {
        "id": tenant.id,
        "name": tenant.name,
        "description": tenant.description,
        "is_active": tenant.is_active,
        "create_date": tenant.create_date,
        "write_date": tenant.write_date,
        "user_count": user_count,
        "group_count": group_count,
    }
    if include_members:
        result["users"] = [
            {"id": item.user_id, "username": item.user.username}
            for item in tenant.user_memberships.select_related("user").order_by(
                "user__username"
            )
        ]
        result["groups"] = [
            {"id": item.group_id, "name": item.group.name}
            for item in tenant.group_memberships.select_related("group").order_by(
                "group__name"
            )
        ]
    return result


class TenantView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    serializer_class = TenantSerializer

    def get(self, request, tenant_id=None):
        serializer = self.get_serializer(
            data={"tenant_id": tenant_id} if tenant_id else request.query_params
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        if tenant_id:
            return Response(tenant_info(serializer.validated_data["tenant"], True))

        tenant_qs = Tenant.objects.annotate(
            user_count=Count("user_memberships", distinct=True),
            group_count=Count("group_memberships", distinct=True),
        ).order_by(serializer.validated_data.get("ordering", "name"))
        search = serializer.validated_data.get("search")
        if search:
            tenant_qs = tenant_qs.filter(name__icontains=search)

        count = None
        page_size = serializer.validated_data.get("page_size")
        if page_size:
            paginator = Paginator(tenant_qs, page_size)
            count = paginator.count
            tenant_qs = paginator.page(
                serializer.validated_data.get("page", 0) + 1
            ).object_list

        return Response(
            {
                "count": count,
                "tenants": [tenant_info(tenant) for tenant in tenant_qs],
            }
        )

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            tenant = Tenant.objects.create(
                name=serializer.validated_data["name"],
                description=serializer.validated_data.get("description", ""),
                is_active=serializer.validated_data.get("is_active", True),
            )
        except IntegrityError:
            return Response(
                {"name": ["TENANT_NAME_ALREADY_EXISTS"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(tenant_info(tenant), status=status.HTTP_201_CREATED)

    def put(self, request, tenant_id=None):
        data = dict(request.data)
        data["tenant_id"] = tenant_id or data.get("tenant_id")
        serializer = self.get_serializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        tenant = serializer.validated_data["tenant"]
        for field in ("name", "description", "is_active"):
            if field in serializer.validated_data:
                setattr(tenant, field, serializer.validated_data[field])
        try:
            tenant.save()
        except IntegrityError:
            return Response(
                {"name": ["TENANT_NAME_ALREADY_EXISTS"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(tenant_info(tenant))

    def delete(self, request, tenant_id=None):
        data = dict(request.data)
        data["tenant_id"] = tenant_id or data.get("tenant_id")
        serializer = self.get_serializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            serializer.validated_data["tenant"].delete()
        except ProtectedError:
            return Response(
                {"non_field_errors": ["TENANT_NOT_EMPTY"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({})
