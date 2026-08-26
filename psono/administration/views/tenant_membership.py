from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from restapi.models import TenantGroupMembership, TenantUserMembership
from administration.permissions import AdminPermission
from administration.serializers.tenant import TenantMembershipSerializer
from restapi.authentication import TokenAuthentication


class TenantMembershipView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    serializer_class = TenantMembershipSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        tenant = serializer.validated_data["tenant"]
        if serializer.validated_data.get("user"):
            membership, created = TenantUserMembership.objects.get_or_create(
                tenant=tenant,
                user=serializer.validated_data["user"],
                defaults={"created_by": request.user},
            )
        else:
            membership, created = TenantGroupMembership.objects.get_or_create(
                tenant=tenant,
                group=serializer.validated_data["group"],
                defaults={"created_by": request.user},
            )
        return Response(
            {"id": membership.id},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def delete(self, request):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        tenant = serializer.validated_data["tenant"]
        if serializer.validated_data.get("user"):
            TenantUserMembership.objects.filter(
                tenant=tenant, user=serializer.validated_data["user"]
            ).delete()
        else:
            TenantGroupMembership.objects.filter(
                tenant=tenant, group=serializer.validated_data["group"]
            ).delete()
        return Response({})
