from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import (
    UpdateMembershipSerializer,
    DeleteMembershipSerializer,
)
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import User_Group_Membership
from administration.serializers.read_administration import ReadMembershipSerializer


class MembershipView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    allowed_methods = ("GET", "OPTIONS", "HEAD")

    def get_serializer_class(self):
        if self.request.method == "PUT":
            return UpdateMembershipSerializer
        elif self.request.method == "DELETE":
            return DeleteMembershipSerializer
        return ReadMembershipSerializer

    def get(self, request, *args, **kwargs):
        """
        Returns a list of all memberships
        """

        serializer = ReadMembershipSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        access = serializer.validated_data["admin_access"]
        queryset = User_Group_Membership.objects.select_related(
            "user", "group"
        ).order_by("-create_date")
        if not access.is_global:
            queryset = queryset.filter(
                group__tenant_memberships__tenant_id__in=access.tenant_ids,
                group__tenant_memberships__tenant__is_active=True,
            ).distinct()
        memberships = []
        for g in queryset:
            memberships.append(
                {
                    "id": g.id,
                    "create_date": g.create_date,
                    "username": g.user.username,
                    "group": g.group.name,
                }
            )

        return Response({"memberships": memberships}, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):

        serializer = UpdateMembershipSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        membership = serializer.validated_data.get("membership")
        group_admin = serializer.validated_data.get("group_admin")
        share_admin = serializer.validated_data.get("share_admin")

        require_save = False
        if group_admin is not None:
            membership.group_admin = group_admin
            require_save = True
        if share_admin is not None:
            membership.share_admin = share_admin
            require_save = True

        if require_save:
            membership.save()

        return Response({}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a membership
        """

        serializer = DeleteMembershipSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        membership = serializer.validated_data.get("membership")

        # delete it
        membership.delete()

        return Response({}, status=status.HTTP_200_OK)
