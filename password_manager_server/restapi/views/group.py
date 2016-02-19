from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny

from rest_framework.exceptions import PermissionDenied

from ..models import (
    Group, Share, Group_User_Right
)
from ..authentication import TokenAuthentication

class GroupView(GenericAPIView):

    """
    Check the REST Token and returns a list of all groups or the specified groups details

    Return the user's public key
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    def get(self, request, uuid = None, *args, **kwargs):

        if not uuid:

            # Generates a list of groups wherever the user has any rights for it

            try:
                groups = Group.objects.filter(group_user_rights__user=request.user).distinct()
            except Share.DoesNotExist:
                groups = []

            response = []

            for g in groups:

                response.append({
                    'id': g.id,
                    'name': g.name,
                    'user_id': g.user_id,
                })

            return Response({'groups': response},
                status=status.HTTP_200_OK)
        else:

            # Returns the specified share if the user has any rights for it and joins the user_share objects

            try:
                group = Group.objects.get(pk=uuid)
            except Group.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)


            user_share_rights = []

            for u in group.group_user_rights.filter(user=request.user):
                user_share_rights.append({
                    'id': u.id,
                    'user': u.user_id,
                    'key': u.key,
                    'key_nonce': u.key_nonce,
                    'read': u.read,
                    'write': u.write,
                    'add_share': u.add_share,
                    'remove_share': u.remove_share,
                    'grant': u.grant,
                })

            if not user_share_rights:
                raise PermissionDenied({"message":"You don't have permission to access",
                                "resource_id": group.id})

            response = {
                'id': group.id,
                'name': group.name,
                'user_id': group.user_id,
                'user_share_rights': user_share_rights
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):

        group = Group.objects.create(
            name = str(request.data['name']),
            user = request.user
        )

        Group_User_Right.objects.create(
                user = request.user,
                owner = request.user,
                group = group,
                key = str(request.data['secret_key']),
                key_nonce = str(request.data['secret_key_nonce']),
                read = True,
                write = True,
                grant = True,
                add_share=True,
                remove_share=True,
            )

        return Response({"group_id": group.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):

        #TODO Implement

        return Response(status=status.HTTP_200_OK)
