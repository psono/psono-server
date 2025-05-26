from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from ..permissions import IsAuthenticated

from ..app_settings import (
    ReadShareRightsSerializer,
)

from ..authentication import TokenAuthentication

class ShareRightsView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'GET':
            return ReadShareRightsSerializer
        return Serializer

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, request, share_id, *args, **kwargs):
        """
        Returns all share rights of a specified share. Including the share rights of other people as long as the user
        who requests it has the "grant" right, and is allowed to see them.
        """

        serializer = ReadShareRightsSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        share = serializer.validated_data.get('share')
        own_share_rights = serializer.validated_data.get('own_share_rights')

        user_share_rights = []
        group_share_rights = []

        for u in share.user_share_rights.exclude(creator__isnull=True, accepted__isnull=True).exclude(creator__isnull=True, accepted=False).all():

            right = {
                'id': u.id,
                'create_date': u.create_date.isoformat(),
                'write_date': u.write_date.isoformat(),
                'accepted': u.accepted,
                'read': u.read,
                'write': u.write,
                'grant': u.grant,
                'user_id': u.user_id,
                'share_id': u.share_id,
                'username': u.user.username,
            }

            user_share_rights.append(right)

        for u in share.group_share_rights.all():

            right = {
                'id': u.id,
                'create_date': u.create_date.isoformat(),
                'write_date': u.write_date.isoformat(),
                'accepted': True,
                'read': u.read,
                'write': u.write,
                'grant': u.grant,
                'group_id': u.group_id,
                'share_id': u.share_id,
                'group_name': u.group.name,
            }

            group_share_rights.append(right)

        response = {
            'id': share.id,
            'own_share_rights': own_share_rights,
            'user_share_rights': user_share_rights,
            'group_share_rights': group_share_rights
        }

        return Response(response, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
