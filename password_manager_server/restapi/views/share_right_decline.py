from ..utils import request_misses_uuid
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..models import (
    User_Share_Right
)

from ..authentication import TokenAuthentication

class ShareRightDeclineView(GenericAPIView):

    """
    Check the REST Token and the object permissions and updates the share right as declined and removes title and keys
    from the share right
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Mark a Share_right as declined. In addition deletes now unnecessary information like title and encryption key.

        :param request:
        :param uuid: share_right_id
        :param args:
        :param kwargs:
        :return: 200 / 403 / 404
        """

        if request_misses_uuid(request, 'share_right_id'):
            return Response({"error": "IdNoUUID", 'message': "Share Right ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        if not request.data['share_right_id']:
            return Response({"message": "UUID for share not specified."}, status=status.HTTP_404_NOT_FOUND)

        try:
            user_share_right_obj = User_Share_Right.objects.get(id=request.data['share_right_id'], user=request.user, accepted=None)

            user_share_right_obj.accepted = False
            user_share_right_obj.title = ''
            user_share_right_obj.title_nonce = ''
            user_share_right_obj.type = ''
            user_share_right_obj.type_nonce = ''
            user_share_right_obj.key_type = ''
            user_share_right_obj.key = ''
            user_share_right_obj.key_nonce = ''
            user_share_right_obj.save()

        except User_Share_Right.DoesNotExist:
            return Response({"message":"You don't have permission to access it or it does not exist or you already accepted or declined this share.",
                            "resource_id": request.data['share_right_id']}, status=status.HTTP_403_FORBIDDEN)

        return Response(status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
