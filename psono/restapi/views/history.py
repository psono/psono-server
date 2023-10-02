from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..permissions import IsAuthenticated
from ..utils import readbuffer, decrypt_with_db_secret

from ..app_settings import (
    ReadHistorySerializer
)

from ..authentication import TokenAuthentication

class HistoryView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, request, secret_history_id, *args, **kwargs):
        """
        Returns a specific history item

        Necessary Rights:
            - read on secret

        :param request:
        :type request:
        :param secret_id:
        :type secret_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        serializer = ReadHistorySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        secret_history = serializer.validated_data.get('secret_history')

        try:
            callback_pass = decrypt_with_db_secret(secret_history.callback_pass)
        except:
            callback_pass = ''  #nosec -- not [B105:hardcoded_password_string]

        return Response({
            'create_date': secret_history.create_date.isoformat(),
            'write_date': secret_history.write_date.isoformat(),
            'data': readbuffer(secret_history.data),
            'data_nonce': secret_history.data_nonce if secret_history.data_nonce else '',
            'type': secret_history.type,
            'callback_url': secret_history.callback_url,
            'callback_user': secret_history.callback_user,
            'callback_pass': callback_pass,
        }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
