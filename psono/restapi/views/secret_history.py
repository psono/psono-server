from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from ..models import (
    Secret_History,
)

from ..app_settings import (
    ReadSecretHistorySerializer
)

from ..authentication import TokenAuthentication

class SecretHistoryView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, request, secret_id = None, *args, **kwargs):
        """
        Lists a the history of a specific secret

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

        serializer = ReadSecretHistorySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        secret = serializer.validated_data.get('secret')

        history_items = Secret_History.objects.filter(secret_id=secret.id).values('id', 'create_date', 'user__username')

        history = []
        for item in history_items:
            history.append({
                'id': str(item['id']),
                'create_date': item['create_date'],
                'username': item['user__username'],
            })

        return Response({
            'history': history,
        }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
