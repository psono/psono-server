from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
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

    def get_serializer_class(self):
        if self.request.method == 'GET':
            return ReadSecretHistorySerializer
        return Serializer

    def get(self, request, secret_id, *args, **kwargs):
        """
        Lists the history of a specific secret

        Necessary Rights:
            - read on secret
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

