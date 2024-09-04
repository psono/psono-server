from rest_framework import status
from django.db.models import F
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..permissions import IsAuthenticated
from ..utils import decrypt_with_db_secret
from ..app_settings import BulkReadSecretSerializer
from ..authentication import TokenAuthentication
from ..models import Secret

class BulkSecretReadView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def post(self, request, *args, **kwargs):
        """
        Lists multiple secrets

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
        :return: 200 / 400 / 403
        :rtype:
        """

        serializer = BulkReadSecretSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        secrets = serializer.validated_data.get('secrets')

        read_secrets = []

        for secret in secrets:
            try:
                callback_pass = decrypt_with_db_secret(secret.callback_pass)
            except:
                callback_pass = ''  #nosec -- not [B105:hardcoded_password_string]

            read_secrets.append({
                'id': str(secret.id),
                'create_date': secret.create_date.isoformat(),
                'write_date': secret.write_date.isoformat(),
                'data': secret.data.decode(),
                'data_nonce': secret.data_nonce if secret.data_nonce else '',
                'type': secret.type,
                'read_count': secret.read_count + 1,
                'callback_url': secret.callback_url,
                'callback_user': secret.callback_user,
                'callback_pass': callback_pass,
            })

        if len(read_secrets) > 0:
            Secret.objects.filter(pk__in=[s['id'] for s in read_secrets]).update(read_count=F('read_count') + 1)

        return Response({"secrets": read_secrets}, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
