from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from ..models import (
    Token
)

from ..app_settings import (
    ActivateTokenSerializer,
)
import nacl.encoding
import nacl.utils
import nacl.secret
import hashlib

class ActivateTokenView(GenericAPIView):

    permission_classes = (AllowAny,)
    serializer_class = ActivateTokenSerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Activates a token

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """
        serializer = self.get_serializer(data=self.request.data)

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        token = serializer.validated_data['token']

        token.active = True
        token.user_validator = None
        token.save()

        # decrypt user email address
        secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        encrypted_email = nacl.encoding.HexEncoder.decode(token.user.email)
        decrypted_email = crypto_box.decrypt(encrypted_email)

        return Response({
            "user": {
                "id": token.user.id,
                "email": decrypted_email,
                "secret_key": token.user.secret_key,
                "secret_key_nonce": token.user.secret_key_nonce
            }
        },status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)