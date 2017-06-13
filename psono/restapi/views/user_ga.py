from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    User, Google_Authenticator
)

from ..app_settings import (
    NewGASerializer
)


from ..authentication import TokenAuthentication
from ..utils import request_misses_uuid
import nacl.encoding
import nacl.utils
import nacl.secret
import hashlib
import pyotp


class UserGA(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = NewGASerializer
    allowed_methods = ('GET', 'PUT', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Checks the REST Token and returns a list of a all google authenticators

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        user = User.objects.get(pk=request.user.id)

        google_authenticators = []

        for ga in Google_Authenticator.objects.filter(user=user).all():
            google_authenticators.append({
                'id': ga.id,
                'title': ga.title,
            })

        return Response({
            "google_authenticators": google_authenticators
        },
            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Checks the REST Token and sets a new google authenticator for multifactor authentication

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        user = User.objects.get(pk=request.user.id)

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            secret = pyotp.random_base32()

            # normally encrypt secrets, so they are not stored in plaintext with a random nonce
            secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
            crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
            encrypted_secret = crypto_box.encrypt(str(secret), nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
            encrypted_secret_hex = nacl.encoding.HexEncoder.encode(encrypted_secret)

            new_ga = Google_Authenticator.objects.create(
                user=user,
                title= serializer.validated_data.get('title'),
                secret = encrypted_secret_hex
            )

            return Response({
                "id": new_ga.id,
                "secret": str(secret)
            },
                status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an Google Authenticator

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400 / 403
        """

        user = User.objects.get(pk=request.user.id)

        if request_misses_uuid(request, 'google_authenticator_id'):
            return Response({"error": "IdNoUUID", 'message': "Google Authenticator ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)


        # check if google authenticator exists
        try:
            google_authenticator = Google_Authenticator.objects.get(pk=request.data['google_authenticator_id'], user=user)
        except Google_Authenticator.DoesNotExist:
            return Response({"message": "Google authenticator does not exist.",
                         "resource_id": request.data['google_authenticator_id']}, status=status.HTTP_403_FORBIDDEN)

        # delete it
        google_authenticator.delete()

        return Response(status=status.HTTP_200_OK)
