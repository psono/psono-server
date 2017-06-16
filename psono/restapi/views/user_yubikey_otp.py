from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    User, Yubikey_OTP
)

from ..app_settings import (
    NewYubikeyOTPSerializer
)

from ..authentication import TokenAuthentication
from ..utils import request_misses_uuid
import nacl.encoding
import nacl.utils
import nacl.secret
import hashlib


class UserYubikeyOTP(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = NewYubikeyOTPSerializer
    allowed_methods = ('GET', 'PUT', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Checks the REST Token and returns a list of a all YubiKey OTPs

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

        yubikey_otps = []

        for ga in Yubikey_OTP.objects.filter(user=user).all():
            yubikey_otps.append({
                'id': ga.id,
                'title': ga.title,
            })

        return Response({
            "yubikey_otps": yubikey_otps
        },
            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Checks the REST Token and sets a new YubiKey OTP for multifactor authentication

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

            yubikey_otp = serializer.validated_data.get('yubikey_otp')

            yubikey_id = yubikey_otp[:12]

            # normally encrypt secrets, so they are not stored in plaintext with a random nonce
            secret_key = hashlib.sha256(settings.DB_SECRET.encode('utf-8')).hexdigest()
            crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
            encrypted_yubikey_id = crypto_box.encrypt(str(yubikey_id), nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
            encrypted_yubikey_id_hex = nacl.encoding.HexEncoder.encode(encrypted_yubikey_id)

            new_yubikey = Yubikey_OTP.objects.create(
                user=user,
                title= serializer.validated_data.get('title'),
                yubikey_id = encrypted_yubikey_id_hex
            )

            return Response({
                "id": new_yubikey.id,
            },
                status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an Yubikey

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400 / 403
        """

        user = User.objects.get(pk=request.user.id)

        if request_misses_uuid(request, 'yubikey_otp_id'):
            return Response({"error": "IdNoUUID", 'message': "Yubikey OTP ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)


        # check if the YubiKey exists
        try:
            yubikey_otp = Yubikey_OTP.objects.get(pk=request.data['yubikey_otp_id'], user=user)
        except Yubikey_OTP.DoesNotExist:
            return Response({"message": "YubiKey does not exist.",
                         "resource_id": request.data['yubikey_otp_id']}, status=status.HTTP_403_FORBIDDEN)

        # delete it
        yubikey_otp.delete()

        return Response(status=status.HTTP_200_OK)
