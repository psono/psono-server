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

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)


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
        :return: 200
        :rtype:
        """

        yubikey_otps = []

        for ga in Yubikey_OTP.objects.filter(user=request.user).all():
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
        :return: 201 / 400
        :rtype:
        """

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='CREATE_YUBIKEY_OTP_ERROR', errors=serializer.errors)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        yubikey_otp = serializer.validated_data.get('yubikey_otp')

        yubikey_id = yubikey_otp[:12]

        # normally encrypt secrets, so they are not stored in plaintext with a random nonce
        secret_key = hashlib.sha256(settings.DB_SECRET.encode('utf-8')).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        encrypted_yubikey_id = crypto_box.encrypt(str(yubikey_id).encode("utf-8"), nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
        encrypted_yubikey_id_hex = nacl.encoding.HexEncoder.encode(encrypted_yubikey_id)

        new_yubikey = Yubikey_OTP.objects.create(
            user=request.user,
            title= serializer.validated_data.get('title'),
            yubikey_id = encrypted_yubikey_id_hex
        )

        log_info(logger=logger, request=request, status='HTTP_201_CREATED',
                 event='CREATE_YUBIKEY_OTP_SUCCESS', request_resource=new_yubikey.id)

        return Response({
            "id": new_yubikey.id,
        },
            status=status.HTTP_201_CREATED)

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

        if request_misses_uuid(request, 'yubikey_otp_id'):

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST',
                     event='DELETE_YUBIKEY_OTP_NO_YUBIKEY_OTP_ID_ERROR')

            return Response({"error": "IdNoUUID", 'message': "Yubikey OTP ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)


        # check if the YubiKey exists
        try:
            yubikey_otp = Yubikey_OTP.objects.get(pk=request.data['yubikey_otp_id'], user=request.user)
        except Yubikey_OTP.DoesNotExist:

            log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                     event='DELETE_YUBIKEY_OTP_YUBIKEY_OTP_NOT_EXIST_ERROR')

            return Response({"message": "YubiKey does not exist.",
                         "resource_id": request.data['yubikey_otp_id']}, status=status.HTTP_403_FORBIDDEN)

        # delete it
        yubikey_otp.delete()

        log_info(logger=logger, request=request, status='HTTP_200_OK',
                 event='DELETE_YUBIKEY_OTP_SUCCESS', request_resource=request.data['yubikey_otp_id'])

        return Response(status=status.HTTP_200_OK)
