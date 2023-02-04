from django.conf import settings
from django.utils import timezone
from django.contrib.auth.hashers import make_password
import nacl, json
from nacl.public import PrivateKey, PublicKey, Box
from nacl import encoding

from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny

from ..app_settings import (
    EnableNewPasswordSerializer,
    SetNewPasswordSerializer,
)

from ..models import (
    Google_Authenticator,
    Yubikey_OTP,
    Duo
)


from ..utils import readbuffer

class PasswordView(GenericAPIView):

    permission_classes = (AllowAny,)
    allowed_methods = ('PUT', 'POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'password'

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Second step of the recovery code password reset.
        Validates the code and sets the new password.

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400 / 403
        :rtype:
        """

        serializer = SetNewPasswordSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        update_data = serializer.validated_data['update_data']
        update_data_nonce = serializer.validated_data['update_data_nonce']
        recovery_code = serializer.validated_data['recovery_code']
        user = serializer.validated_data['user']
        hashing_algorithm = serializer.validated_data['hashing_algorithm']
        hashing_parameters = serializer.validated_data['hashing_parameters']

        try:
            crypto_box = Box(PrivateKey(recovery_code.verifier, encoder=nacl.encoding.HexEncoder),
                             PublicKey(user.public_key, encoder=nacl.encoding.HexEncoder))

            update_data_dec = json.loads(crypto_box.decrypt(update_data, update_data_nonce).decode())

            authkey = make_password(str(update_data_dec['authkey']))
            private_key = update_data_dec['private_key']
            private_key_nonce = update_data_dec['private_key_nonce']
            secret_key = update_data_dec['secret_key']
            secret_key_nonce = update_data_dec['secret_key_nonce']

        except:
            return Response({"message": "Validation failed"}, status=status.HTTP_403_FORBIDDEN)

        recovery_code.verifier  = ''
        recovery_code.verifier_issue_date  = None
        recovery_code.save()

        user.authkey = authkey
        user.private_key = private_key
        user.private_key_nonce = private_key_nonce
        user.secret_key = secret_key
        user.secret_key_nonce = secret_key_nonce
        user.google_authenticator_enabled = False
        user.webauthn_enabled = False
        user.yubikey_otp_enabled = False
        user.duo_enabled = False
        user.hashing_algorithm = hashing_algorithm
        user.hashing_parameters = hashing_parameters
        user.save()

        # Delete 2 Factors
        Google_Authenticator.objects.filter(user=user).delete()
        Yubikey_OTP.objects.filter(user=user).delete()
        Duo.objects.filter(user=user).delete()

        return Response({}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        First step of the password reset with a recovery code

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400/ 403
        :rtype:
        """

        serializer = EnableNewPasswordSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.validated_data['user']
        recovery_code = serializer.validated_data['recovery_code']

        verifier_box = PrivateKey.generate()
        public_key = verifier_box.public_key.encode(encoder=encoding.HexEncoder)


        verifier_issue_date = timezone.now()

        recovery_code.verifier = verifier_box.encode(encoder=encoding.HexEncoder).decode()
        recovery_code.verifier_issue_date  = verifier_issue_date
        recovery_code.save()

        return Response({
            'recovery_data': readbuffer(recovery_code.recovery_data),
            'recovery_data_nonce': recovery_code.recovery_data_nonce,
            'recovery_sauce': recovery_code.recovery_sauce,
            'user_sauce': user.user_sauce,
            'hashing_algorithm': user.hashing_algorithm,
            'hashing_parameters': user.hashing_parameters,
            'verifier_public_key': public_key.decode(),
            'verifier_time_valid': settings.RECOVERY_VERIFIER_TIME_VALID
        }, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)