from django.utils import timezone
from django.conf import settings
from django.contrib.auth.hashers import make_password
import nacl, json, datetime
from nacl.public import PrivateKey, PublicKey, Box
from nacl import encoding

from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny

from ..authentication import TokenAuthentication
from ..app_settings import (
    CreateRecoverycodeSerializer,
    EnableNewPasswordSerializer,
    SetNewPasswordSerializer,
)
from ..models import (
    Recovery_Code, User
)




class RecoveryCodeView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):

        serializer = CreateRecoverycodeSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # delete existing Recovery Codes
        Recovery_Code.objects.filter(user=request.user).delete()

        recovery_code = Recovery_Code.objects.create(
            user = request.user,
            recovery_authkey = str(serializer.validated_data['recovery_authkey']),
            recovery_data = str(serializer.validated_data['recovery_data']),
            recovery_data_nonce = serializer.validated_data['recovery_data_nonce'],
            recovery_sauce = str(serializer.validated_data['recovery_sauce']),
        )

        return Response({
            'recovery_code_id': recovery_code.id
        }, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

class PasswordView(GenericAPIView):

    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):

        serializer = SetNewPasswordSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        username = str(serializer.validated_data['username'])
        recovery_authkey = str(serializer.validated_data['recovery_authkey'])
        update_data = nacl.encoding.HexEncoder.decode(str(serializer.validated_data['update_data']))
        update_data_nonce = nacl.encoding.HexEncoder.decode(str(serializer.validated_data['update_data_nonce']))

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"message": "Username or recovery code incorrect."}, status=status.HTTP_403_FORBIDDEN)

        try:
            recovery_code = Recovery_Code.objects.get(user_id=user.id, recovery_authkey=recovery_authkey)
        except Recovery_Code.DoesNotExist:
            return Response({"message": "Username or recovery code incorrect."}, status=status.HTTP_403_FORBIDDEN)

        if recovery_code.verifier_issue_date + datetime.timedelta(0,settings.RECOVERY_VERIFIER_TIME_VALID) < timezone.now():
            return Response({"message": "Validator expired."}, status=status.HTTP_403_FORBIDDEN)

        try:
            crypto_box = Box(PrivateKey(recovery_code.verifier, encoder=nacl.encoding.HexEncoder),
                             PublicKey(user.public_key, encoder=nacl.encoding.HexEncoder))

            update_data_dec = json.loads(crypto_box.decrypt(update_data, update_data_nonce))

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
        user.save()


        return Response({}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):

        serializer = EnableNewPasswordSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        username = str(serializer.validated_data['username'])
        recovery_authkey = str(serializer.validated_data['recovery_authkey'])

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"message": "Username or recovery code incorrect."}, status=status.HTTP_403_FORBIDDEN)

        try:
            recovery_code = Recovery_Code.objects.get(user_id=user.id, recovery_authkey=recovery_authkey)
        except Recovery_Code.DoesNotExist:
            return Response({"message": "Username or recovery code incorrect."}, status=status.HTTP_403_FORBIDDEN)

        verifier_box = PrivateKey.generate()
        public_key = verifier_box.public_key.encode(encoder=encoding.HexEncoder)


        verifier_issue_date = timezone.now()

        recovery_code.verifier  = verifier_box.encode(encoder=encoding.HexEncoder)
        recovery_code.verifier_issue_date  = verifier_issue_date
        recovery_code.save()

        return Response({
            'recovery_data': str(recovery_code.recovery_data),
            'recovery_data_nonce': recovery_code.recovery_data_nonce,
            'recovery_sauce': recovery_code.recovery_sauce,
            'user_sauce': user.user_sauce,
            'verifier_public_key': public_key,
            'verifier_time_valid': settings.RECOVERY_VERIFIER_TIME_VALID
        }, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)