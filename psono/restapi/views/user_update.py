from django.conf import settings
from ..utils import authenticate, encrypt_with_db_secret
from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..app_settings import (
    UserUpdateSerializer
)
from rest_framework.exceptions import PermissionDenied


from ..authentication import TokenAuthentication
import nacl.encoding
import nacl.utils
import nacl.secret
import bcrypt
import hashlib


class UserUpdate(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = UserUpdateSerializer
    allowed_methods = ('PUT', 'OPTIONS', 'HEAD')
    throttle_scope = 'user_update'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Checks the REST Token and updates the users email / authkey / secret and private key

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype: 200 / 400 / 403
        """

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user, error_code = authenticate(username=request.user.username, authkey=str(request.data['authkey_old']))

        if not user:
            raise PermissionDenied({"message":"Your old password was not right."})

        # E-Mail Change
        if 'email' in request.data and request.data['email'] is not None:
            email = str(request.data['email']).lower().strip()

            # generate bcrypt with static salt.
            # I know its bad to use static salts, but its the best solution I could come up with,
            # if you want to store emails encrypted while not having to decrypt all emails for duplicate email hunt
            # Im aware that this allows attackers with this fix salt to "mass" attack all passwords.
            # if you have a better solution, please let me know.
            request.user.email_bcrypt = bcrypt.hashpw(email.encode(), settings.EMAIL_SECRET_SALT.encode()).decode().replace(settings.EMAIL_SECRET_SALT, '', 1)
            request.user.email = encrypt_with_db_secret(email)

        # Password Change
        if 'authkey' in request.data and request.data['authkey'] is not None:
            request.user.authkey = make_password(str(request.data['authkey']))
        if 'secret_key' in request.data and request.data['secret_key'] is not None:
            request.user.secret_key = str(request.data['secret_key'])
        if 'secret_key_nonce' in request.data and request.data['secret_key_nonce'] is not None:
            request.user.secret_key_nonce = str(request.data['secret_key_nonce'])
        if 'private_key' in request.data and request.data['private_key'] is not None:
            request.user.private_key = str(request.data['private_key'])
        if 'private_key_nonce' in request.data and request.data['private_key_nonce'] is not None:
            request.user.private_key_nonce = str(request.data['private_key_nonce'])
        if 'user_sauce' in request.data and request.data['user_sauce'] is not None:
            request.user.user_sauce = str(request.data['user_sauce'])

        request.user.save()

        return Response({"success": "User updated."},
                        status=status.HTTP_200_OK)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
