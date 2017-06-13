from django.conf import settings
from ..utils import authenticate
from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    User
)

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
        :rtype:
        """

        user = User.objects.get(pk=request.user.id)

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():

            user = authenticate(username=user.username, authkey=str(request.data['authkey_old']))

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
                user.email_bcrypt = bcrypt.hashpw(email, settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)

                # normally encrypt emails, so they are not stored in plaintext with a random nonce
                secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
                crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
                encrypted_email = crypto_box.encrypt(email, nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
                user.email = nacl.encoding.HexEncoder.encode(encrypted_email)

            # Password Change
            if 'authkey' in request.data and request.data['authkey'] is not None:
                user.authkey = make_password(str(request.data['authkey']))
            if 'secret_key' in request.data and request.data['secret_key'] is not None:
                user.secret_key = str(request.data['secret_key'])
            if 'secret_key_nonce' in request.data and request.data['secret_key_nonce'] is not None:
                user.secret_key_nonce = str(request.data['secret_key_nonce'])
            if 'private_key' in request.data and request.data['private_key'] is not None:
                user.private_key = str(request.data['private_key'])
            if 'private_key_nonce' in request.data and request.data['private_key_nonce'] is not None:
                user.private_key_nonce = str(request.data['private_key_nonce'])
            if 'user_sauce' in request.data and request.data['user_sauce'] is not None:
                user.user_sauce = str(request.data['user_sauce'])

            user.save()

            return Response({"success": "User updated."},
                            status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
