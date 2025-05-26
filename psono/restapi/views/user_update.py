from ..utils import encrypt_with_db_secret, get_static_bcrypt_hash_from_email
from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from ..permissions import IsAuthenticated

from ..app_settings import (
    UserUpdateSerializer
)


from ..authentication import TokenAuthentication


class UserUpdate(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('PUT', 'OPTIONS', 'HEAD')
    throttle_scope = 'user_update'

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return UserUpdateSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Checks the REST Token and updates the users email / authkey / secret and private key
        """

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        hashing_algorithm = serializer.validated_data.get('hashing_algorithm')
        hashing_parameters = serializer.validated_data.get('hashing_parameters')

        # E-Mail Change
        if 'email' in request.data and request.data['email'] is not None:
            email = str(request.data['email']).lower().strip()

            # generate bcrypt with static salt.
            # I know its bad to use static salts, but its the best solution I could come up with,
            # if you want to store emails encrypted while not having to decrypt all emails for duplicate email hunt
            # Im aware that this allows attackers with this fix salt to "mass" attack all emails.
            # if you have a better solution, please let me know.
            request.user.email_bcrypt = get_static_bcrypt_hash_from_email(email)
            request.user.email = encrypt_with_db_secret(email)

        if 'language' in request.data and request.data['language'] is not None:
            request.user.language = str(request.data['language'])

        if serializer.validated_data['zoneinfo'] is not None:
            request.user.zoneinfo = serializer.validated_data['zoneinfo']

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
        if hashing_parameters:
            request.user.hashing_parameters = hashing_parameters
        if hashing_algorithm:
            request.user.hashing_algorithm = hashing_algorithm

        request.user.save()

        return Response({"success": "User updated."},
                        status=status.HTTP_200_OK)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
