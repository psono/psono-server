from django.conf import settings
from ..utils import authenticate
from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    User, Google_Authenticator, Yubikey_OTP
)

from ..app_settings import (
    UserUpdateSerializer, NewGASerializer,
    NewYubikeyOTPSerializer, UserPublicKeySerializer
)
from rest_framework.exceptions import PermissionDenied
from django.core.exceptions import ValidationError


from ..authentication import TokenAuthentication
from ..utils import request_misses_uuid
import nacl.encoding
import nacl.utils
import nacl.secret
import bcrypt
import hashlib
import pyotp


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
            secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
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


class UserSearch(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = UserPublicKeySerializer
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Check the REST Token and returns the user's public key. To identify the user either the email or the user_id needs
        to be provided

        Return the user's public key

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """
        if 'user_id' in request.data and request.data['user_id']:
            try:
                user = User.objects.get(pk=str(request.data['user_id']))
            except ValidationError:
                return Response({"error": "IdNoUUID", 'message': "User ID is badly formed and no uuid"},
                                status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_id'])}, status=status.HTTP_403_FORBIDDEN)

        elif 'user_username' in request.data and request.data['user_username']:
            try:
                user = User.objects.get(username=str(request.data['user_username']))
            except User.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_username'])}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        return Response({'id': user.id, 'public_key': user.public_key, 'username': user.username},
                status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
