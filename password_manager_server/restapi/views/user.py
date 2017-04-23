from django.conf import settings
from ..utils import generate_activation_code, authenticate
from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from ..models import (
    Token, User, Google_Authenticator
)

from ..app_settings import (
    LoginSerializer, GAVerifySerializer, ActivateTokenSerializer,
    RegisterSerializer, VerifyEmailSerializer,
    UserUpdateSerializer, NewGASerializer,
    UserPublicKeySerializer
)
from rest_framework.exceptions import PermissionDenied
from django.core.exceptions import ValidationError

from django.core.mail import send_mail
from django.template.loader import render_to_string

from ..authentication import TokenAuthentication
from ..utils import is_uuid
import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box
import bcrypt
import hashlib
import pyotp


class RegisterView(GenericAPIView):
    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'registration'

    serializer_class = RegisterSerializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Accepts the username, email and authkey and creates a new user
        if the username (and email address) do not already exist

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        def splitAt(w, n):
            for i in range(0, len(w), n):
                yield w[i:i + n]

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():

            activation_code = generate_activation_code(serializer.validated_data['email'])

            # serializer.validated_data['email'] gets now encrypted
            serializer.save()

            # if len(self.request.data.get('base_url', '')) < 1:
            #    raise exceptions.ValidationError(msg)

            activation_link = self.request.data.get('base_url', '') + 'activate.html#/activation-code/' + activation_code

            msg_plain = render_to_string('email/registration_successful.txt', {
                'email': self.request.data.get('email', ''),
                'username': self.request.data.get('username', ''),
                'activation_code': activation_code,
                'activation_link': activation_link,
                'activation_link_with_wbr': "<wbr>".join(splitAt(activation_link,40)),
                'host_url': settings.HOST_URL,
            })
            msg_html = render_to_string('email/registration_successful.html', {
                'email': self.request.data.get('email', ''),
                'username': self.request.data.get('username', ''),
                'activation_code': activation_code,
                'activation_link': activation_link,
                'activation_link_with_wbr': "<wbr>".join(splitAt(activation_link,40)),
                'host_url': settings.HOST_URL,
            })

            send_mail(
                'Registration successful',
                msg_plain,
                settings.EMAIL_FROM,
                [self.request.data.get('email', '')],
                html_message=msg_html,
            )

            return Response({"success": "Successfully registered."},
                            status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

class VerifyEmailView(GenericAPIView):

    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    serializer_class = VerifyEmailSerializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Verifies the activation code sent via email and updates the user

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']
            user.is_email_active = True
            user.save()

            return Response({"success": "Successfully activated."},
                            status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



class LoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Check the credentials and return the REST Token
        if the credentials are valid and authenticated.

        Accepts the following POST parameters: email, authkey
        Returns the token.

        Clients should authenticate by passing the token key in the "Authorization"
        HTTP header, prepended with the string "Token ". For example:

            Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a

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

        user = serializer.validated_data['user']

        if Google_Authenticator.objects.filter(user=user).exists():
            google_authenticator_2fa = True
        else:
            google_authenticator_2fa = False

        token = self.token_model.objects.create(user=user, google_authenticator_2fa=google_authenticator_2fa)

        # our public / private key box
        box = PrivateKey.generate()

        # our hex encoded public / private keys
        server_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        server_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)
        user_session_public_key_hex = serializer.validated_data['user_session_public_key']
        user_public_key_hex = user.public_key

        # both our crypto boxes
        user_crypto_box = Box(PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                              PublicKey(user_public_key_hex, encoder=nacl.encoding.HexEncoder))
        session_crypto_box = Box(PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                                 PublicKey(user_session_public_key_hex, encoder=nacl.encoding.HexEncoder))

        # encrypt session secret with session_crypto_box
        session_secret_key_nonce = nacl.utils.random(Box.NONCE_SIZE)
        session_secret_key_nonce_hex = nacl.encoding.HexEncoder.encode(session_secret_key_nonce)
        encrypted = session_crypto_box.encrypt(token.secret_key, session_secret_key_nonce)
        session_secret_key = encrypted[len(session_secret_key_nonce):]
        session_secret_key_hex = nacl.encoding.HexEncoder.encode(session_secret_key)

        # encrypt user_validator with user_crypto_box
        user_validator_nonce = nacl.utils.random(Box.NONCE_SIZE)
        user_validator_nonce_hex = nacl.encoding.HexEncoder.encode(user_validator_nonce)
        encrypted = user_crypto_box.encrypt(token.user_validator, user_validator_nonce)
        user_validator = encrypted[len(user_validator_nonce):]
        user_validator_hex = nacl.encoding.HexEncoder.encode(user_validator)


        # if getattr(settings, 'REST_SESSION_LOGIN', True):
        #     login(self.request, user)

        required_multifactors = []

        if token.google_authenticator_2fa:
            required_multifactors.append('google_authenticator_2fa')

        return Response({
            "token": token.clear_text_key,
            "required_multifactors": required_multifactors,
            "session_public_key": server_session_public_key_hex,
            "session_secret_key": session_secret_key_hex,
            "session_secret_key_nonce": session_secret_key_nonce_hex,
            "user_validator": user_validator_hex,
            "user_validator_nonce": user_validator_nonce_hex,
            "user": {
                "public_key": user.public_key,
                "private_key": user.private_key,
                "private_key_nonce": user.private_key_nonce,
                "user_sauce": user.user_sauce
            }
        },status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



class GAVerifyView(GenericAPIView):

    permission_classes = (AllowAny,)
    serializer_class = GAVerifySerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Validates a Google Authenticator based OATH-TOTP

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

        # Google Authenticator challenge has been solved, so lets update the token
        token = serializer.validated_data['token']
        token.google_authenticator_2fa = False
        token.save()

        return Response(status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


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


class LogoutView(APIView):

    """
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    token_model = Token

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request):
        """
        Delete the current used token object.

        Accepts/Returns nothing.

        :param request:
        :type request:
        :return:
        :rtype:
        """
        try:
            token_hash=TokenAuthentication.get_token_hash(request)
            self.token_model.objects.filter(key=token_hash).delete()
        except:
            pass

        return Response({"success": "Successfully logged out."},
                        status=status.HTTP_200_OK)


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

        if 'google_authenticator_id' not in request.data or not is_uuid(request.data['google_authenticator_id']):
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
