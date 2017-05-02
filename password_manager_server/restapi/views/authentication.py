from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from ..models import (
    Token, Google_Authenticator, Yubikey_OTP
)

from ..app_settings import (
    LoginSerializer, GAVerifySerializer,
    YubikeyOTPVerifySerializer, ActivateTokenSerializer,
    LogoutSerializer,
    RegisterSerializer, VerifyEmailSerializer,
)
from ..utils import generate_activation_code
from ..authentication import TokenAuthentication

from datetime import timedelta
import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box
import hashlib


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

        if Yubikey_OTP.objects.filter(user=user).exists():
            yubikey_otp_2fa = True
        else:
            yubikey_otp_2fa = False

        token = self.token_model.objects.create(
            user=user,
            google_authenticator_2fa=google_authenticator_2fa,
            yubikey_otp_2fa=yubikey_otp_2fa,
            device_fingerprint=serializer.validated_data['device_fingerprint'],
            device_description=serializer.validated_data['device_description'],
        )

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

        if token.yubikey_otp_2fa:
            required_multifactors.append('yubikey_otp_2fa')

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
    throttle_scope = 'ga_verify'

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



class YubikeyOTPVerifyView(GenericAPIView):

    permission_classes = (AllowAny,)
    serializer_class = YubikeyOTPVerifySerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'yubikey_otp_verify'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Validates a Yubikey OTP

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

        # Yubikey OTP challenge has been solved, so lets update the token
        token = serializer.validated_data['token']
        token.yubikey_otp_2fa = False
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


class SessionView(GenericAPIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = LogoutSerializer
    token_model = Token
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):

        time_threshold = timezone.now() - timedelta(seconds=settings.TOKEN_TIME_VALID)

        sessions = []
        for session in self.token_model.objects.filter(user=request.user, create_date__gt=time_threshold, active=True):
            sessions.append({
                "id": str(session.id),
                "create_date": session.create_date.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "device_description": session.device_description,
                "current_session": session.id == request.auth.id,
            })

        return Response({
            'sessions': sessions
        }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


class LogoutView(GenericAPIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = LogoutSerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

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


        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            token_hash = serializer.validated_data['token_hash']
            self.token_model.objects.filter(key=token_hash, user=request.user).delete()
        except:
            pass

        return Response({"success": "Successfully logged out."},
                        status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)








