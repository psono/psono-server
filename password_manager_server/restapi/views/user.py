from django.conf import settings
from ..utils import generate_activation_code

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from ..models import (
    Token, User
)

from ..app_settings import (
    LoginSerializer,
    AuthkeyChangeSerializer, RegisterSerializer, VerifyEmailSerializer,
    UserPublicKeySerializer
)

from django.core.mail import send_mail
from django.template.loader import render_to_string

from ..authentication import TokenAuthentication


class RegisterView(GenericAPIView):
    """
    Accepts the email and authkey and creates a new user
    if the email address does not already exist

    Method: POST

    Fields: email, authkey

    Returns: nothing
    """

    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    serializer_class = RegisterSerializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():

            activation_code = generate_activation_code(serializer.data['email'])

            serializer.save()

            # if len(self.request.data.get('base_url', '')) < 1:
            #    raise exceptions.ValidationError(msg)

            activation_link = self.request.data.get('base_url', '') + 'data/activate.html#/activation-code/' + activation_code

            msg_plain = render_to_string('email/registration_successful.txt', {
                'email': self.request.data.get('email', ''),
                'activation_code': activation_code,
                'activation_link': activation_link
            })
            msg_html = render_to_string('email/registration_successful.html', {
                'email': self.request.data.get('email', ''),
                'activation_code': activation_code,
                'activation_link': activation_link
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

class VerifyEmailView(GenericAPIView):
    """
    Verifies the activation code sent via email and updates the user

    Method: POST

    Fields: activation_code

    Returns: nothing
    """

    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    serializer_class = VerifyEmailSerializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):

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



class LoginView(GenericAPIView):

    """
    Check the credentials and return the REST Token
    if the credentials are valid and authenticated.

    Accepts the following POST parameters: email, authkey
    Returns the token.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ". For example:

        Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a

    """
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    token_model = Token

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=self.request.data)

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.validated_data['user']
        token = self.token_model.objects.create(user=user)

        # if getattr(settings, 'REST_SESSION_LOGIN', True):
        #     login(self.request, user)

        return Response({
            "token": token.clear_text_key,
            "user": {
                "id": user.id,
                "public_key": user.public_key,
                "private_key": user.private_key,
                "private_key_nonce": user.private_key_nonce,
                "secret_key": user.secret_key,
                "secret_key_nonce": user.secret_key_nonce
            }
        },status=status.HTTP_200_OK)


class LogoutView(APIView):

    """
    Delete the current used token object.

    Accepts/Returns nothing.
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (AllowAny,)
    token_model = Token

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request):
        #TODO Create this logout function
        try:
            token_hash=TokenAuthentication.get_token_hash(request)
            self.token_model.objects.filter(key=token_hash).delete()
        except:
            pass

        return Response({"success": "Successfully logged out."},
                        status=status.HTTP_200_OK)


class AuthkeyChangeView(GenericAPIView):

    """
    Calls Django Auth SetAuthkeyForm save method.

    Accepts the following POST parameters: new_password1, new_password2
    Returns the success/fail message.
    """

    serializer_class = AuthkeyChangeSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save()
        return Response({"success": "New password has been saved."})



class UserSearch(GenericAPIView):

    """
    Check the REST Token and returns the user's public key. To identify the user either the email or the user_id needs
    to be provided

    Return the user's public key
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = UserPublicKeySerializer

    def post(self, request, *args, **kwargs):

        if 'user_id' in request.data and request.data['user_id']:
            try:
                user = User.objects.get(pk=str(request.data['user_id']))
                if user is None:
                    return Response({"message":"You don't have permission to access or it does not exist.",
                                    "resource_id": str(request.data['user_id'])}, status=status.HTTP_404_NOT_FOUND)
            except User.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_id'])}, status=status.HTTP_404_NOT_FOUND)

        elif 'user_email' in request.data and request.data['user_email']:
            try:
                user = User.objects.get(email=str(request.data['user_email']))
                if user is None:
                    return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_email'])}, status=status.HTTP_404_NOT_FOUND)
            except User.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_email'])}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        return Response({'id': user.id, 'public_key': user.public_key, 'email': user.email},
                status=status.HTTP_200_OK)
