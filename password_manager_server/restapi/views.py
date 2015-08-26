from django.contrib.auth import login, logout
from django.conf import settings
from utils import generate_activation_code

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from models import Token, Data_Store
from rest_framework.generics import RetrieveUpdateAPIView

from .app_settings import (
    UserDetailsSerializer, LoginSerializer,
    AuthkeyChangeSerializer, RegisterSerializer, VerifyEmailSerializer,
    DatastoreSerializer, DatastoreOverviewSerializer
)
from rest_framework.exceptions import PermissionDenied

from django.core.mail import send_mail
from django.template.loader import render_to_string

from authentication import TokenAuthentication


class RegisterView(GenericAPIView):
    """
    Accepts the email and authkey and creates a new Data Store Owner
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

            msg_plain = render_to_string('email/registration_successful.txt', {
                'email': self.request.data.get('email', ''),
                'activation_code': activation_code
            })
            msg_html = render_to_string('email/registration_successful.html', {
                'email': self.request.data.get('email', ''),
                'activation_code': activation_code
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
    Verifies the activation code sent via email and updates the Owner

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
            owner = serializer.validated_data['owner']
            owner.is_email_active = True
            owner.save()

            return Response({"success": "Successfully activated."},
                            status=status.HTTP_201_CREATED)
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

        owner = serializer.validated_data['owner']
        token = self.token_model.objects.create(owner=owner)

        # if getattr(settings, 'REST_SESSION_LOGIN', True):
        #     login(self.request, owner)

        return Response({"token": token.clear_text_key},
            status=status.HTTP_200_OK)


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


class UserDetailsView(RetrieveUpdateAPIView):

    """
    Returns User's details in JSON format.

    Accepts the following GET parameters: token
    Accepts the following POST parameters:
        Required: token
        Optional: email, first_name, last_name and UserProfile fields
    Returns the updated UserProfile and/or User object.
    """
    serializer_class = UserDetailsSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user

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



class DatastoreView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    the datastore if the necessary access rights are granted

    Accept the following POST parameters: datastore_id (optional)
    Return a list of the datastores or the datastore
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = DatastoreSerializer

    def get(self, request, uuid = None, *args, **kwargs):

        if not uuid:
            # TODO Discuss if many datastorages may make sense
            storages, created = Data_Store.objects.get_or_create(owner=request.user, type='password', description='default')

            if not isinstance(storages, (list, tuple)):
                storages = [storages]

            # TODO Discuss type of data field and base64 encoding or not and if encoding then client or serverside
            return Response({'datastores': DatastoreOverviewSerializer(storages, many=True).data},
                status=status.HTTP_200_OK)
        else:
            datastore = Data_Store.objects.get(pk=uuid)

            return Response(DatastoreSerializer(datastore).data,
                status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        # TODO implement insert statement for enterprise users
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, uuid = None, *args, **kwargs):

        try:
            datastore = Data_Store.objects.get(pk=uuid)
        except Data_Store.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)


        if not datastore.owner == request.user:
            raise PermissionDenied({"message":"You don't have permission to access",
                            "object_id": datastore.id})

        datastore.data = str(request.data['data'])
        datastore.save()

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)

