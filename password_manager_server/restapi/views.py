from django.contrib.auth import login, logout
from django.conf import settings
from utils import generate_activation_code

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
import models
from rest_framework.generics import RetrieveUpdateAPIView

from .app_settings import (
    LoginSerializer,
    AuthkeyChangeSerializer, RegisterSerializer, VerifyEmailSerializer,
    DatastoreSerializer, ShareSerializer, DatastoreOverviewSerializer,
    UserPublicKeySerializer
)
from rest_framework.exceptions import PermissionDenied

from django.core.mail import send_mail
from django.template.loader import render_to_string

from django.db import IntegrityError
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
    token_model = models.Token

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

        return Response({
            "token": token.clear_text_key,
            "datastore_owner": {
                "id": owner.id,
                "public_key": owner.public_key,
                "private_key": owner.private_key,
                "private_key_nonce": owner.private_key_nonce,
                "secret_key": owner.secret_key,
                "secret_key_nonce": owner.secret_key_nonce
            }
        },status=status.HTTP_200_OK)


class LogoutView(APIView):

    """
    Delete the current used token object.

    Accepts/Returns nothing.
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (AllowAny,)
    token_model = models.Token

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
            try:
                storages = models.Data_Store.objects.filter(owner=request.user)
            except models.Data_Store.DoesNotExist:
                storages = []

            return Response({'datastores': DatastoreOverviewSerializer(storages, many=True).data},
                status=status.HTTP_200_OK)
        else:
            try:
                datastore = models.Data_Store.objects.get(pk=uuid)
            except models.Data_Store.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)

            if not datastore.owner == request.user:
                raise PermissionDenied({"message":"You don't have permission to access",
                                "resource_id": datastore.id})

            return Response(self.serializer_class(datastore).data,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        # TODO implement check for more datastores for enterprise users

        #TODO Check if secret_key and nonce exist

        try:
            datastore = models.Data_Store.objects.create(
                data = str(request.data['data']),
                data_nonce = str(request.data['data_nonce']),
                secret_key = str(request.data['secret_key']),
                secret_key_nonce = str(request.data['secret_key_nonce']),
                owner = request.user
            )
        except IntegrityError:
            return Response({"error": "DuplicateNonce", 'message': "Don't use a nonce twice"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"datastore_id": datastore.id}, status=status.HTTP_201_CREATED)

    def post(self, request, uuid = None, *args, **kwargs):

        try:
            datastore = models.Data_Store.objects.get(pk=uuid)
        except models.Data_Store.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)


        if not datastore.owner == request.user:
            raise PermissionDenied({"message":"You don't have permission to access",
                            "resource_id": datastore.id})

        if 'data' in request.data:
            datastore.data = str(request.data['data'])
        if 'data_nonce' in request.data:
            datastore.data_nonce = str(request.data['data_nonce'])
        if 'secret_key' in request.data:
            datastore.secret_key = str(request.data['secret_key'])
        if 'secret_key_nonce' in request.data:
            datastore.secret_key_nonce = str(request.data['secret_key_nonce'])

        datastore.save()

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)


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
                user = models.Data_Store_Owner.objects.get(pk=str(request.data['user_id']))
                if user is None:
                    return Response({"message":"You don't have permission to access or it does not exist.",
                                    "resource_id": str(request.data['user_id'])}, status=status.HTTP_404_NOT_FOUND)
            except models.Data_Store_Owner.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_id'])}, status=status.HTTP_404_NOT_FOUND)

        elif 'user_email' in request.data and request.data['user_email']:
            try:
                user = models.Data_Store_Owner.objects.get(email=str(request.data['user_email']))
                if user is None:
                    return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_email'])}, status=status.HTTP_404_NOT_FOUND)
            except models.Data_Store_Owner.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_email'])}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        return Response({'id': user.id, 'public_key': user.public_key, 'email': user.email},
                status=status.HTTP_200_OK)


class ShareRightsView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    the share rights if the necessary access rights are granted
    and the user is  the owner of the share

    Accept the following GET parameters: share_id (optional)
    Return a list of the shares or the share and the access rights or a message for an update of rights
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = ShareSerializer

    def get(self, request, uuid = None, *args, **kwargs):

        if not uuid:

            # Generate a list of a all shares where the owner is the user and join all user_share objects
            # Share data is not returned

            # TODO optimize query. this way its too inefficient ...

            try:
                shares = models.Share.objects.filter(owner=request.user)
            except models.Share.DoesNotExist:
                shares = []

            response = []
            for s in shares:

                user_share_rights = []
                for u in s.user_share_rights.all():
                    user_share_rights.append({
                        'id': u.id,
                        'key': u.key,
                        'key_nonce': u.key_nonce,
                        'encryption_type': u.encryption_type,
                        'approved': u.approved,
                        'read': u.read,
                        'write': u.write,
                        'grant': u.grant,
                        'revoke': u.revoke,
                        'user_id': u.user_id,
                    })

                response.append({
                    'id': s.id,
                    'type': s.type,
                    'user_share_rights': user_share_rights
                })

            return Response({'shares': response},
                status=status.HTTP_200_OK)
        else:

            # Returns the specified share if the owner is the user and join all user_share objects
            # Share data is not returned

            try:
                share = models.Share.objects.get(pk=uuid, owner=request.user)
            except models.Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)


            user_share_rights = []

            for u in share.user_share_rights.all():
                user_share_rights.append({
                    'id': u.id,
                    'key': u.key,
                    'key_nonce': u.key_nonce,
                    'encryption_type': u.encryption_type,
                    'approved': u.approved,
                    'read': u.read,
                    'write': u.write,
                    'grant': u.grant,
                    'revoke': u.revoke,
                    'user_id': u.user_id,
                })

            response = {
                'id': share.id,
                'type': share.type,
                'user_share_rights': user_share_rights
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, uuid = None, *args, **kwargs):

        if not uuid:
            return Response({"error": "NoIdProvided", 'message': "No share id provided"},
                            status=status.HTTP_400_BAD_REQUEST)
        else:

            # Adds the rights for the specified user to the user_share_rights table

            try:
                share = models.Share.objects.get(pk=uuid, owner=request.user)
            except models.Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)

            try:
                user = models.Data_Store_Owner.objects.get(pk=str(request.data['user_id']) )
            except models.Data_Store_Owner.DoesNotExist:
                return Response({"message":"Target user does not exist.",
                                "resource_id": str(request.data['user_id'])}, status=status.HTTP_404_NOT_FOUND)


            user_share_obj = models.User_Share_Right.objects.create(
                key=str(request.data['key']),
                key_nonce=str(request.data['nonce']),
                encryption_type='public',
                share=share,
                owner=request.user,
                user=user,
                approved=False,
                read=request.data['read'],
                write=request.data['write'],
            )

            return Response({"user_share_id": str(user_share_obj.id)},
                status=status.HTTP_201_CREATED)


class ShareView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    the share if the necessary access rights are granted

    Accept the following POST parameters: share_id (optional)
    Return a list of the shares or the share
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = ShareSerializer

    def get(self, request, uuid = None, *args, **kwargs):

        if not uuid:

            # Generates a list of shares wherever the user has any rights for it and joins the user_share objects

            #TODO optimize query. this way its too inefficient ...

            try:
                shares = models.Share.objects.filter(user_share_rights__user=request.user).distinct()
            except models.Share.DoesNotExist:
                shares = []

            response = []

            for s in shares:
                user_share_rights = []

                for u in s.user_share_rights.filter(user=request.user):
                    user_share_rights.append({
                        'id': u.id,
                        'key': u.key,
                        'key_nonce': u.key_nonce,
                        'encryption_type': u.encryption_type,
                        'approved': u.approved,
                        'read': u.read,
                        'write': u.write,
                        'grant': u.grant,
                        'revoke': u.revoke,
                        'owner_id': u.owner_id,
                    })

                response.append({
                    'id': s.id,
                    'data': str(s.data) if s.data else '',
                    'data_nonce': s.data_nonce if s.data_nonce else '',
                    'type': s.type,
                    'owner_id': s.owner_id,
                    'user_share_rights': user_share_rights
                })

            return Response({'shares': response},
                status=status.HTTP_200_OK)
        else:

            # Returns the specified share if the user has any rights for it and joins the user_share objects

            try:
                share = models.Share.objects.get(pk=uuid)
            except models.Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)


            user_share_rights = []

            for u in share.user_share_rights.filter(user=request.user):
                user_share_rights.append({
                    'id': u.id,
                    'key': u.key,
                    'key_nonce': u.key_nonce,
                    'encryption_type': u.encryption_type,
                    'approved': u.approved,
                    'read': u.read,
                    'write': u.write,
                    'grant': u.grant,
                    'revoke': u.revoke,
                    'owner_id': u.owner_id,
                })

            if not user_share_rights:
                raise PermissionDenied({"message":"You don't have permission to access",
                                "resource_id": share.id})

            response = {
                'id': share.id,
                'data': str(share.data) if share.data else '',
                'data_nonce': share.data_nonce if share.data_nonce else '',
                'type': share.type,
                'owner_id': share.owner_id,
                'user_share_rights': user_share_rights
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        # TODO implement check for more shares for enterprise users

        #TODO Check if secret_key and nonce exist

        try:
            share = models.Share.objects.create(
                data = str(request.data['data']),
                data_nonce = str(request.data['data_nonce']),
                owner = request.user
            )
        except IntegrityError:
            return Response({"error": "DuplicateNonce", 'message': "Don't use a nonce twice"}, status=status.HTTP_400_BAD_REQUEST)

        models.User_Share_Right.objects.create(
                owner = request.user,
                user = request.user,
                share = share,
                key = str(request.data['secret_key']),
                key_nonce = str(request.data['secret_key_nonce']),
                approved = True,
                encryption_type = 'secret',
                read = True,
                write = True,
                grant = True,
                revoke = True,
            )

        return Response({"share_id": share.id}, status=status.HTTP_201_CREATED)

    def post(self, request, uuid = None, *args, **kwargs):

        try:
            share = models.Share.objects.get(pk=uuid)
        except models.Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)

        if share.owner != request.user and share.user_share_rights.filter(user=request.user, write=True).count() < 0:
            raise PermissionDenied()

        if 'data' in request.data:
            share.data = str(request.data['data'])
        if 'data_nonce' in request.data:
            share.data_nonce = str(request.data['data_nonce'])
        if 'secret_key' in request.data:
            share.secret_key = str(request.data['secret_key'])
        if 'secret_key_nonce' in request.data:
            share.secret_key_nonce = str(request.data['secret_key_nonce'])

        share.save()

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)


class GroupView(GenericAPIView):

    """
    Check the REST Token and returns a list of all groups or the specified groups details

    Return the user's public key
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    def get(self, request, uuid = None, *args, **kwargs):

        if not uuid:

            # Generates a list of groups wherever the user has any rights for it

            try:
                groups = models.Group.objects.filter(group_user_rights__user=request.user).distinct()
            except models.Share.DoesNotExist:
                groups = []

            response = []

            for g in groups:

                response.append({
                    'id': g.id,
                    'name': g.name,
                    'owner_id': g.owner_id,
                })

            return Response({'groups': response},
                status=status.HTTP_200_OK)
        else:

            # Returns the specified share if the user has any rights for it and joins the user_share objects

            try:
                group = models.Group.objects.get(pk=uuid)
            except models.Group.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)


            user_share_rights = []

            for u in group.group_user_rights.filter(user=request.user):
                user_share_rights.append({
                    'id': u.id,
                    'owner': u.owner_id,
                    'key': u.key,
                    'key_nonce': u.key_nonce,
                    'encryption_type': u.encryption_type,
                    'approved': u.approved,
                    'read': u.read,
                    'write': u.write,
                    'add_share': u.add_share,
                    'remove_share': u.remove_share,
                    'grant': u.grant,
                    'revoke': u.revoke,
                })

            if not user_share_rights:
                raise PermissionDenied({"message":"You don't have permission to access",
                                "resource_id": group.id})

            response = {
                'id': group.id,
                'name': group.name,
                'owner_id': group.owner_id,
                'user_share_rights': user_share_rights
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):

        group = models.Group.objects.create(
            name = str(request.data['name']),
            owner = request.user
        )

        models.Group_User_Right.objects.create(
                owner = request.user,
                user = request.user,
                group = group,
                approved = True,
                encryption_type = 'secret',
                key = str(request.data['secret_key']),
                key_nonce = str(request.data['secret_key_nonce']),
                read = True,
                write = True,
                grant = True,
                revoke = True,
                add_share=True,
                remove_share=True,
            )

        return Response({"group_id": group.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):

        #TODO Implement

        return Response(status=status.HTTP_200_OK)
