from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from django.conf import settings
from ..permissions import IsAuthenticated
from django.db import IntegrityError
import requests

from .secret_link import create_secret_link
from ..utils import readbuffer, decrypt_with_db_secret, encrypt_with_db_secret
from ..utils import is_allowed_callback_url
from ..models import (
    Secret,
    Secret_History,
)

from ..app_settings import (
    CreateSecretSerializer,
    ReadSecretSerializer,
    UpdateSecretSerializer,
)

from ..authentication import TokenAuthentication

class SecretView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Lists a specific secret

        Necessary Rights:
            - read on secret

        :param request:
        :type request:
        :param secret_id:
        :type secret_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400 / 403
        :rtype:
        """

        serializer = ReadSecretSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        secret = serializer.validated_data.get('secret')

        try:
            callback_pass = decrypt_with_db_secret(secret.callback_pass)
        except:
            callback_pass = ''  #nosec -- not [B105:hardcoded_password_string]

        return Response({
            'create_date': secret.create_date.isoformat(),
            'write_date': secret.write_date.isoformat(),
            'data': readbuffer(secret.data),
            'data_nonce': secret.data_nonce if secret.data_nonce else '',
            'type': secret.type,
            'callback_url': secret.callback_url,
            'callback_user': secret.callback_user,
            'callback_pass': callback_pass,
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Creates a secret

        Necessary Rights:
            - write on parent_share
            - write on parent_datastore

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateSecretSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        try:

            callback_pass = encrypt_with_db_secret(serializer.validated_data['callback_pass'])

            secret = Secret.objects.create(
                data = readbuffer(str(request.data['data'])),
                data_nonce = str(request.data['data_nonce']),
                callback_url = serializer.validated_data['callback_url'],
                callback_user = serializer.validated_data['callback_user'],
                callback_pass = callback_pass,
                user = request.user
            )
        except IntegrityError:

            return Response({"error": "DuplicateNonce", 'message': "Don't use a nonce twice"}, status=status.HTTP_400_BAD_REQUEST)

        if not create_secret_link(request.data['link_id'], secret.id, serializer.validated_data['parent_share_id'], serializer.validated_data['parent_datastore_id']):

            return Response({"error": "DuplicateLinkID", 'message': "Don't use a link id twice"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"secret_id": secret.id}, status=status.HTTP_201_CREATED)



    def post(self, request, *args, **kwargs):
        """
        Updates a secret

        Necessary Rights:
            - write on secret

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        serializer = UpdateSecretSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        secret = serializer.validated_data['secret']

        Secret_History.objects.create(
            secret = secret,
            data = secret.data,
            data_nonce = secret.data_nonce,
            user = request.user,
            type = secret.type,
            callback_url = secret.callback_url,
            callback_user = secret.callback_user,
            callback_pass = secret.callback_pass,
        )

        if serializer.validated_data['data']:
            secret.data = serializer.validated_data['data'].encode()
        if serializer.validated_data['data_nonce']:
            secret.data_nonce = str(serializer.validated_data['data_nonce'])

        if serializer.validated_data.get('callback_url', None) is not None:
            secret.callback_url = serializer.validated_data['callback_url']
        if serializer.validated_data.get('callback_user', None) is not None:
            secret.callback_user = serializer.validated_data['callback_user']
        if serializer.validated_data.get('callback_pass', None) is not None:
            secret.callback_pass = encrypt_with_db_secret(serializer.validated_data['callback_pass'])

        secret.save()

        if secret.callback_url and not settings.DISABLE_CALLBACKS and is_allowed_callback_url(secret.callback_url):
            headers = {'content-type': 'application/json'}
            data = {
                'event': 'UPDATE_SECRET_SUCCESS',
                'secret_id': str(secret.id),
            }

            callback_pass = ''  #nosec -- not [B105:hardcoded_password_string]
            if secret.callback_user and secret.callback_pass:
                try:
                    callback_pass = decrypt_with_db_secret(secret.callback_pass)
                except:
                    callback_pass = secret.callback_pass

            if secret.callback_user and callback_pass:
                auth = (secret.callback_user, callback_pass)
            else:
                auth = None

            try:
                requests.post(secret.callback_url, data=data, headers=headers, auth=auth, timeout=5.0)
            except: # nosec
                pass

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
