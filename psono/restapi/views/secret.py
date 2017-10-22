from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from django.core.exceptions import ValidationError
from .secret_link import create_secret_link
from ..utils import user_has_rights_on_secret, readbuffer
from ..models import (
    Secret,
)

from ..app_settings import (
    SecretOverviewSerializer,
    CreateSecretSerializer,
    UpdateSecretSerializer,
)

from django.db import IntegrityError
from ..authentication import TokenAuthentication

import six

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)

class SecretView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'OPTIONS', 'HEAD')

    def get(self, request, uuid = None, *args, **kwargs):
        """
        Lists all secrets the user created or only a specific secret

        Necessary Rights:
            - read on secret

        :param request:
        :type request:
        :param uuid:
        :type uuid:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400 / 403
        :rtype:
        """
        if not uuid:
            try:
                storages = Secret.objects.filter(user=request.user)
            except Secret.DoesNotExist:
                storages = []

            log_info(logger=logger, request=request, status='HTTP_200_OK',
                     event='READ_SECRETS_ALL_SUCCESS')

            return Response({'secrets': SecretOverviewSerializer(storages, many=True).data},
                status=status.HTTP_200_OK)
        else:
            try:
                secret = Secret.objects.get(pk=uuid)
            except ValidationError:

                log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                         event='READ_SECRET_ID_NO_UUID_ERROR', request_resource=uuid)

                return Response({"error": "IdNoUUID", 'message': "Secret ID is badly formed and no uuid"},
                                status=status.HTTP_400_BAD_REQUEST)
            except Secret.DoesNotExist:

                log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                         event='READ_SECRET_NOT_EXIST_ERROR', request_resource=uuid)

                raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})

            if not user_has_rights_on_secret(request.user.id, secret.id, True, None):

                log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                         event='READ_SECRET_PERMISSION_DENIED_ERROR', request_resource=uuid)

                raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})

            log_info(logger=logger, request=request, status='HTTP_200_OK',
                     event='READ_SECRET_SUCCESS', request_resource=uuid)

            return Response({
                'create_date': secret.create_date,
                'write_date': secret.write_date,
                'data': readbuffer(secret.data),
                'data_nonce': secret.data_nonce if secret.data_nonce else '',
                'type': secret.type,
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
        :return: 201 / 400 / 403 / 404
        :rtype:
        """

        serializer = CreateSecretSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='CREATE_SECRET_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # if 'data' not in request.data:
        #
        #     return Response({"error": "NotInRequest", 'message': "data not in request"},
        #                         status=status.HTTP_400_BAD_REQUEST)
        #
        # if 'data_nonce' not in request.data:
        #     return Response({"error": "NotInRequest", 'message': "data_nonce not in request"},
        #                         status=status.HTTP_400_BAD_REQUEST)

        # if request_misses_uuid(request, 'link_id'):
        #     return Response({"error": "IdNoUUID", 'message': "link ID not in request"},
        #                         status=status.HTTP_400_BAD_REQUEST)

        # parent_share = None
        # parent_share_id = None
        # if 'parent_share_id' in request.data and request.data['parent_share_id']:
        #     # check permissions on parent
        #     if not user_has_rights_on_share(request.user.id, request.data['parent_share_id'], write=True):
        #         return Response({"message": "You don't have permission to access or it does not exist.",
        #                          "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)
        #
        #     try:
        #         parent_share = Share.objects.get(pk=request.data['parent_share_id'])
        #         parent_share_id = parent_share.id
        #     except Share.DoesNotExist:
        #         return Response({"message":"You don't have permission to access or it does not exist.",
        #                         "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        # parent_datastore = None
        # parent_datastore_id = None
        # if 'parent_datastore_id' in request.data and request.data['parent_datastore_id']:
        #     parent_datastore = get_datastore(request.data['parent_datastore_id'], request.user)
        #     if not parent_datastore:
        #         return Response({"message":"You don't have permission to access or it does not exist.",
        #                         "resource_id": request.data['parent_datastore_id']}, status=status.HTTP_403_FORBIDDEN)
        #     parent_datastore_id = parent_datastore.id
        #
        # if not parent_share and not parent_datastore:
        #     return Response({"message": "Either parent share or datastore need to be specified."},
        #                     status=status.HTTP_404_NOT_FOUND)

        try:
            secret = Secret.objects.create(
                data = readbuffer(str(request.data['data'])),
                data_nonce = str(request.data['data_nonce']),
                user = request.user
            )
        except IntegrityError:

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST',
                     event='CREATE_SECRET_DUPLICATE_NONCE_ERROR')

            return Response({"error": "DuplicateNonce", 'message': "Don't use a nonce twice"}, status=status.HTTP_400_BAD_REQUEST)

        if not create_secret_link(request.data['link_id'], secret.id, serializer.validated_data['parent_share_id'], serializer.validated_data['parent_datastore_id']):

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST',
                     event='CREATE_SECRET_DUPLICATE_LINK_ID_ERROR')

            return Response({"error": "DuplicateLinkID", 'message': "Don't use a link id twice"}, status=status.HTTP_400_BAD_REQUEST)

        log_info(logger=logger, request=request, status='HTTP_201_CREATED',
                 event='CREATE_SECRET_SUCCESS', request_resource=secret.id)

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
        :return: 200 / 400 / 403
        :rtype:
        """

        serializer = UpdateSecretSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='UPDATE_SECRET_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )


        # if request_misses_uuid(request, 'secret_id'):
        #     return Response({"error": "IdNoUUID", 'message': "Secret ID not in request"},
        #                         status=status.HTTP_400_BAD_REQUEST)
        #
        #
        # try:
        #     secret = Secret.objects.get(pk=request.data['secret_id'])
        # except Secret.DoesNotExist:
        #     raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})
        # except ValueError:
        #     return Response({"error": "IdNoUUID", 'message': "Secret ID is badly formed and no uuid"},
        #                     status=status.HTTP_400_BAD_REQUEST)
        #
        # if not user_has_rights_on_secret(request.user.id, secret.id, None, True):
        #     raise PermissionDenied({"message":"You don't have permission to access",
        #                     "resource_id": secret.id})

        secret = serializer.validated_data['secret']
        if serializer.validated_data['data']:
            secret.data = six.b(str(serializer.validated_data['data']))
        if serializer.validated_data['data_nonce']:
            secret.data_nonce = str(serializer.validated_data['data_nonce'])

        secret.save()

        log_info(logger=logger, request=request, status='HTTP_200_OK',
                 event='UPDATE_SECRET_SUCCESS', request_resource=secret.id)

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
