from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Data_Store,
)

from ..utils import request_misses_uuid, readbuffer, authenticate, get_datastore

from ..app_settings import (
    DatastoreOverviewSerializer,
    CreateDatastoreSerializer,
    DeleteDatastoreSerializer,
)
from rest_framework.exceptions import PermissionDenied

from django.db import IntegrityError
from ..authentication import TokenAuthentication

import six

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)


class DatastoreView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'OPTIONS', 'HEAD')

    def get(self, request, uuid = None, *args, **kwargs):
        """
        Lists all datastores of the user or returns a specific datastore with content

        :param request:
        :type request:
        :param uuid: PK of the datastore
        :type uuid: uuid
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        if not uuid:
            datastores = get_datastore(user=request.user)

            log_info(logger=logger, request=request, status='HTTP_200_OK', event='LIST_ALL_DATASTORES_SUCCESS')

            return Response({'datastores': DatastoreOverviewSerializer(datastores, many=True).data},
                status=status.HTTP_200_OK)
        else:
            datastore = get_datastore(uuid, request.user)
            if not datastore:

                log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                         event='LIST_DATASTORE_ERROR')

                raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})

            log_info(logger=logger, request=request, status='HTTP_200_OK',
                     event='LIST_DATASTORE_SUCCESS', request_resource= datastore.id)

            return Response({
                'data': readbuffer(datastore.data),
                'data_nonce': datastore.data_nonce if datastore.data_nonce else '',
                'type': datastore.type,
                'description': datastore.description,
                'secret_key': datastore.secret_key,
                'secret_key_nonce': datastore.secret_key_nonce,
                'is_default': datastore.is_default,
            },status=status.HTTP_200_OK)


    def put(self, request, *args, **kwargs):
        """
        Creates a new datastore

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateDatastoreSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='CREATE_DATASTORE_REQUEST_ERROR', errors=serializer.errors)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


        try:

            datastore = Data_Store.objects.create(
                type = str(request.data['type']),
                description = str(request.data['description']),
                data = readbuffer(request.data['data']),
                data_nonce = str(request.data['data_nonce']),
                secret_key = str(request.data['secret_key']),
                secret_key_nonce = str(request.data['secret_key_nonce']),
                user = request.user,
                is_default = request.data.get('is_default', True)
            )

            if request.data.get('is_default', True):
                Data_Store.objects.filter(user=request.user, type=str(request.data['type'])).exclude(pk=datastore.pk).update(is_default=False)

        except IntegrityError:

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST',
                     event='CREATE_DATASTORE_INTEGRITY_ERROR')

            return Response({"error": "DuplicateTypeDescription", 'message': "The combination of type and "
                                                                             "description must be unique"},
                        status=status.HTTP_400_BAD_REQUEST)


        log_info(logger=logger, request=request, status='HTTP_201_CREATED',
                 event='CREATE_DATASTORE_SUCCESS', request_resource=datastore.id)

        return Response({"datastore_id": datastore.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a specific datastore

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        if request_misses_uuid(request, 'datastore_id'):

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST',
                     event='UPDATE_DATASTORE_NO_DATASTORE_ID_ERROR')

            return Response({"error": "IdNoUUID", 'message': "Datastore ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        datastore = get_datastore(request.data['datastore_id'], request.user)
        if not datastore:
            log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                     event='UPDATE_DATASTORE_PERMISSIONS_ERROR', request_resource=request.data['datastore_id'])

            raise PermissionDenied({"message": "You don't have permission to access or it does not exist."})

        if 'data' in request.data:
            datastore.data = six.b(str(request.data['data']))
        if 'data_nonce' in request.data:
            datastore.data_nonce = str(request.data['data_nonce'])
        if 'secret_key' in request.data:
            datastore.secret_key = str(request.data['secret_key'])
        if 'secret_key_nonce' in request.data:
            datastore.secret_key_nonce = str(request.data['secret_key_nonce'])
        if 'description' in request.data:
            datastore.description = str(request.data['description'])
        if 'is_default' in request.data:
            datastore.is_default = request.data['is_default']

        datastore.save()

        if request.data.get('is_default', False):
            Data_Store.objects.filter(user=request.user, type=datastore.type).exclude(pk=datastore.pk).update(is_default=False)

        log_info(logger=logger, request=request, status='HTTP_200_OK',
                 event='UPDATE_DATASTORE_SUCCESS', request_resource=request.data['datastore_id'])

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an Datastore

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400 / 403
        """

        serializer = DeleteDatastoreSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='DELETE_DATASTORE_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        if not authenticate(username=request.user.username, authkey=str(request.data['authkey'])):

            log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                     event='DELETE_DATASTORE_WRONG_PASSWORD_ERROR')

            raise PermissionDenied({"message":"Your old password was not right."})

        # check if datastore exists
        try:
            data_store = Data_Store.objects.get(pk=request.data['datastore_id'], user=request.user)
        except Data_Store.DoesNotExist:

            log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                     event='DELETE_DATASTORE_NOT_EXIST_ERROR')

            return Response({"message": "Datastore does not exist.",
                         "resource_id": request.data['datastore_id']}, status=status.HTTP_403_FORBIDDEN)

        # prevent deletion of the default datastore
        if data_store.is_default:

            log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                     event='DELETE_DATASTORE_DEFAULT_PROTECTION_ERROR', request_resource=data_store.id)

            return Response({"message": "Cannot delete default datastore.",
                         "resource_id": request.data['datastore_id']}, status=status.HTTP_400_BAD_REQUEST)

        log_info(logger=logger, request=request, status='HTTP_200_OK',
                 event='DELETE_DATASTORE_SUCCESS', request_resource=data_store.id)

        # delete it
        data_store.delete()

        return Response(status=status.HTTP_200_OK)
