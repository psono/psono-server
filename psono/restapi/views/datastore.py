from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Data_Store,
)

from ..utils import request_misses_uuid, readbuffer

from ..app_settings import (
    DatastoreOverviewSerializer,
)
from rest_framework.exceptions import PermissionDenied

from django.db import IntegrityError
from ..authentication import TokenAuthentication

import six

# import the logging
import logging
logger = logging.getLogger(__name__)

def get_datastore(datastore_id=None, user=None):

    if user and not datastore_id:
        try:
            datastores = Data_Store.objects.filter(user=user)
        except Data_Store.DoesNotExist:
            datastores = []
        return datastores

    datastore = None
    try:
        if user and datastore_id:
            datastore = Data_Store.objects.get(pk=datastore_id, user=user)
        else:
            datastore = Data_Store.objects.get(pk=datastore_id)
    except Data_Store.DoesNotExist:
        pass
    except ValueError:
        pass

    return datastore


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

            if settings.LOGGING_AUDIT:
                logger.info({
                    'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                    'request_method': request.META['REQUEST_METHOD'],
                    'request_url': request.META['PATH_INFO'],
                    'success': True,
                    'status': 'HTTP_200_OK',
                    'event': 'LIST_ALL_DATASTORES_SUCCESS',
                    'user': request.user.username
                })

            return Response({'datastores': DatastoreOverviewSerializer(datastores, many=True).data},
                status=status.HTTP_200_OK)
        else:
            datastore = get_datastore(uuid, request.user)
            if not datastore:

                if settings.LOGGING_AUDIT:
                    logger.info({
                        'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                        'request_method': request.META['REQUEST_METHOD'],
                        'request_url': request.META['PATH_INFO'],
                        'success': False,
                        'status': 'HTTP_403_FORBIDDEN',
                        'request_ressource': uuid,
                        'event': 'LIST_DATASTORE_ERROR',
                        'user': request.user.username
                    })

                raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})

            if settings.LOGGING_AUDIT:
                logger.info({
                    'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                    'request_method': request.META['REQUEST_METHOD'],
                    'request_url': request.META['PATH_INFO'],
                    'success': True,
                    'status': 'HTTP_200_OK',
                    'event': 'LIST_DATASTORE_SUCCESS',
                    'user': request.user.username
                })



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
        :return:
        :rtype:
        """

        #TODO Check if secret_key and nonce exist

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

        except IntegrityError as e:

            if settings.LOGGING_AUDIT:
                logger.info({
                    'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                    'request_method': request.META['REQUEST_METHOD'],
                    'request_url': request.META['PATH_INFO'],
                    'success': False,
                    'error': 'IntegrityError',
                    'status': 'HTTP_400_BAD_REQUEST',
                    'event': 'CREATE_DATASTORE_ERROR',
                    'user': request.user.username
                })

            if hasattr(e, 'message') and '(user_id, type, description)' in e.message:
                return Response({"error": "DuplicateTypeDescription", 'message': "The combination of type and "
                                                                                 "description must be unique"},
                            status=status.HTTP_400_BAD_REQUEST)

            if hasattr(e, 'args') and '(user_id, type, description)' in e.args[0]:
                return Response({"error": "DuplicateTypeDescription", 'message': "The combination of type and "
                                                                                 "description must be unique"},
                            status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": "DuplicateNonce", 'message': "Don't use a nonce twice"},
                            status=status.HTTP_400_BAD_REQUEST)

        if settings.LOGGING_AUDIT:
            logger.info({
                'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                'request_method': request.META['REQUEST_METHOD'],
                'request_url': request.META['PATH_INFO'],
                'success': True,
                'status': 'HTTP_201_CREATED',
                'event': 'CREATE_DATASTORE_SUCCESS',
                'user': request.user.username
            })

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
            if settings.LOGGING_AUDIT:
                logger.info({
                    'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                    'request_method': request.META['REQUEST_METHOD'],
                    'request_url': request.META['PATH_INFO'],
                    'success': False,
                    'status': 'HTTP_400_BAD_REQUEST',
                    'event': 'UPDATE_DATASTORE_NO_DATASTORE_ID_ERROR',
                    'user': request.user.username
                })
            return Response({"error": "IdNoUUID", 'message': "Datastore ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        datastore = get_datastore(request.data['datastore_id'], request.user)
        if not datastore:
            if settings.LOGGING_AUDIT:
                logger.info({
                    'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                    'request_method': request.META['REQUEST_METHOD'],
                    'request_url': request.META['PATH_INFO'],
                    'success': False,
                    'request_ressource': request.data['datastore_id'],
                    'status': 'HTTP_403_FORBIDDEN',
                    'event': 'UPDATE_DATASTORE_PERMISSIONS_ERROR',
                    'user': request.user.username
                })
            raise PermissionDenied({"message": "You don't have permission to access or it does not exist."})

        if 'data' in request.data:
            datastore.data = six.b(str(request.data['data']))
        if 'data_nonce' in request.data:
            datastore.data_nonce = str(request.data['data_nonce'])
        if 'secret_key' in request.data:
            datastore.secret_key = str(request.data['secret_key'])
        if 'secret_key_nonce' in request.data:
            datastore.secret_key_nonce = str(request.data['secret_key_nonce'])

        datastore.save()

        if settings.LOGGING_AUDIT:
            logger.info({
                'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                'request_method': request.META['REQUEST_METHOD'],
                'request_url': request.META['PATH_INFO'],
                'success': True,
                'request_ressource': request.data['datastore_id'],
                'status': 'HTTP_200_OK',
                'event': 'UPDATE_DATASTORE_SUCCESS',
                'user': request.user.username
            })

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
