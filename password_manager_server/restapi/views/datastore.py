from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Data_Store,
)

from ..utils import is_uuid

from ..app_settings import (
    DatastoreSerializer, DatastoreOverviewSerializer,
)
from rest_framework.exceptions import PermissionDenied

from django.db import IntegrityError
from ..authentication import TokenAuthentication

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
    serializer_class = DatastoreSerializer
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
            return Response({'datastores': DatastoreOverviewSerializer(datastores, many=True).data},
                status=status.HTTP_200_OK)
        else:
            datastore = get_datastore(uuid, request.user)
            if not datastore:
                raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})

            return Response(self.serializer_class(datastore).data,
                status=status.HTTP_200_OK)


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
                data = str(request.data['data']),
                data_nonce = str(request.data['data_nonce']),
                secret_key = str(request.data['secret_key']),
                secret_key_nonce = str(request.data['secret_key_nonce']),
                user = request.user
            )
        except IntegrityError as e:
            if '(user_id, type, description)' in e.message:
                return Response({"error": "DuplicateTypeDescription", 'message': "The combination of type and "
                                                                                 "description must be unique"},
                            status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": "DuplicateNonce", 'message': "Don't use a nonce twice"},
                            status=status.HTTP_400_BAD_REQUEST)

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

        if 'datastore_id' not in request.data or not is_uuid(request.data['datastore_id']):
            return Response({"error": "IdNoUUID", 'message': "Datastore ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        datastore = get_datastore(request.data['datastore_id'], request.user)
        if not datastore:
            raise PermissionDenied({"message": "You don't have permission to access or it does not exist."})

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

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
