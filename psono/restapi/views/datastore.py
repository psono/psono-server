from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from ..permissions import IsAuthenticated
from ..models import (
    Data_Store,
)

from ..utils import authenticate, get_datastore

from ..app_settings import (
    CreateDatastoreSerializer,
    UpdateDatastoreSerializer,
    DeleteDatastoreSerializer,
)
from rest_framework.exceptions import PermissionDenied

from django.db import IntegrityError
from ..authentication import TokenAuthentication


class DatastoreView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return CreateDatastoreSerializer
        if self.request.method == 'POST':
            return UpdateDatastoreSerializer
        if self.request.method == 'DELETE':
            return DeleteDatastoreSerializer
        if self.request.method == 'GET':
            return Serializer
        return Serializer

    def get(self, request, datastore_id = None, *args, **kwargs):
        """
        Lists all datastores of the user or returns a specific datastore with content
        """

        if not datastore_id:
            datastores = []

            for datastore in get_datastore(user=request.user):
                datastores.append({
                    'id': str(datastore.id),
                    'type': datastore.type,
                    'description': datastore.description,
                    'is_default': datastore.is_default,
                })

            return Response({'datastores': datastores},
                status=status.HTTP_200_OK)
        else:
            datastore = get_datastore(datastore_id, request.user)
            if not datastore:

                raise PermissionDenied({"message":"NO_PERMISSION_OR_NOT_EXIST"})

            return Response({
                'data': datastore.data.decode(),
                'data_nonce': datastore.data_nonce if datastore.data_nonce else '',
                'type': datastore.type,
                'description': datastore.description,
                'secret_key': datastore.secret_key,
                'secret_key_nonce': datastore.secret_key_nonce,
                'is_default': datastore.is_default,
                'write_date': datastore.write_date.isoformat(),
            },status=status.HTTP_200_OK)


    def put(self, request, *args, **kwargs):
        """
        Creates a new datastore
        """

        serializer = CreateDatastoreSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


        try:

            datastore = Data_Store.objects.create(
                type = str(request.data['type']),
                description = str(request.data['description']),
                data = request.data['data'].encode(),
                data_nonce = str(request.data['data_nonce']),
                secret_key = str(request.data['secret_key']),
                secret_key_nonce = str(request.data['secret_key_nonce']),
                user = request.user,
                is_default = request.data.get('is_default', True)
            )

            if request.data.get('is_default', True):
                Data_Store.objects.filter(user=request.user, type=str(request.data['type'])).exclude(pk=datastore.pk).update(is_default=False)

        except IntegrityError:

            return Response({"error": "DuplicateTypeDescription", 'message': "The combination of type and "
                                                                             "description must be unique"},
                        status=status.HTTP_400_BAD_REQUEST)

        return Response({"datastore_id": datastore.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a specific datastore
        """

        serializer = UpdateDatastoreSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        datastore = serializer.validated_data.get('datastore')

        if 'data' in request.data:
            datastore.data = request.data['data'].encode()
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

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        datastore = serializer.validated_data.get('datastore')

        user, error_code = authenticate(username=request.user.username, authkey=str(serializer.validated_data.get('authkey')))

        if not user:
            raise PermissionDenied({"message": "PASSWORD_INCORRECT"})

        # delete it
        datastore.delete()

        return Response({}, status=status.HTTP_200_OK)
