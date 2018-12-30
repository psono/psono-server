from django.db import transaction
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Data_Store,
    File,
    File_Link,
)

from ..utils import readbuffer, authenticate, get_datastore

from ..app_settings import (
    DatastoreOverviewSerializer,
    CreateFileSerializer,
    UpdateDatastoreSerializer,
    DeleteDatastoreSerializer,
)
from rest_framework.exceptions import PermissionDenied

from django.db import IntegrityError
from ..authentication import TokenAuthentication

import six


class FileView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'OPTIONS', 'HEAD')

    def get(self, request, datastore_id = None, *args, **kwargs):
        #
        # if not datastore_id:
        #     file = get_datastore(user=request.user)
        #
        #     return Response({'file': DatastoreOverviewSerializer(file, many=True).data},
        #         status=status.HTTP_200_OK)
        # else:
        #     datastore = get_datastore(datastore_id, request.user)
        #     if not datastore:
        #
        #         raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})
        #
        #     return Response({
        #         'data': readbuffer(datastore.data),
        #         'data_nonce': datastore.data_nonce if datastore.data_nonce else '',
        #         'type': datastore.type,
        #         'description': datastore.description,
        #         'secret_key': datastore.secret_key,
        #         'secret_key_nonce': datastore.secret_key_nonce,
        #         'is_default': datastore.is_default,
        #     },status=status.HTTP_200_OK)

        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



    def put(self, request, *args, **kwargs):
        """
        Creates a new file

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateFileSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        shard = serializer.validated_data['shard']
        chunk_count = serializer.validated_data['chunk_count']
        size = serializer.validated_data['size']
        link_id = serializer.validated_data['link_id']
        parent_datastore_id = serializer.validated_data['parent_datastore_id']
        parent_share_id = serializer.validated_data['parent_share_id']

        with transaction.atomic():
            file = File.objects.create(
                shard = shard,
                chunk_count = chunk_count,
                size = size,
                user_id = request.user.id,
            )

            File_Link.objects.create(
                link_id = link_id,
                file_id = file.id,
                parent_datastore_id = parent_datastore_id,
                parent_share_id = parent_share_id
            )

        return Response({"file_id": file.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):

        # serializer = UpdateDatastoreSerializer(data=request.data, context=self.get_serializer_context())
        #
        # if not serializer.is_valid():
        #
        #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        #
        # datastore = serializer.validated_data.get('datastore')
        #
        # if 'data' in request.data:
        #     datastore.data = six.b(str(request.data['data']))
        # if 'data_nonce' in request.data:
        #     datastore.data_nonce = str(request.data['data_nonce'])
        # if 'secret_key' in request.data:
        #     datastore.secret_key = str(request.data['secret_key'])
        # if 'secret_key_nonce' in request.data:
        #     datastore.secret_key_nonce = str(request.data['secret_key_nonce'])
        # if 'description' in request.data:
        #     datastore.description = str(request.data['description'])
        # if 'is_default' in request.data:
        #     datastore.is_default = request.data['is_default']
        #
        # datastore.save()
        #
        # if request.data.get('is_default', False):
        #     Data_Store.objects.filter(user=request.user, type=datastore.type).exclude(pk=datastore.pk).update(is_default=False)
        #
        # return Response({"success": "Data updated."},
        #                 status=status.HTTP_200_OK)

        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):

        # serializer = DeleteDatastoreSerializer(data=request.data, context=self.get_serializer_context())
        #
        # if not serializer.is_valid():
        #
        #     return Response(
        #         serializer.errors, status=status.HTTP_400_BAD_REQUEST
        #     )
        #
        # datastore = serializer.validated_data.get('datastore')
        #
        # user, error_code = authenticate(username=request.user.username, authkey=str(request.data['authkey']))
        #
        # if not user:
        #     raise PermissionDenied({"message":"Your old password was not right."})
        #
        # # delete it
        # datastore.delete()
        #
        # return Response(status=status.HTTP_200_OK)

        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
