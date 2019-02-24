from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

import json

from ..permissions import IsAuthenticated

from ..app_settings import (
    CreateFileExchangeSerializer,
    UpdateFileExchangeSerializer,
    DeleteFileExchangeSerializer,
)
from ..models import (
    File_Exchange,
    File_Exchange_User,
)

from ..utils import encrypt_with_db_secret, decrypt_with_db_secret
from ..authentication import TokenAuthentication


class FileExchangeView(GenericAPIView):
    """
    Check the REST Token and returns a list of all file_exchanges or the specified file_exchanges details
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, file_exchange_id=None, *args, **kwargs):
        """
        Returns either a list of all file_exchanges with own access privileges or the members specified file_exchange

        :param request:
        :type request:
        :param file_exchange_id:
        :type file_exchange_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 403
        :rtype:
        """

        if not file_exchange_id:

            file_exchanges = []

            for file_exchange in File_Exchange.objects.filter(file_exchange_user__user=request.user).annotate(read=F('file_exchange_user__read'), write=F('file_exchange_user__write'), grant=F('file_exchange_user__grant')):
                file_exchanges.append({
                    'id': file_exchange.id,
                    'title': file_exchange.title,
                    'type': file_exchange.type,
                    'active': file_exchange.active,
                    'read': file_exchange.read,
                    'write': file_exchange.write,
                    'grant': file_exchange.grant,
                })

            return Response({'file_exchanges': file_exchanges},
                            status=status.HTTP_200_OK)
        else:
            # Returns the specified file_exchange if the user has any rights for it
            try:
                file_exchange = File_Exchange.objects.select_related('file_exchange_user').get(id=file_exchange_id, file_exchange_user__user=request.user, file_exchange_user__read=True)
            except File_Exchange.DoesNotExist:
                return Response({"message": "You don't have permission to access or it does not exist.",
                                 "resource_id": file_exchange_id}, status=status.HTTP_400_BAD_REQUEST)

            data = json.loads(decrypt_with_db_secret(file_exchange.data))

            response = {
                'id': file_exchange.id,
                'title': file_exchange.title,
                'type': file_exchange.type,
                'active': file_exchange.active,
            }

            for key, value in data.items():
                response[key] = value

            return Response(response,
                            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Creates an file_exchange

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateFileExchangeSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_exchange = File_Exchange.objects.create(
            title=str(serializer.validated_data.get('title')),
            type=str(serializer.validated_data.get('type')),
            data=encrypt_with_db_secret(json.dumps(serializer.validated_data.get('data'))),
            active=True,
        )

        File_Exchange_User.objects.create(
            user=request.user,
            file_exchange=file_exchange,
        )

        return Response({
            "file_exchange_id": file_exchange.id,
        }, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a file_exchange

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = UpdateFileExchangeSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_exchange = serializer.validated_data.get('file_exchange')

        file_exchange.title = serializer.validated_data.get('title')
        file_exchange.type = serializer.validated_data.get('type')
        file_exchange.data = encrypt_with_db_secret(json.dumps(serializer.validated_data.get('data')))
        file_exchange.active = serializer.validated_data.get('active')

        file_exchange.save()

        return Response(status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an file_exchange

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteFileExchangeSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_exchange = serializer.validated_data.get('file_exchange')

        # delete it
        file_exchange.delete()

        return Response(status=status.HTTP_200_OK)
