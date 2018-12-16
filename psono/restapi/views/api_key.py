from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..app_settings import (
    CreateAPIKeySerializer,
    UpdateAPIKeySerializer,
    DeleteAPIKeySerializer,
)
from ..models import (
    API_Key
)
from ..authentication import TokenAuthentication

class APIKeyView(GenericAPIView):

    """
    Check the REST Token and returns a list of all api_keys or the specified api_keys details
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')


    def get(self, request, api_key_id = None, *args, **kwargs):
        """
        Returns either a list of all api_keys with own access privileges or the members specified api_key
        
        :param request:
        :type request:
        :param api_key_id:
        :type api_key_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 403
        :rtype:
        """

        if not api_key_id:

            api_keys = []

            for api_key in API_Key.objects.filter(user=request.user):
                api_keys.append({
                    'id': api_key.id,
                    'title': api_key.title,
                    'read': api_key.read,
                    'write': api_key.write,
                    'restrict_to_secrets': api_key.restrict_to_secrets,
                    'allow_insecure_access': api_key.allow_insecure_access,
                    'active': api_key.active,
                })

            return Response({'api_keys': api_keys},
                status=status.HTTP_200_OK)
        else:
            # Returns the specified api_key if the user has any rights for it
            try:
                api_key = API_Key.objects.get(id=api_key_id, user=request.user)
            except API_Key.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                 "resource_id": api_key_id}, status=status.HTTP_400_BAD_REQUEST)

            response = {
                'id': api_key.id,
                'title': api_key.title,
                'public_key': api_key.public_key,
                'private_key': api_key.private_key,
                'private_key_nonce': api_key.private_key_nonce,
                'secret_key': api_key.secret_key,
                'secret_key_nonce': api_key.secret_key_nonce,
                'read': api_key.read,
                'write': api_key.write,
                'restrict_to_secrets': api_key.restrict_to_secrets,
                'allow_insecure_access': api_key.allow_insecure_access,
                'active': api_key.active,
            }


            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Creates an api_key

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateAPIKeySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        api_key = API_Key.objects.create(
            user = request.user,
            title = str(serializer.validated_data.get('title')),
            public_key = str(serializer.validated_data.get('public_key')),
            private_key = str(serializer.validated_data.get('private_key')),
            private_key_nonce = str(serializer.validated_data.get('private_key_nonce')),
            secret_key = str(serializer.validated_data.get('secret_key')),
            secret_key_nonce = str(serializer.validated_data.get('secret_key_nonce')),
            user_private_key = str(serializer.validated_data.get('user_private_key')),
            user_private_key_nonce = str(serializer.validated_data.get('user_private_key_nonce')),
            user_secret_key = str(serializer.validated_data.get('user_secret_key')),
            user_secret_key_nonce = str(serializer.validated_data.get('user_secret_key_nonce')),
            verify_key = str(serializer.validated_data.get('verify_key')),
            read = serializer.validated_data.get('read'),
            write = serializer.validated_data.get('write'),
            restrict_to_secrets = serializer.validated_data.get('restrict_to_secrets'),
            allow_insecure_access = serializer.validated_data.get('allow_insecure_access'),
        )

        return Response({
            "api_key_id": api_key.id,
        }, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a api_key

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = UpdateAPIKeySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        api_key = serializer.validated_data.get('api_key')
        title = serializer.validated_data.get('title')
        read = serializer.validated_data.get('read')
        write = serializer.validated_data.get('write')
        restrict_to_secrets = serializer.validated_data.get('restrict_to_secrets')
        allow_insecure_access = serializer.validated_data.get('allow_insecure_access')

        if title is not None:
            api_key.title = title

        if read is not None and api_key.read != read:
            api_key.read = read
            for token in api_key.tokens.all():
                token.read = read
                token.save()

        if write is not None and api_key.write != write:
            api_key.write = write
            for token in api_key.tokens.all():
                token.write = write
                token.save()

        if restrict_to_secrets is not None:
            api_key.restrict_to_secrets = restrict_to_secrets

        if allow_insecure_access is not None:
            api_key.allow_insecure_access = allow_insecure_access

        api_key.save()

        return Response(status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an api_key

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteAPIKeySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        api_key = serializer.validated_data.get('api_key')

        # delete it
        api_key.delete()

        return Response(status=status.HTTP_200_OK)
