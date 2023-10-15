from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..app_settings import (
    AddSecretToAPIKeySerializer,
    RemoveSecretFromAPIKeySerializer,
)
from ..models import (
    API_Key,
    API_Key_Secret,
)
from ..authentication import TokenAuthentication

class APIKeySecretView(GenericAPIView):

    """
    Check the REST Token and returns a list of all api_keys or the specified api_keys details
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'DELETE', 'OPTIONS', 'HEAD')


    def get(self, request, api_key_id=None, *args, **kwargs):
        """
        Returns a list of all api key secrets of an API key
        
        :param request:
        :type request:
        :param api_key_id:
        :type api_key_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        # Returns the specified api_key if the user has any rights for it
        try:
            API_Key.objects.get(id=api_key_id, user=request.user)
        except API_Key.DoesNotExist:
            return Response({"message":"NO_PERMISSION_OR_NOT_EXIST",
                             "resource_id": api_key_id}, status=status.HTTP_400_BAD_REQUEST)

        api_key_secrets = API_Key_Secret.objects.filter(api_key_id=api_key_id)

        response = []

        for api_key_secret in api_key_secrets:
            response.append({
                'id': api_key_secret.id,
                'secret_id': api_key_secret.secret_id,
                'title': api_key_secret.title,
                'title_nonce': api_key_secret.title_nonce
            })

        return Response(response,
            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Adds a secret to an api_key

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = AddSecretToAPIKeySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        api_key = serializer.validated_data.get('api_key')
        secret = serializer.validated_data.get('secret')
        title = serializer.validated_data.get('title')
        title_nonce = serializer.validated_data.get('title_nonce')
        secret_key = serializer.validated_data.get('secret_key')
        secret_key_nonce = serializer.validated_data.get('secret_key_nonce')

        api_key_secret = API_Key_Secret.objects.create(
            api_key = api_key,
            secret = secret,
            title = title,
            title_nonce = title_nonce,
            secret_key = secret_key,
            secret_key_nonce = secret_key_nonce,
        )

        return Response({
            "api_key_secret_id": api_key_secret.id,
        }, status=status.HTTP_201_CREATED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Removes a secret from an api_key

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = RemoveSecretFromAPIKeySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        api_key_secret = serializer.validated_data.get('api_key_secret')

        # delete it
        api_key_secret.delete()

        return Response({}, status=status.HTTP_200_OK)
