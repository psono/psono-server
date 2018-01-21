from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Google_Authenticator
)

from ..app_settings import (
    NewGASerializer,
    DeleteGASerializer,
)


from ..authentication import TokenAuthentication
from ..utils import encrypt_with_db_secret
import nacl.encoding
import nacl.utils
import nacl.secret
import hashlib
import pyotp


class UserGA(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = NewGASerializer
    allowed_methods = ('GET', 'PUT', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Checks the REST Token and returns a list of a all google authenticators

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200
        :rtype:
        """

        google_authenticators = []

        for ga in Google_Authenticator.objects.filter(user=request.user).all():
            google_authenticators.append({
                'id': ga.id,
                'title': ga.title,
            })

        return Response({
            "google_authenticators": google_authenticators
        },
            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Checks the REST Token and sets a new google authenticator for multifactor authentication

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        secret = pyotp.random_base32()

        new_ga = Google_Authenticator.objects.create(
            user=request.user,
            title= serializer.validated_data.get('title'),
            secret = encrypt_with_db_secret(str(secret))
        )

        return Response({
            "id": new_ga.id,
            "secret": str(secret)
        },
            status=status.HTTP_201_CREATED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an Google Authenticator

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteGASerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        google_authenticator = serializer.validated_data.get('google_authenticator')

        # delete it
        google_authenticator.delete()

        return Response(status=status.HTTP_200_OK)
