from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
import pyotp

from ..models import Google_Authenticator
from ..app_settings import NewGASerializer, ActivateGASerializer, DeleteGASerializer
from ..authentication import TokenAuthentication
from ..utils import encrypt_with_db_secret

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
                'active': ga.active,
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
            secret = encrypt_with_db_secret(str(secret)),
            active=False
        )

        return Response({
            "id": new_ga.id,
            "secret": str(secret)
        },
            status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Validates a Google authenticator and activates it

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = ActivateGASerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        google_authenticator = serializer.validated_data.get('google_authenticator')

        google_authenticator.active = True
        google_authenticator.save()

        request.user.google_authenticator_enabled = True
        request.user.save()

        return Response(status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a Google Authenticator

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
        google_authenticator_count = serializer.validated_data.get('google_authenticator_count')

        # Update the user attribute if we only had 1 yubikey
        if google_authenticator_count < 2 and google_authenticator.active:
            request.user.google_authenticator_enabled = False
            request.user.save()

        # delete it
        google_authenticator.delete()

        return Response(status=status.HTTP_200_OK)
