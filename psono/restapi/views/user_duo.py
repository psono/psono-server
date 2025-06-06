from django.utils import timezone
from datetime import timedelta
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from ..permissions import IsAuthenticated

from ..models import Duo
from ..app_settings import NewDuoSerializer, ActivateDuoSerializer, DeleteDuoSerializer
from ..utils import encrypt_with_db_secret
from ..authentication import TokenAuthentication

class UserDuo(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ActivateDuoSerializer
        if self.request.method == 'PUT':
            return NewDuoSerializer
        if self.request.method == 'DELETE':
            return DeleteDuoSerializer
        return Serializer

    def get(self, request, *args, **kwargs):
        """
        Checks the REST Token and returns a list of all duo
        """

        duos = []

        for duo in Duo.objects.filter(user=request.user).all():
            duos.append({
                'id': duo.id,
                'active': duo.active,
                'title': duo.title,
            })

        return Response({
            "duos": duos
        },
            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Checks the REST Token and sets a new duo for multifactor authentication
        """

        serializer = NewDuoSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        title = serializer.validated_data.get('title')
        use_system_wide_duo = serializer.validated_data.get('use_system_wide_duo')
        duo_integration_key = serializer.validated_data.get('integration_key')
        duo_secret_key = serializer.validated_data.get('secret_key')
        duo_host = serializer.validated_data.get('host')
        enrollment_user_id = serializer.validated_data.get('enrollment_user_id')
        enrollment_activation_code = serializer.validated_data.get('enrollment_activation_code')
        validity_in_seconds = serializer.validated_data.get('validity_in_seconds')

        if use_system_wide_duo:
            new_duo = Duo.objects.create(
                user = request.user,
                title = 'System wide',
                duo_integration_key = '',
                duo_secret_key = encrypt_with_db_secret(''),
                duo_host = '',
                enrollment_user_id = enrollment_user_id,
                enrollment_activation_code = enrollment_activation_code,
                enrollment_expiration_date = timezone.now() + timedelta(seconds=validity_in_seconds),
                active=False
            )
        else:
            new_duo = Duo.objects.create(
                user = request.user,
                title = title,
                duo_integration_key = duo_integration_key,
                duo_secret_key = encrypt_with_db_secret(duo_secret_key),
                duo_host = duo_host,
                enrollment_user_id = enrollment_user_id,
                enrollment_activation_code = enrollment_activation_code,
                enrollment_expiration_date = timezone.now() + timedelta(seconds=validity_in_seconds),
                active=False
            )

        return Response({
            "id": new_duo.id,
            "activation_code": new_duo.enrollment_activation_code,
        },
            status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Validates a duo and activates it
        """

        serializer = ActivateDuoSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        duo = serializer.validated_data.get('duo')

        # delete it
        duo.active = True
        duo.save()

        request.user.duo_enabled = True
        request.user.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a duo
        """

        serializer = DeleteDuoSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        duo = serializer.validated_data.get('duo')
        duo_count = serializer.validated_data.get('duo_count')

        # Update the user attribute if we only had 1 duo
        if duo_count < 2 and duo.active:
            request.user.duo_enabled = False
            request.user.save()

        # delete it
        duo.delete()

        return Response({}, status=status.HTTP_200_OK)
