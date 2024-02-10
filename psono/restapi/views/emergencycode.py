from django.contrib.auth.hashers import make_password

from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..authentication import TokenAuthentication
from ..app_settings import (
    CreateEmergencycodeSerializer,
    DeleteEmergencycodeSerializer,
)
from ..models import (
    Emergency_Code
)


class EmergencyCodeView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'POST', 'OPTIONS', 'HEAD')

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, request, *args, **kwargs):
        """
        Returns the list of emergency codes of the user
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        emegency_codes = []

        for code in Emergency_Code.objects.filter(user=request.user):
            emegency_codes.append({
                'id': code.id,
                'description': code.description,
                'activation_date': code.activation_date,
                'activation_delay': code.activation_delay,
            })

        return Response({
            'emegency_codes': emegency_codes
        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        Stores a new emergency code

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = CreateEmergencycodeSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        emergency_code = Emergency_Code.objects.create(
            user = request.user,
            description = serializer.validated_data['description'],
            activation_delay = serializer.validated_data['activation_delay'],
            emergency_authkey = make_password(str(serializer.validated_data['emergency_authkey'])),
            emergency_data = serializer.validated_data['emergency_data'].encode(),
            emergency_data_nonce = serializer.validated_data['emergency_data_nonce'],
            emergency_sauce = str(serializer.validated_data['emergency_sauce']),
        )

        return Response({
            'emergency_code_id': emergency_code.id
        }, status=status.HTTP_201_CREATED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an Emergency Code

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteEmergencycodeSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        emergency_code = serializer.validated_data.get('emergency_code')

        # delete it
        emergency_code.delete()

        return Response({}, status=status.HTTP_200_OK)
