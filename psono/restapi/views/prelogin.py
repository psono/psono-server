from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny

from ..models import (
    User,
    default_hashing_parameters,
)
from ..app_settings import (
    PreLoginSerializer
)

class PreLoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = PreLoginSerializer
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'prelogin'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Will return the hashing algorithm and configured paramters for a given user.
        Will return fake parameters if a user is not found to prevent username probing.

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """
        serializer = self.get_serializer(data=self.request.data)

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.validated_data['user']

        hashing_parameters = default_hashing_parameters()
        hashing_algorithm = User.DEFAULT_HASHING_ALGORITHM

        if user:
            hashing_parameters = user.hashing_parameters
            hashing_algorithm = user.hashing_algorithm


        return Response({
            'hashing_parameters': hashing_parameters,
            'hashing_algorithm': hashing_algorithm
        }, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)