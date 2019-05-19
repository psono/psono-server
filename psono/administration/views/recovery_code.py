from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    DeleteRecoveryCodeSerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Recovery_Code


class RecoveryCodeView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    serializer_class = DeleteRecoveryCodeSerializer
    allowed_methods = ('DELETE', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        """
        Returns a list of all recovery codes

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        recovery_codes = []
        for g in  Recovery_Code.objects.select_related('user').order_by('-create_date'):
            recovery_codes.append({
                'id': g.id,
                'create_date': g.create_date,
                'user': g.user.username,
            })

        return Response({
            'recovery_codes': recovery_codes
        }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a Recovery Code

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteRecoveryCodeSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        recovery_code = serializer.validated_data.get('recovery_code')

        # delete it
        recovery_code.delete()

        return Response(status=status.HTTP_200_OK)
