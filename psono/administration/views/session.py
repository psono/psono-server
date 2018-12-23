from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    DeleteSessionSerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Token


class SessionView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        """
        Returns a list of all sessions

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        sessions = []
        for u in  Token.objects.select_related('user').only('id', 'create_date', 'user__username', 'active', 'valid_till', 'device_description', 'device_fingerprint').order_by('-create_date'):
            sessions.append({
                'id': u.id,
                'create_date': u.create_date.strftime('%Y-%m-%d %H:%M:%S'),
                'username': u.user.username,
                'active': u.active,
                'valid_till': u.valid_till.strftime('%Y-%m-%d %H:%M:%S'),
                'device_description': u.device_description,
                'device_fingerprint': u.device_fingerprint,
            })

        return Response({
            'sessions': sessions
        }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        # """
        # Check the REST Token and returns the user's public key. To identify the user either the email or the user_id needs
        # to be provided
        #
        # Return the user's public key
        #
        # :param request:
        # :type request:
        # :param args:
        # :type args:
        # :param kwargs:
        # :type kwargs:
        # :return: 200 / 400
        # :rtype:
        # """
        #
        # serializer = self.get_serializer(data=request.data)
        #
        # if not serializer.is_valid():
        #
        #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        #
        # user = serializer.validated_data.get('user')
        #
        # user_details = {
        #     'id': user.id,
        #     'public_key': user.public_key,
        #     'username': user.username
        # }
        #
        # if user.id == request.user.id:
        #     user_details['multifactor_auth_enabled'] = Google_Authenticator.objects.filter(user=user).exists() or Yubikey_OTP.objects.filter(user=user).exists()
        #     user_details['recovery_code_enabled'] = Recovery_Code.objects.filter(user=user).exists()
        #
        #
        # return Response(user_details, status=status.HTTP_200_OK)
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a session

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteSessionSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        token = serializer.validated_data.get('token')

        # delete it
        token.delete()

        return Response(status=status.HTTP_200_OK)
