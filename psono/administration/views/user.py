from django.db.models import Exists, OuterRef
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    UserSerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import User, Duo, Google_Authenticator, Yubikey_OTP


class UserView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    serializer_class = UserSerializer
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        """
        Returns a list of all users

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        duos = Duo.objects.filter(user = OuterRef('pk')).only('id')
        gas = Google_Authenticator.objects.filter(user = OuterRef('pk')).only('id')
        yubikeys = Yubikey_OTP.objects.filter(user = OuterRef('pk')).only('id')


        users = []
        for u in  User.objects.annotate(duo_2fa=Exists(duos), ga_2fa=Exists(gas), yubikey_2fa=Exists(yubikeys))\
                .only('id', 'create_date', 'username', 'is_active', 'is_email_active').order_by('-create_date'):
            users.append({
                'id': u.id,
                'create_date': u.create_date.strftime('%Y-%m-%d %H:%M:%S'),
                'username': u.username,
                'is_active': u.is_active,
                'is_email_active': u.is_email_active,
                'duo_2fa': u.duo_2fa,
                'ga_2fa': u.duo_2fa,
                'yubikey_2fa': u.yubikey_2fa,
            })

        return Response({
            'users': users
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

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
