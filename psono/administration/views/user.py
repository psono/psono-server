from django.db.models import Exists, OuterRef
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    UserSerializer, DeleteUserSerializer, UpdateUserSerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import User, User_Group_Membership, Duo, Google_Authenticator, Yubikey_OTP, Recovery_Code
# from restapi.utils import decrypt_with_db_secret


class UserView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    serializer_class = UserSerializer
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_user_info(self, user_id):

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

        groups = []
        for m in User_Group_Membership.objects.filter(user=user).select_related('group').only("id", "accepted", "group_admin", "create_date", "group__id", "group__name", "group__create_date", "group__public_key"):
            groups.append({
                'id': m.group.id,
                'name': m.group.name,
                'create_date': m.group.create_date,
                'public_key': m.group.public_key,
                'membership_id': m.id,
                'membership_create_date': m.create_date,
                'accepted': m.accepted,
                'admin': m.group_admin,
            })

        duos = []
        for d in Duo.objects.filter(user=user).only("id", "title", "duo_integration_key", "duo_secret_key", "duo_host", "create_date", "active"):
            duos.append({
                'id': d.id,
                'title': d.title,
                'duo_integration_key': d.duo_integration_key,
                'duo_secret_key': d.duo_secret_key,
                'duo_host': d.duo_host,
                'create_date': d.create_date,
                'active': d.active,
            })

        google_authenticators = []
        for g in Google_Authenticator.objects.filter(user=user).only("id", "title", "create_date", "active"):
            duos.append({
                'id': g.id,
                'title': g.title,
                'create_date': g.create_date,
                'active': g.active,
            })

        yubikey_otps = []
        for y in Yubikey_OTP.objects.filter(user=user).only("id", "title", "create_date", "active"):
            yubikey_otps.append({
                'id': y.id,
                'title': y.title,
                'create_date': y.create_date,
                'active': y.active,
            })

        recovery_codes = []
        for r in Recovery_Code.objects.filter(user=user).only("id", "create_date"):
            recovery_codes.append({
                'id': r.id,
                'create_date': r.create_date,
            })

        return {
            'id': user.id,
            'username': user.username,
            # 'email': decrypt_with_db_secret(user.email),
            'create_date': user.create_date,
            'public_key': user.public_key,
            'is_email_active': user.is_email_active,
            'is_superuser': user.is_staff,
            'authentication': user.authentication,

            'groups': groups,
            'duos': duos,
            'google_authenticators': google_authenticators,
            'yubikey_otps': yubikey_otps,
        }

    def get(self, request, user_id = None, *args, **kwargs):
        """
        Returns a list of all users or a the infos of a single user

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """
        if user_id:


            user_info = self.get_user_info(user_id)

            if not user_info:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            return Response(user_info,
                status=status.HTTP_200_OK)

        else:
            recovery_codes = Recovery_Code.objects.filter(user = OuterRef('pk')).only('id')


            users = []
            for u in  User.objects.annotate(recovery_code_exist=Exists(recovery_codes))\
                    .only('id', 'create_date', 'username', 'is_active', 'is_email_active').order_by('-create_date'):
                users.append({
                    'id': u.id,
                    'create_date': u.create_date.strftime('%Y-%m-%d %H:%M:%S'),
                    'username': u.username,
                    'is_active': u.is_active,
                    'is_email_active': u.is_email_active,
                    'duo_2fa': u.duo_enabled,
                    'ga_2fa': u.google_authenticator_enabled,
                    'yubikey_2fa': u.yubikey_otp_enabled,
                    'recovery_code': u.recovery_code_exist,
                })

            return Response({
                'users': users
            }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Updates a user

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = UpdateUserSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.validated_data.get('user')
        is_active = serializer.validated_data.get('is_active')
        is_email_active = serializer.validated_data.get('is_email_active')
        email = serializer.validated_data.get('email')

        if is_active is not None:
            user.is_active = is_active

        if is_email_active is not None:
            user.is_email_active = is_email_active

        if email is not None:
            user.email = email
            user.email_bcrypt = serializer.validated_data.get('email_bcrypt')

        # saves it
        user.save()

        return Response(status=status.HTTP_200_OK)

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
        Deletes a user

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteUserSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.validated_data.get('user')

        # delete it
        user.delete()

        return Response(status=status.HTTP_200_OK)
