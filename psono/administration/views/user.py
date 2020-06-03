from django.db.models import Exists, OuterRef
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    DeleteUserSerializer, UpdateUserSerializer, CreateUserSerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import User, User_Group_Membership, Duo, Google_Authenticator, Yubikey_OTP, Recovery_Code, Emergency_Code, Token, User_Share_Right
from restapi.utils import decrypt_with_db_secret, create_user

import secrets
import string


class UserView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD')

    def get_user_info(self, user_id):

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

        memberships = []
        for m in User_Group_Membership.objects.filter(user=user).select_related('group').only("id", "accepted", "group_admin", "create_date", "group__id", "group__name", "group__create_date", "group__public_key"):
            memberships.append({
                'id': m.id,
                'create_date': m.create_date,
                'accepted': m.accepted,
                'admin': m.group_admin,
                'group_id': m.group.id,
                'group_name': m.group.name,
            })

        duos = []
        for d in Duo.objects.filter(user=user).only("id", "title", "duo_integration_key", "duo_secret_key", "duo_host", "create_date", "active"):
            duos.append({
                'id': d.id,
                'title': d.title,
                'create_date': d.create_date,
                'active': d.active,
            })

        google_authenticators = []
        for g in Google_Authenticator.objects.filter(user=user).only("id", "title", "create_date", "active"):
            google_authenticators.append({
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

        emergency_codes = []
        for r in Emergency_Code.objects.filter(user=user).only("id", "create_date", "description"):
            emergency_codes.append({
                'id': r.id,
                'create_date': r.create_date,
                'description': r.description,
                'activation_delay': r.activation_delay,
            })

        sessions = []
        for u in Token.objects.filter(user=user).only('id', 'create_date', 'active',
                                                           'valid_till', 'device_description',
                                                           'device_fingerprint').order_by('-create_date'):
            sessions.append({
                'id': u.id,
                'create_date': u.create_date,
                'active': u.active,
                'valid_till': u.valid_till,
                'device_description': u.device_description,
                'device_fingerprint': u.device_fingerprint,
            })

        share_rights = []
        for m in User_Share_Right.objects.filter(user=user).only("id", "create_date", "read", "write", "grant", "accepted", "share_id"):
            share_rights.append({
                'id': m.id,
                'create_date': m.create_date,
                'read': m.read,
                'write': m.write,
                'grant': m.grant,
                'accepted': m.accepted,
                'share_id': m.share_id,
            })

        return {
            'id': user.id,
            'username': user.username,
            'email': decrypt_with_db_secret(user.email),
            'create_date': user.create_date,
            'public_key': user.public_key,
            'is_active': user.is_active,
            'is_email_active': user.is_email_active,
            'is_superuser': user.is_superuser,
            'is_staff': user.is_staff or user.is_superuser,
            'authentication': user.authentication,

            'memberships': memberships,
            'duos': duos,
            'google_authenticators': google_authenticators,
            'yubikey_otps': yubikey_otps,
            'recovery_codes': recovery_codes,
            'emergency_codes': emergency_codes,
            'sessions': sessions,
            'share_rights': share_rights,
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
            emergency_codes = Emergency_Code.objects.filter(user = OuterRef('pk')).only('id')


            users = []
            for u in  User.objects.annotate(recovery_code_exist=Exists(recovery_codes), emergency_code_exist=Exists(emergency_codes))\
                    .only('id', 'create_date', 'username', 'is_active', 'is_email_active', 'duo_enabled', 'google_authenticator_enabled', 'yubikey_otp_enabled').order_by('-create_date'):
                users.append({
                    'id': u.id,
                    'create_date': u.create_date,
                    'username': u.username,
                    'is_active': u.is_active,
                    'is_email_active': u.is_email_active,
                    'duo_2fa': u.duo_enabled,
                    'ga_2fa': u.google_authenticator_enabled,
                    'yubikey_2fa': u.yubikey_otp_enabled,
                    'recovery_code': u.recovery_code_exist,
                    'emergency_code': u.emergency_code_exist,
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
        is_superuser = serializer.validated_data.get('is_superuser')
        email = serializer.validated_data.get('email')

        if is_active is not None:
            user.is_active = is_active

        if is_email_active is not None:
            user.is_email_active = is_email_active

        if is_superuser is not None:
            user.is_superuser = is_superuser

        if email is not None:
            user.email = email
            user.email_bcrypt = serializer.validated_data.get('email_bcrypt')

        # saves it
        user.save()

        return Response(status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        Creates a user

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateUserSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data.get('username')
        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')

        if not password:
            password = ''.join(secrets.choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(12))

        user_details = create_user(
            username=username,
            password=password,
            email=email,
        )

        if 'error' in user_details:
            return Response({"non_field_errors": [user_details['error']]},
                            status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'id': user_details['user'].id,
            'password': password,
        }, status=status.HTTP_201_CREATED)

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
