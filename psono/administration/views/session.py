from django.db.models import F, Q
from django.core.paginator import Paginator
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    ReadSessionSerializer,
    DeleteSessionSerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Token


class SessionView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Returns a list of all sessions

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = ReadSessionSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        page = serializer.validated_data.get('page')
        page_size = serializer.validated_data.get('page_size')
        ordering = serializer.validated_data.get('ordering')
        search = serializer.validated_data.get('search')

        session_qs = Token.objects.select_related('user').annotate(username=F('user__username'))\
            .filter(valid_till__gt=timezone.now())\
            .only('id', 'create_date', 'user__username', 'active', 'valid_till', 'device_description', 'device_fingerprint')

        if search:
            session_qs = session_qs.filter(Q(user__username__icontains=search) | Q(device_description__icontains=search))
        if ordering:
            session_qs = session_qs.order_by(ordering)

        count = None
        if page_size:
            paginator = Paginator(session_qs, page_size)
            count = paginator.count
            chosen_page = paginator.page(page)
            session_qs = chosen_page.object_list

        sessions = []
        for u in  session_qs:
            sessions.append({
                'id': u.id,
                'create_date': u.create_date,
                'username': u.user.username,
                'active': u.active,
                'valid_till': u.valid_till,
                'device_description': u.device_description,
                'device_fingerprint': u.device_fingerprint,
            })

        return Response({
            'count': count,
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

        return Response({}, status=status.HTTP_200_OK)
