import os
from email.mime.image import MIMEImage
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.core.cache import cache
from django.conf import settings
from django.utils import translation

from ..utils import decrypt_with_db_secret
from ..permissions import IsAuthenticated

from ..app_settings import (
    CreateMembershipSerializer,
    UpdateMembershipSerializer,
    DeleteMembershipSerializer,
)
from ..models import (
    User_Group_Membership
)
from ..authentication import TokenAuthentication

class MembershipView(GenericAPIView):

    """
    Manages group memberships
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



    def put(self, request, *args, **kwargs):
        """
        Creates a new group membership

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateMembershipSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        membership = User_Group_Membership.objects.create(
            user_id = serializer.validated_data['user_id'],
            group_id = serializer.validated_data['group_id'],
            creator = request.user,
            secret_key = str(serializer.validated_data['secret_key']),
            secret_key_nonce = str(serializer.validated_data['secret_key_nonce']),
            secret_key_type = str(serializer.validated_data['secret_key_type']),
            private_key = str(serializer.validated_data['private_key']),
            private_key_nonce = str(serializer.validated_data['private_key_nonce']),
            private_key_type = str(serializer.validated_data['private_key_type']),
            group_admin = serializer.validated_data['group_admin'],
            share_admin = serializer.validated_data['share_admin'],
        )

        if not settings.DISABLE_EMAIL_NEW_GROUP_MEMBERSHIP_CREATED and serializer.validated_data['user'].email:
            # send email
            if settings.WEB_CLIENT_URL:
                groups_link = settings.WEB_CLIENT_URL + '/index.html#!/groups'
            else:
                groups_link = None

            with translation.override(serializer.validated_data['user'].language):
                subject = render_to_string('email/new_group_membership_created_subject.txt', {
                    'groups_link': groups_link
                }).replace('\n', ' ').replace('\r', '')
                msg_plain = render_to_string('email/new_group_membership_created.txt', {
                    'groups_link': groups_link
                })
                msg_html = render_to_string('email/new_group_membership_created.html', {
                    'groups_link': groups_link
                })

            if settings.EMAIL_BACKEND in ['anymail.backends.brevo.EmailBackend']:
                # Brevo does not support inline attachments
                msg_html = msg_html.replace('cid:logo.png', f'{settings.WEB_CLIENT_URL}/img/logo.png')

            msg = EmailMultiAlternatives(subject, msg_plain,
                                         settings.EMAIL_FROM,
                                         [decrypt_with_db_secret(serializer.validated_data['user'].email)])

            msg.attach_alternative(msg_html, "text/html")
            msg.mixed_subtype = 'related'

            if settings.EMAIL_BACKEND not in ['anymail.backends.brevo.EmailBackend']:
                for f in ['logo.png']:
                    fp = open(os.path.join(os.path.dirname(__file__), '..', '..', 'static', 'email', f), 'rb')

                    msg_img = MIMEImage(fp.read())
                    fp.close()
                    msg_img.add_header('Content-ID', '<{}>'.format(f))
                    msg_img.add_header('Content-Disposition', 'inline', filename='logo.png')
                    msg.attach(msg_img)

            try:
                msg.send()
            except:  # nosec
                # Let's not fail group invitation for failing emails e.g. due to a completely missing email config
                pass

        if settings.CACHE_ENABLE:
            cache_key = 'psono_user_status_' + str(serializer.validated_data['user_id'])
            cache.delete(cache_key)

        return Response({'membership_id': membership.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a group membership

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        serializer = UpdateMembershipSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        membership = serializer.validated_data['membership']
        membership.group_admin = serializer.validated_data['group_admin']
        membership.share_admin = serializer.validated_data['share_admin']
        membership.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a group membership

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteMembershipSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        membership = serializer.validated_data.get('membership')

        if settings.CACHE_ENABLE:
            cache_key = 'psono_user_status_' + str(membership.user.id)
            cache.delete(cache_key)

        # delete it
        membership.delete()

        return Response({}, status=status.HTTP_200_OK)
