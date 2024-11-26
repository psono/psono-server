from anymail.exceptions import AnymailUnsupportedFeature
from django.conf import settings
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.parsers import JSONParser
from django.utils import translation

import os
from email.mime.image import MIMEImage

from ..utils.avatar import delete_avatar_storage_of_user
from ..app_settings import CreateUnregisterSerializer
from ..app_settings import UpdateUnregisterSerializer
from ..utils import generate_unregistration_code
from ..utils import decrypt_with_db_secret

class UnregisterView(GenericAPIView):
    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'PUT', 'OPTIONS', 'HEAD')
    throttle_scope = 'registration'
    parser_classes = [JSONParser]

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Accepts a user's unregistration link, validates it and then deletes the account

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype: 200 / 400
        """

        serializer = UpdateUnregisterSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']

        delete_avatar_storage_of_user(user.id)

        user.delete()

        return Response({}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        Accepts the email address or username and sends an email with a link that allows a user to delete his account

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype: 201 / 400
        """

        def splitAt(w, n):
            for i in range(0, len(w), n):
                yield w[i:i + n]

        serializer = CreateUnregisterSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']
        email = decrypt_with_db_secret(user.email)

        unregistration_code = generate_unregistration_code(email)

        if settings.WEB_CLIENT_URL:
            unregistration_link = settings.WEB_CLIENT_URL + '/delete-user-confirm.html#!/unregistration-code/' + unregistration_code
        else:
            unregistration_link = self.request.data.get('base_url', '') + 'delete-user-confirm.html#!/unregistration-code/' + unregistration_code

        with translation.override(request.LANGUAGE_CODE):
            subject = render_to_string('email/unregistration_subject.txt', {
                'email': email,
                'username': user.username,
                'unregistration_code': unregistration_code,
                'unregistration_link': unregistration_link,
                'unregistration_link_with_wbr': "<wbr>".join(splitAt(unregistration_link,40)),
                'host_url': settings.HOST_URL,
            }).replace('\n', ' ').replace('\r', '')
            msg_plain = render_to_string('email/unregistration.txt', {
                'email': email,
                'username': user.username,
                'unregistration_code': unregistration_code,
                'unregistration_link': unregistration_link,
                'unregistration_link_with_wbr': "<wbr>".join(splitAt(unregistration_link,40)),
                'host_url': settings.HOST_URL,
            })
            msg_html = render_to_string('email/unregistration.html', {
                'email': email,
                'username': user.username,
                'unregistration_code': unregistration_code,
                'unregistration_link': unregistration_link,
                'unregistration_link_with_wbr': "<wbr>".join(splitAt(unregistration_link,40)),
                'host_url': settings.HOST_URL,
            })


        if settings.EMAIL_BACKEND in ['anymail.backends.brevo.EmailBackend']:
            # SenndInBlue does not support inline attachments
            msg_html = msg_html.replace('cid:logo.png', f'{settings.WEB_CLIENT_URL}/img/logo.png')

        msg = EmailMultiAlternatives(subject, msg_plain, settings.EMAIL_FROM,
                                     [email])

        msg.attach_alternative(msg_html, "text/html")
        msg.mixed_subtype = 'related'

        if settings.EMAIL_BACKEND not in ['anymail.backends.brevo.EmailBackend']:
            # SenndInBlue does not support inline attachments
            for f in ['logo.png']:
                fp = open(os.path.join(os.path.dirname(__file__), '..', '..', 'static', 'email', f), 'rb')

                msg_img = MIMEImage(fp.read())
                fp.close()
                msg_img.add_header('Content-ID', '<{}>'.format(f))
                msg_img.add_header('Content-Disposition', 'inline', filename='logo.png')
                msg.attach(msg_img)

        try:
            msg.send()
        except AnymailUnsupportedFeature:
            raise
        except:
            return Response({"non_field_errors": ["UNREGISTRATION_EMAIL_DELIVERY_FAILED"]},
                            status=status.HTTP_400_BAD_REQUEST)

        return Response({},
                        status=status.HTTP_201_CREATED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)