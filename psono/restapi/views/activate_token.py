from anymail.exceptions import AnymailUnsupportedFeature
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from django.core.mail import EmailMultiAlternatives
from django.utils import timezone
from django.conf import settings
from django.template.loader import render_to_string
from django.utils import translation

import os
from email.mime.image import MIMEImage

from ..permissions import IsAuthenticated
from ..models import Token
from ..app_settings import ActivateTokenSerializer
from ..authentication import TokenAuthenticationAllowInactive
from ..utils import decrypt_with_db_secret
from ..utils import get_ip

class ActivateTokenView(GenericAPIView):

    authentication_classes = (TokenAuthenticationAllowInactive, )
    permission_classes = (IsAuthenticated,)
    serializer_class = ActivateTokenSerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Activates a token

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

        token = serializer.validated_data['token']

        token.active = True
        token.user_validator = None
        token.save()

        ip_address = get_ip(request)
        login_datetime = timezone.now()

        request.user.last_login = login_datetime
        request.user.save()

        def splitAt(w, n):
            for i in range(0, len(w), n):
                yield w[i:i + n]


        if not settings.DISABLE_EMAIL_NEW_LOGIN:
            email = decrypt_with_db_secret(request.user.email)

            with translation.override(request.LANGUAGE_CODE):
                subject = render_to_string('email/new_login_subject.txt', {
                    'ip_address': ip_address,
                    'login_datetime': login_datetime,
                    'email': email,
                    'username': request.user.username,
                    'webclient_url': settings.WEB_CLIENT_URL,
                    'webclient_url_with_wbr': "<wbr>".join(splitAt(settings.WEB_CLIENT_URL,40)),
                    'host_url': settings.HOST_URL,
                }).replace('\n', ' ').replace('\r', '')
                msg_plain = render_to_string('email/new_login.txt', {
                    'ip_address': ip_address,
                    'login_datetime': login_datetime,
                    'email': email,
                    'username': request.user.username,
                    'webclient_url': settings.WEB_CLIENT_URL,
                    'webclient_url_with_wbr': "<wbr>".join(splitAt(settings.WEB_CLIENT_URL,40)),
                    'host_url': settings.HOST_URL,
                })
                msg_html = render_to_string('email/new_login.html', {
                    'ip_address': ip_address,
                    'login_datetime': login_datetime,
                    'email': email,
                    'username': request.user.username,
                    'webclient_url': settings.WEB_CLIENT_URL,
                    'webclient_url_with_wbr': "<wbr>".join(splitAt(settings.WEB_CLIENT_URL,40)),
                    'host_url': settings.HOST_URL,
                })


            if settings.EMAIL_BACKEND in ['anymail.backends.brevo.EmailBackend']:
                # Brevo does not support inline attachments
                msg_html = msg_html.replace('cid:logo.png', f'{settings.WEB_CLIENT_URL}/img/logo.png')

            msg = EmailMultiAlternatives(subject, msg_plain, settings.EMAIL_FROM,
                                         [email])

            msg.attach_alternative(msg_html, "text/html")
            msg.mixed_subtype = 'related'

            if settings.EMAIL_BACKEND not in ['anymail.backends.brevo.EmailBackend']:
                # Brevo does not support inline attachments
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
                # Let's not fail login for failing emails e.g. due to a completely missing email config
                pass

        return Response({
            "user": {
                "id": request.user.id,
                "authentication": 'AUTHKEY',
                "email": decrypt_with_db_secret(request.user.email) if request.user.email else '',
                "secret_key": request.user.secret_key,
                "secret_key_nonce": request.user.secret_key_nonce
            }
        },status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)