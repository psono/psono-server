from anymail.exceptions import AnymailUnsupportedFeature
from django.conf import settings
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.serializers import Serializer
from rest_framework.parsers import JSONParser
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError
from django.utils import translation

import os
from email.mime.image import MIMEImage

from ..models import User
from ..app_settings import RegisterSerializer
from ..utils import generate_activation_code

class RegisterView(GenericAPIView):
    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'registration'
    parser_classes = [JSONParser]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return RegisterSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Accepts the username, email and authkey and creates a new user
        if the username (and email address) do not already exist
        """

        def splitAt(w, n):
            for i in range(0, len(w), n):
                yield w[i:i + n]

        if not settings.ALLOW_REGISTRATION or not settings.WEB_CLIENT_URL:
            return Response({"custom": ["REGISTRATION_HAS_BEEN_DISABLED"]},
                            status=status.HTTP_400_BAD_REQUEST)

        if settings.ENFORCE_MATCHING_USERNAME_AND_EMAIL and self.request.data.get('username', '').lower() != self.request.data.get('email', '').lower():
            return Response({"custom": ["REGISTRATION_FAILED_USERNAME_AND_EMAIL_HAVE_TO_MATCH"]},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = RegisterSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data['username']
        authkey = serializer.validated_data['authkey']
        public_key = serializer.validated_data['public_key']
        private_key = serializer.validated_data['private_key']
        private_key_nonce = serializer.validated_data['private_key_nonce']
        secret_key = serializer.validated_data['secret_key']
        secret_key_nonce = serializer.validated_data['secret_key_nonce']
        user_sauce = serializer.validated_data['user_sauce']
        email = serializer.validated_data['email']
        email_decrypted = serializer.validated_data['email_decrypted']
        email_bcrypt = serializer.validated_data['email_bcrypt']
        hashing_algorithm = serializer.validated_data['hashing_algorithm']
        hashing_parameters = serializer.validated_data['hashing_parameters']
        credit = serializer.validated_data['credit']

        activation_code = generate_activation_code(email_decrypted)

        try:
            user = User.objects.create(
                username=username,
                authkey=make_password(authkey),
                public_key=public_key,
                private_key=private_key,
                private_key_nonce=private_key_nonce,
                secret_key=secret_key,
                secret_key_nonce=secret_key_nonce,
                user_sauce=user_sauce,
                email=email,
                email_bcrypt=email_bcrypt,
                hashing_algorithm=hashing_algorithm,
                hashing_parameters=hashing_parameters,
                language=request.LANGUAGE_CODE,
                credit=credit,
            )
        except IntegrityError:
            return Response({"custom": ["REGISTRATION_FAILED_USERNAME_ALREADY_EXISTS"]},
                            status=status.HTTP_400_BAD_REQUEST)

        if settings.WEB_CLIENT_URL:
            activation_link = settings.WEB_CLIENT_URL + '/activate.html#!/activation-code/' + activation_code
        else:
            return None

        with translation.override(request.LANGUAGE_CODE):
            subject = render_to_string('email/registration_successful_subject.txt', {
                'email': self.request.data.get('email', ''),
                'username': self.request.data.get('username', ''),
                'activation_code': activation_code,
                'activation_link': activation_link,
                'activation_link_with_wbr': "<wbr>".join(splitAt(activation_link,40)),
                'host_url': settings.HOST_URL,
            }).replace('\n', ' ').replace('\r', '')
            msg_plain = render_to_string('email/registration_successful.txt', {
                'email': self.request.data.get('email', ''),
                'username': self.request.data.get('username', ''),
                'activation_code': activation_code,
                'activation_link': activation_link,
                'activation_link_with_wbr': "<wbr>".join(splitAt(activation_link,40)),
                'host_url': settings.HOST_URL,
            })
            msg_html = render_to_string('email/registration_successful.html', {
                'email': self.request.data.get('email', ''),
                'username': self.request.data.get('username', ''),
                'activation_code': activation_code,
                'activation_link': activation_link,
                'activation_link_with_wbr': "<wbr>".join(splitAt(activation_link,40)),
                'host_url': settings.HOST_URL,
            })


        if settings.EMAIL_BACKEND in ['anymail.backends.brevo.EmailBackend']:
            # Brevo does not support inline attachments
            msg_html = msg_html.replace('cid:logo.png', f'{settings.WEB_CLIENT_URL}/img/logo.png')

        msg = EmailMultiAlternatives(subject, msg_plain, settings.EMAIL_FROM,
                                     [self.request.data.get('email', '')])

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
        except AnymailUnsupportedFeature:
            user.delete()
            raise
        except:
            user.delete()
            return Response({"non_field_errors": ["REGISTRATION_EMAIL_DELIVERY_FAILED"]},
                            status=status.HTTP_400_BAD_REQUEST)

        return Response({"success": "REGISTRATION_SUCCESSFUL"},
                        status=status.HTTP_201_CREATED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)