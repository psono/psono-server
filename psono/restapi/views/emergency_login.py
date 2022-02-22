from django.conf import settings
from django.utils import timezone
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives

from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny

from datetime import timedelta
from math import ceil
from email.mime.image import MIMEImage
import json
import os
import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box

from ..utils import decrypt_with_db_secret
from ..app_settings import (
    EmergencyLoginSerializer,
    ActivateEmergencyLoginSerializer,
)


from ..models import (
    Token
)

from ..utils import readbuffer

class EmergencyLoginView(GenericAPIView):

    permission_classes = (AllowAny,)
    allowed_methods = ('PUT', 'POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'password'

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Second step of the login with emergency code.
        Validates the code and returns an active session.

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400 / 403
        :rtype:
        """

        serializer = ActivateEmergencyLoginSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.validated_data['user']
        user_session_public_key_hex = serializer.validated_data['user_session_public_key']

        emergency_code = serializer.validated_data['emergency_code']

        emergency_code.verifier  = ''
        emergency_code.verifier_issue_date  = None
        emergency_code.save()

        if not settings.ALLOW_MULTIPLE_SESSIONS:
            Token.objects.filter(user=user).delete()

        token = Token.objects.create(
            user=user,
            device_fingerprint=serializer.validated_data.get('device_fingerprint', ''),
            device_description=serializer.validated_data.get('device_description', ''),
            client_date=serializer.validated_data.get('device_time'),
            valid_till=timezone.now() + timedelta(seconds=serializer.validated_data.get('session_duration')),
            active=True,
            is_emergency_session=True,
        )

        response = {
            "token": token.clear_text_key,
            "session_secret_key": token.secret_key,
            "user_public_key": user.public_key,
            "user_email": decrypt_with_db_secret(user.email),
            'user_id': str(user.id)
        }

        server_crypto_box = Box(PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
                                PublicKey(user_session_public_key_hex, encoder=nacl.encoding.HexEncoder))


        login_info_nonce = nacl.utils.random(Box.NONCE_SIZE)
        login_info_nonce_hex = nacl.encoding.HexEncoder.encode(login_info_nonce)
        encrypted = server_crypto_box.encrypt(json.dumps(response).encode(), login_info_nonce)
        encrypted_login_info = encrypted[len(login_info_nonce):]
        encrypted_login_info_hex = nacl.encoding.HexEncoder.encode(encrypted_login_info)

        return Response({
            'login_info': encrypted_login_info_hex,
            'login_info_nonce': login_info_nonce_hex,
        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        First step of the login with an emergency code

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400/ 403
        :rtype:
        """

        serializer = EmergencyLoginSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.validated_data['user']
        emergency_code = serializer.validated_data['emergency_code']

        if not emergency_code.activation_date:
            emergency_code.activation_date = timezone.now()
            emergency_code.save()

            # send email
            if settings.WEB_CLIENT_URL:
                emergency_code_link = settings.WEB_CLIENT_URL + '/activate.html#!/account/emergency-codes'
            else:
                emergency_code_link = None

            msg_plain = render_to_string('email/emergency_code_armed.txt', {
                'emergency_code_description': emergency_code.description,
                'emergency_code_activation_delay': emergency_code.activation_delay,
                'activation_link': emergency_code_link,
                'host_url': settings.HOST_URL,
            })
            msg_html = render_to_string('email/emergency_code_armed.html', {
                'emergency_code_description': emergency_code.description,
                'emergency_code_activation_delay': emergency_code.activation_delay,
                'activation_link': emergency_code_link,
                'host_url': settings.HOST_URL,
            })


            if settings.EMAIL_BACKEND in ['anymail.backends.sendinblue.EmailBackend']:
                # SenndInBlue does not support inline attachments
                msg_html = msg_html.replace('cid:logo.png', f'{settings.WEB_CLIENT_URL}/img/logo.png')

            msg = EmailMultiAlternatives(settings.EMAIL_TEMPLATE_EMERGENCY_CODE_ARMED_SUBJECT, msg_plain, settings.EMAIL_FROM,
                                         [decrypt_with_db_secret(emergency_code.user.email)])

            msg.attach_alternative(msg_html, "text/html")
            msg.mixed_subtype = 'related'

            if settings.EMAIL_BACKEND not in ['anymail.backends.sendinblue.EmailBackend']:
                for f in ['logo.png']:
                    fp = open(os.path.join(os.path.dirname(__file__), '..', '..', 'static', 'email', f), 'rb')

                    msg_img = MIMEImage(fp.read())
                    fp.close()
                    msg_img.add_header('Content-ID', '<{}>'.format(f))
                    msg.attach(msg_img)

            msg.send()

            if emergency_code.activation_delay > 0:
                return Response({
                    'remaining_wait_time': emergency_code.activation_delay,
                    'status': 'started',
                }, status=status.HTTP_200_OK)


        remaining_wait_time = emergency_code.activation_date + timedelta(seconds=emergency_code.activation_delay) - timezone.now()
        if emergency_code.activation_delay > 0 and remaining_wait_time.total_seconds() > 0:
            return Response({
                'remaining_wait_time': int(ceil(remaining_wait_time.total_seconds())),
                'status': 'waiting',
            }, status=status.HTTP_200_OK)


        verifier_box = PrivateKey.generate()
        public_key = verifier_box.public_key.encode(encoder=nacl.encoding.HexEncoder)

        verifier_issue_date = timezone.now()

        emergency_code.verifier = verifier_box.encode(encoder=nacl.encoding.HexEncoder).decode()
        emergency_code.verifier_issue_date  = verifier_issue_date
        emergency_code.save()

        return Response({
            'remaining_wait_time': 0,
            'status': 'ready',
            'emergency_data': readbuffer(emergency_code.emergency_data),
            'emergency_data_nonce': emergency_code.emergency_data_nonce,
            'emergency_sauce': emergency_code.emergency_sauce,
            'user_sauce': user.user_sauce,
            'verifier_public_key': public_key.decode(),
            'verifier_time_valid': settings.RECOVERY_VERIFIER_TIME_VALID
        }, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)