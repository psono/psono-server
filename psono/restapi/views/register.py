from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny

from ..app_settings import (
    RegisterSerializer,
)
from ..utils import generate_activation_code

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)

class RegisterView(GenericAPIView):
    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'registration'

    serializer_class = RegisterSerializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Accepts the username, email and authkey and creates a new user
        if the username (and email address) do not already exist

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        def splitAt(w, n):
            for i in range(0, len(w), n):
                yield w[i:i + n]

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='REGISTER_ERROR', errors=serializer.errors)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        activation_code = generate_activation_code(serializer.validated_data['email'])

        # serializer.validated_data['email'] gets now encrypted
        user = serializer.save()

        # if len(self.request.data.get('base_url', '')) < 1:
        #    raise exceptions.ValidationError(msg)


        if settings.WEB_CLIENT_URL:
            activation_link = settings.WEB_CLIENT_URL + '/activate.html#!/activation-code/' + activation_code
        else:
            activation_link = self.request.data.get('base_url', '') + 'activate.html#!/activation-code/' + activation_code

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

        send_mail(
            'Registration successful',
            msg_plain,
            settings.EMAIL_FROM,
            [self.request.data.get('email', '')],
            html_message=msg_html,
        )

        log_info(logger=logger, request=request, status='HTTP_201_CREATED',
                 event='REGISTER_SUCCESS', request_resource=user.id)

        return Response({"success": "Successfully registered."},
                        status=status.HTTP_201_CREATED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)