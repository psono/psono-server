import json
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from django.conf import settings
import nacl.encoding

from webauthn import (
    generate_registration_options,
    options_to_json,
)
from webauthn.helpers.structs import AttestationConveyancePreference, AuthenticatorSelectionCriteria, UserVerificationRequirement

from ..permissions import IsAuthenticated
from ..models import Webauthn
from ..app_settings import NewWebauthnSerializer, ActivateWebauthnSerializer, DeleteWebauthnSerializer
from ..authentication import TokenAuthentication
from ..utils import encrypt_with_db_secret

class UserWebauthn(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return NewWebauthnSerializer
        if self.request.method == 'POST':
            return ActivateWebauthnSerializer
        if self.request.method == 'DELETE':
            return DeleteWebauthnSerializer
        return Serializer

    def get(self, request, *args, **kwargs):
        """
        Checks the REST Token and returns a list of all webauthns

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200
        :rtype:
        """

        webauthns = []

        for w in Webauthn.objects.filter(user=request.user).all():
            webauthns.append({
                'id': w.id,
                'active': w.active,
                'title': w.title,
            })

        return Response({
            "webauthns": webauthns
        },
            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Checks the REST Token and sets a new webauthn for multifactor authentication

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        origin = serializer.validated_data.get('origin')
        rp_id = serializer.validated_data.get('rp_id')

        opts = generate_registration_options(
            rp_id=rp_id,
            rp_name=settings.SERVICE_NAME,
            timeout=90000,
            user_id=str(request.user.id).encode("utf-8"),
            user_name=request.user.username,
            # attestation=AttestationConveyancePreference.DIRECT, # so we get the model back
            authenticator_selection=AuthenticatorSelectionCriteria(
                # authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                user_verification=UserVerificationRequirement.DISCOURAGED,  # so the user doesn't need to add a pin / passphrase when e.g. using his yubikey
            ),
        )
        options = json.loads(options_to_json(opts))

        new_webauthn = Webauthn.objects.create(
            user=request.user,
            title=serializer.validated_data.get('title'),
            origin=origin,
            rp_id=rp_id,
            challenge=encrypt_with_db_secret(str(options['challenge'])),
            active=False
        )

        return Response({
            "id": new_webauthn.id,
            "options": options
        },
            status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Validates a webauthn and activates it

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = ActivateWebauthnSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        webauthn = serializer.validated_data.get('webauthn')
        credential_id = serializer.validated_data.get('credential_id')
        credential_public_key = serializer.validated_data.get('credential_public_key')

        webauthn.credential_id = nacl.encoding.HexEncoder.encode(credential_id).decode()
        webauthn.credential_public_key = nacl.encoding.HexEncoder.encode(credential_public_key).decode()
        webauthn.active = True
        webauthn.save()

        request.user.webauthn_enabled = True
        request.user.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a webauthn

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteWebauthnSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        webauthn = serializer.validated_data.get('webauthn')
        webauthn_count = serializer.validated_data.get('webauthn_count')

        # Update the user attribute if we only had 1 webauthn
        if webauthn_count < 2 and webauthn.active:
            request.user.webauthn_enabled = False
            request.user.save()

        # delete it
        webauthn.delete()

        return Response({}, status=status.HTTP_200_OK)
