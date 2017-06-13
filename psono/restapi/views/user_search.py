from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    User, Google_Authenticator, Yubikey_OTP, Recovery_Code
)

from ..app_settings import (
    UserPublicKeySerializer
)
from django.core.exceptions import ValidationError


from ..authentication import TokenAuthentication


class UserSearch(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = UserPublicKeySerializer
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Check the REST Token and returns the user's public key. To identify the user either the email or the user_id needs
        to be provided

        Return the user's public key

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """
        if 'user_id' in request.data and request.data['user_id']:
            try:
                user = User.objects.get(pk=str(request.data['user_id']))
            except ValidationError:
                return Response({"error": "IdNoUUID", 'message': "User ID is badly formed and no uuid"},
                                status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_id'])}, status=status.HTTP_403_FORBIDDEN)

        elif 'user_username' in request.data and request.data['user_username']:
            try:
                user = User.objects.get(username=str(request.data['user_username']))
            except User.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": str(request.data['user_username'])}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        user_details = {
            'id': user.id,
            'public_key': user.public_key,
            'username': user.username
        }

        if user.id == request.user.id:
            user_details['multifactor_auth_enabled'] = Google_Authenticator.objects.filter(user=user).exists() or Yubikey_OTP.objects.filter(user=user).exists()
            user_details['recovery_code_enabled'] = Recovery_Code.objects.filter(user=user).exists()

        return Response(user_details,
                status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
