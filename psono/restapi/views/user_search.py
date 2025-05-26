from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from ..permissions import IsAuthenticated
from ..models import (
    Recovery_Code
)

from ..app_settings import (
    UserSearchSerializer
)


from ..authentication import TokenAuthentication


class UserSearch(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return UserSearchSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Check the REST Token and returns the user's public key. To identify the user either the email or the user_id needs
        to be provided

        Return the user's public key
        """

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        users = serializer.validated_data.get('users')

        result = []
        for user in users:
            user_details = {
                'id': user.id,
                'public_key': user.public_key,
                'username': user.username,
                'avatar_id': user.avatar_id,
            }

            if user.id == request.user.id:
                user_details['multifactor_auth_enabled'] = user.any_2fa_active()
                user_details['recovery_code_enabled'] = Recovery_Code.objects.filter(user=user).exists()

            result.append(user_details)

        if len(result) == 1:
            search_result = result[0]
        else:
            search_result = result
        return Response(search_result, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
