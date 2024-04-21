from django.db import transaction
from django.conf import settings
from django.core.files.base import ContentFile
import base64
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..utils.avatar import get_avatar_storage
from ..utils.avatar import delete_avatar_storage_of_user
from ..permissions import IsAuthenticated
from ..models import (
    Avatar,
)

from ..app_settings import (
    CreateAvatarSerializer,
    DeleteAvatarSerializer,
    ReadAvatarSerializer,
)

from ..authentication import TokenAuthentication

class AvatarView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Returns the avatar of a user

        :param request:
        :type request:
        :param avatar_id:
        :type avatar_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        serializer = ReadAvatarSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        avatars = []
        try:
            avatar = Avatar.objects.only('id').get(user=self.request.user)
            avatars.append({
                'id': str(avatar.id)
            })
        except Avatar.DoesNotExist:
            pass

        return Response({
            'avatars': avatars,
        }, status=status.HTTP_200_OK)


    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


    def post(self, request, *args, **kwargs):
        """
        Creates a new avatar (and potentially deletes any existing ones)

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateAvatarSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        data = serializer.validated_data['data']
        mime_type = serializer.validated_data['mime_type']

        with transaction.atomic():
            Avatar.objects.filter(user_id=request.user.id).delete()
            delete_avatar_storage_of_user(request.user.id)


        storage = get_avatar_storage()
        with transaction.atomic():
            avatar = Avatar.objects.create(
                data=None if storage else data,
                mime_type=mime_type,
                user=request.user,
            )
            if storage:
                storage.save(f"{settings.AVATAR_STORAGE_PREFIX}{request.user.id}/{avatar.id}".lower(), ContentFile(data))

        return Response({"id": str(avatar.id)},
                        status=status.HTTP_201_CREATED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an avatar

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteAvatarSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        avatar = serializer.validated_data.get('avatar')

        with transaction.atomic():
            # delete it
            avatar.delete()
            delete_avatar_storage_of_user(request.user.id)

        return Response({}, status=status.HTTP_200_OK)

