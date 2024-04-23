from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from django.conf import settings
from rest_framework.permissions import AllowAny
from ..models import (
    Ivalt,
)

from ..app_settings import (
    CreateIvaltSerializer,
    DeleteIvaltSerializer,
)

from django.db import IntegrityError
from ..authentication import TokenAuthentication


class UserIvalt(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    # permission_classes = (AllowAny,)
    allowed_methods = ('GET', 'PUT', 'DELETE')

    def get(self, request, *args, **kwargs):
        """
        Lists all Ivalt mobile numbers

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        if settings.IVALT_SECRET_KEY == '':
            return Response({"error": "IvaltSecretKey", 'message': "The Ivalt secret key is not "
                                                                   "available"},
                            status=status.HTTP_400_BAD_REQUEST)

        ivalt = []

        for ivalt_obj in Ivalt.objects.filter(user=request.user).all():
            ivalt.append({
                'id': ivalt_obj.id,
                'active': ivalt_obj.active,
                'mobile': ivalt_obj.mobile,
                'secret': settings.IVALT_SECRET_KEY,
            })

        return Response({
            "ivalt": ivalt
        },
            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        sets a new ivalt 2fa

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateIvaltSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        new_ivalt = Ivalt.objects.create(
            user=request.user,
            mobile=serializer.validated_data.get('mobile'),
            active=True
        )

        request.user.ivalt_enabled = True
        request.user.save()

        return Response({
            "id": new_ivalt.id
        },
            status=status.HTTP_201_CREATED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an Datastore

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400 / 403
        """

        serializer = DeleteIvaltSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        ivalt = serializer.validated_data.get('ivalt')

        request.user.ivalt_enabled = False
        request.user.save()
        # delete it
        ivalt.delete()

        return Response({}, status=status.HTTP_200_OK)
