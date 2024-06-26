from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from django.conf import settings
from ..utils import encrypt_with_db_secret, decrypt_with_db_secret
from ..models import (
    Ivalt,
)

from ..app_settings import (
    CreateIvaltSerializer,
    ActivateIvaltSerializer,
    DeleteIvaltSerializer,
)

from django.db import IntegrityError
from ..authentication import TokenAuthentication


class UserIvalt(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE')

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

        ivalt = []
        for ivalt_obj in Ivalt.objects.filter(user=request.user).all():
            ivalt.append({
                'id': ivalt_obj.id,
                'active': ivalt_obj.active,
                'mobile': decrypt_with_db_secret(ivalt_obj.mobile),
            })

        return Response({
            "ivalt": ivalt
        },
            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        sets a new ivalt 2FA

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
            if isinstance(serializer.errors, dict):
                errors = {key: value[0] for key, value in serializer.errors.items()}
            else:
                errors = serializer.errors
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        new_ivalt = Ivalt.objects.create(
            user=request.user,
            mobile=encrypt_with_db_secret(serializer.validated_data.get('mobile')),
            active=False
        )
       
        return Response({'message': 'BIOMETRIC_AUTH_REQUEST_SUCCESSFULLY_SENT', 'id': new_ivalt.id}, status=status.HTTP_201_CREATED)
            

    def post(self, request, *args, **kwargs):
        """
        sets a new ivalt 2FA

        :param request:
        :type request:
        :param args:
        :type args:
        :return: 201 / 400
        :rtype:
        """
        serializer = ActivateIvaltSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            if isinstance(serializer.errors, dict):
                errors = {key: value[0] for key, value in serializer.errors.items()}
            else:
                errors = serializer.errors
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        ivalt = serializer.validated_data.get('ivalt')
        request.user.ivalt_enabled = True
        request.user.save()
        ivalt.active = True
        ivalt.save()
        return Response({'message': 'BIOMETRIC_AUTHENTICATION_SUCCESSFULLY_DONE'}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an Ivalt 2FA

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
