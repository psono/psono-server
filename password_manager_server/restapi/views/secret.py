from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Secret
)

from ..app_settings import (
    SecretSerializer, SecretOverviewSerializer,
)
from rest_framework.exceptions import PermissionDenied

from django.db import IntegrityError
from ..authentication import TokenAuthentication


class SecretView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    the secret if the necessary access rights are granted

    Accept the following POST parameters: secret_id (optional)
    Return a list of the secrets or the secret
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = SecretSerializer

    def get(self, request, uuid = None, *args, **kwargs):

        if not uuid:
            try:
                storages = Secret.objects.filter(user=request.user)
            except Secret.DoesNotExist:
                storages = []

            return Response({'secrets': SecretOverviewSerializer(storages, many=True).data},
                status=status.HTTP_200_OK)
        else:
            try:
                secret = Secret.objects.get(pk=uuid)
            except Secret.DoesNotExist:
                raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})
            except ValueError:
                return Response({"error": "IdNoUUID", 'message': "Secret ID is badly formed and no uuid"},
                                status=status.HTTP_400_BAD_REQUEST)

            if not secret.user_id == request.user.pk:
                raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})

            return Response(self.serializer_class(secret).data,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):

        if 'data' not in request.data:
            return Response({"error": "NotInRequest", 'message': "data not in request"},
                                status=status.HTTP_400_BAD_REQUEST)
        if 'data_nonce' not in request.data:
            return Response({"error": "NotInRequest", 'message': "data_nonce not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        try:
            secret = Secret.objects.create(
                data = str(request.data['data']),
                data_nonce = str(request.data['data_nonce']),
                user = request.user
            )
        except IntegrityError:
            return Response({"error": "DuplicateNonce", 'message': "Don't use a nonce twice"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"secret_id": secret.id}, status=status.HTTP_201_CREATED)

    def post(self, request, uuid = None, *args, **kwargs):

        try:
            secret = Secret.objects.get(pk=uuid)
        except Secret.DoesNotExist:
            raise PermissionDenied({"message":"You don't have permission to access or it does not exist."})
        except ValueError:
            return Response({"error": "IdNoUUID", 'message': "Secret ID is badly formed and no uuid"},
                            status=status.HTTP_400_BAD_REQUEST)


        if not secret.user_id == request.user.pk:
            raise PermissionDenied({"message":"You don't have permission to access",
                            "resource_id": secret.id})

        if 'data' in request.data:
            secret.data = str(request.data['data'])
        if 'data_nonce' in request.data:
            secret.data_nonce = str(request.data['data_nonce'])

        secret.save()

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)
