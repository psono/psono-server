from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from django.db import IntegrityError
from ..permissions import IsAuthenticated
from ..utils import encrypt_with_db_secret
from ..models import (
    Secret,
    Secret_Link,
)

from ..app_settings import (
    BulkCreateSecretSerializer,
)

from ..authentication import TokenAuthentication

class BulkSecretView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('PUT', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Creates multiple secrets and the corresponding links in the datastore or share

        Necessary Rights:
            - write on parent_share
            - write on parent_datastore

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = BulkCreateSecretSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        new_secrets = []
        for s in serializer.validated_data['secrets']:
            callback_pass = encrypt_with_db_secret(s['callback_pass'])

            new_secrets.append(Secret(
                data=s['data'].encode(),
                data_nonce=s['data_nonce'],
                callback_url=s['callback_url'],
                callback_user=s['callback_user'],
                callback_pass=callback_pass,
                user=request.user
            ))

        try:
            db_secret_objects = Secret.objects.bulk_create(new_secrets)
        except IntegrityError:
            return Response({"error": "DuplicateNonce", 'message': "Don't use a nonce twice"}, status=status.HTTP_400_BAD_REQUEST)

        new_secret_links = []
        for index, db_secret_object in enumerate(db_secret_objects):
            new_secret_links.append(Secret_Link(
                link_id=serializer.validated_data['secrets'][index]['link_id'],
                secret_id=db_secret_object.id,
                parent_datastore_id=serializer.validated_data['parent_datastore_id'],
                parent_share_id=serializer.validated_data['parent_share_id']
            ))

        try:
            Secret_Link.objects.bulk_create(new_secret_links)
        except IntegrityError:
            return Response({"error": "DuplicateLinkID", 'message': "Don't use a link id twice"}, status=status.HTTP_400_BAD_REQUEST)

        created_secrets = [{'link_id': l.link_id, 'secret_id': l.secret_id, } for l in new_secret_links]

        return Response({"secrets": created_secrets}, status=status.HTTP_201_CREATED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
