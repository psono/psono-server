from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..app_settings import (
    MoveSecretLinkSerializer,
    DeleteSecretLinkSerializer,
)

from ..models import (
    Secret_Link
)

from ..authentication import TokenAuthentication

def create_secret_link(link_id, secret_id, parent_share_id, parent_datastore_id):
    """
    DB wrapper to create a link between a secret and a datastore or a share

    Takes care of "degenerated" tree structures (e.g a child has two parents)

    In addition checks if the link already exists, as this is a crucial part of the access rights system

    :param link_id:
    :param secret_id:
    :param parent_share_id:
    :param parent_datastore_id:
    :return:
    """

    try:
        Secret_Link.objects.create(
            link_id = link_id,
            secret_id = secret_id,
            parent_datastore_id = parent_datastore_id,
            parent_share_id = parent_share_id
        )
    except:
        return False

    return True

def delete_secret_link(link_id):
    """
    DB wrapper to delete a link to a secret

    :param link_id:
    :return:
    """

    Secret_Link.objects.filter(link_id=link_id).delete()



class SecretLinkView(GenericAPIView):
    """
    Secret Link View:

    Accepted Methods: POST, DELETE
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'DELETE', 'OPTIONS', 'HEAD')

    def post(self, request, *args, **kwargs):
        """
        Move Secret_Link obj

        Necessary Rights:
            - write on old_parent_share
            - write on old_datastore
            - write on new_parent_share
            - write on new_datastore

        :param request:
        :param uuid:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = MoveSecretLinkSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        link_id = serializer.validated_data['link_id']
        new_parent_share_id = serializer.validated_data['new_parent_share_id']
        new_parent_datastore_id = serializer.validated_data['new_parent_datastore_id']
        secrets = serializer.validated_data['secrets']

        # all checks passed, lets move the link with a delete and create at the new location
        delete_secret_link(link_id)

        for secret_id in secrets:
            create_secret_link(link_id, secret_id, new_parent_share_id, new_parent_datastore_id)

        return Response(status=status.HTTP_200_OK)



    def delete(self, request, *args, **kwargs):
        """
        Delete Secret_Link obj

        Necessary Rights:
            - write on parent_share
            - write on parent_datastore

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteSecretLinkSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        link_id = serializer.validated_data['link_id']

        delete_secret_link(link_id)

        return Response(status=status.HTTP_200_OK)