from ..utils import create_share_link, delete_share_link
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated


from ..app_settings import (
    CreateShareLinkSerializer,
    UpdateShareLinkSerializer,
    DeleteShareLinkSerializer,
)

from ..authentication import TokenAuthentication

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)


class ShareLinkView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    own share right if the necessary access rights are granted
    and the user is the user of the share right

    Accept the following GET parameters: share_id (optional)
    Return a list of the shares or the share and the access rights or a message for an update of rights
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')


    def put(self, request, *args, **kwargs):
        """
        Insert share link in share tree

        Necessary Rights:
            - grant on share
            - write on parent_share

        :param request:
        :param args:
        :param kwargs:
        :return: 201 / 400
        """

        serializer = CreateShareLinkSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='CREATE_SHARE_LINK_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        link_id = serializer.validated_data.get('link_id')
        share_id = serializer.validated_data.get('share_id')
        parent_share_id = serializer.validated_data.get('parent_share_id')
        parent_datastore_id = serializer.validated_data.get('parent_datastore_id')

        if not create_share_link(link_id, share_id, parent_share_id, parent_datastore_id):
            return Response({"message":"Link id already exists.",
                            "resource_id": request.data['link_id']}, status=status.HTTP_400_BAD_REQUEST)


        log_info(logger=logger, request=request, status='HTTP_200_OK', event='CREATE_SHARE_LINK_SUCCESS', request_resource=request.data['link_id'])

        return Response(status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Update share link in share tree

        Necessary Rights:
            - grant on share
            - write on old_parent_share
            - write on old_datastore
            - write on new_parent_share
            - write on new_datastore

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = UpdateShareLinkSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='UPDATE_SHARE_LINK_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        shares = serializer.validated_data.get('shares')
        new_parent_share_id = serializer.validated_data.get('new_parent_share_id')
        new_parent_datastore_id = serializer.validated_data.get('new_parent_datastore_id')

        # all checks passed, lets move the link with a delete and create at the new location
        delete_share_link(request.data['link_id'])

        for share_id in shares:
            create_share_link(request.data['link_id'], share_id, new_parent_share_id, new_parent_datastore_id)

        log_info(logger=logger, request=request, status='HTTP_200_OK', event='UPDATE_SHARE_LINK_SUCCESS', request_resource=request.data['link_id'])

        return Response(status=status.HTTP_200_OK)



    def delete(self, request, *args, **kwargs):
        """
        Delete share link in share tree

        Necessary Rights:
            - write on parent_share
            - write on datastore

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteShareLinkSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='DELETE_SHARE_LINK_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        delete_share_link(request.data['link_id'])

        log_info(logger=logger, request=request, status='HTTP_200_OK', event='DELETE_SHARE_LINK_SUCCESS', request_resource=request.data['link_id'])

        return Response(status=status.HTTP_200_OK)