from  more_itertools import unique_everseen

from ..utils import user_has_rights_on_share, request_misses_uuid, create_share_link, delete_share_link
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated


from ..models import (
    Share, Share_Tree, Data_Store
)

from ..app_settings import (
    ShareTreeSerializer
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
    serializer_class = ShareTreeSerializer
    allowed_methods = ('PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')


    def put(self, request, *args, **kwargs):
        """
        Insert Share_Tree obj

        Necessary Rights:
            - grant on share
            - write on parent_share

        :param request:
        :param args:
        :param kwargs:
        :return: 201 / 400 / 403
        """

        # TODO Refactor to use serializer

        if request_misses_uuid(request, 'link_id'):
            return Response({"error": "IdNoUUID", 'message': "Share Right ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        # check if share exists
        try:
            share = Share.objects.get(pk=request.data['share_id'])
        except Share.DoesNotExist:
            return Response({"message":"You don't have permission to access or it does not exist.",
                             "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check if parent_share exists
        parent_share_id = None
        if 'parent_share_id' in request.data and request.data['parent_share_id']:
            try:
                parent_share = Share.objects.get(pk=request.data['parent_share_id'])
                parent_share_id = parent_share.id
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                 "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check if datastore exists
        parent_datastore_id = None
        if 'parent_datastore_id' in request.data and request.data['parent_datastore_id']:
            try:
                datastore = Data_Store.objects.get(pk=request.data['parent_datastore_id'], user=request.user)
                parent_datastore_id = datastore.id
            except Data_Store.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                 "resource_id": request.data['parent_datastore_id']}, status=status.HTTP_403_FORBIDDEN)

        # check permissions on share
        if not user_has_rights_on_share(request.user.id, request.data['share_id'], grant=True):
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check permissions on parent
        if parent_share_id and not user_has_rights_on_share(request.user.id, parent_share_id, write=True):
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": parent_share_id}, status=status.HTTP_403_FORBIDDEN)


        if not create_share_link(request.data['link_id'], share.id, parent_share_id, parent_datastore_id):
            return Response({"message":"Link id already exists.",
                            "resource_id": request.data['link_id']}, status=status.HTTP_403_FORBIDDEN)


        log_info(logger=logger, request=request, status='HTTP_200_OK', event='CREATE_SHARE_LINK_SUCCESS', request_resource=request.data['link_id'])

        return Response(status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Move Share_Tree obj

        Necessary Rights:
            - grant on share
            - write on old_parent_share
            - write on old_datastore
            - write on new_parent_share
            - write on new_datastore

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 403 / 404
        """

        # TODO Refactor to use serializer

        if request_misses_uuid(request, 'link_id'):
            return Response({"error": "IdNoUUID", 'message': "Share Right ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        link_id = str(request.data['link_id']).replace("-", "")

        shares = []
        old_parents = []
        old_datastores = []

        for s in Share_Tree.objects.filter(path__match='*.' + link_id).all():
            shares.append(s.share_id)
            if s.parent_share_id:
                old_parents.append(s.parent_share_id)
            if s.parent_datastore_id:
                old_datastores.append(s.parent_datastore_id)

        # remove duplicates
        shares = list(unique_everseen(shares))
        old_parents = list(unique_everseen(old_parents))
        old_datastores = list(unique_everseen(old_datastores))

        if not shares and not old_parents and not old_datastores:
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['link_id']}, status=status.HTTP_403_FORBIDDEN)


        # check grant permissions on share
        for share_id in shares:
            if not user_has_rights_on_share(request.user.id, share_id, grant=True):
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": share_id}, status=status.HTTP_403_FORBIDDEN)

        # check write permissions on old_parents
        for old_parent_share_id in old_parents:
            if not user_has_rights_on_share(request.user.id, old_parent_share_id, write=True):
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": old_parent_share_id}, status=status.HTTP_403_FORBIDDEN)

        # check write permissions on old_datastores
        for old_datastore_id in old_datastores:
            try:
                Data_Store.objects.get(pk=old_datastore_id, user=request.user)
            except Data_Store.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": old_datastore_id}, status=status.HTTP_403_FORBIDDEN)

        # check if new_parent_share exists
        new_parent_share_id = None
        if 'new_parent_share_id' in request.data and request.data['new_parent_share_id']:
            try:
                parent_share = Share.objects.get(pk=request.data['new_parent_share_id'])
                new_parent_share_id = parent_share.id
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                 "resource_id": request.data['new_parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check if new_datastore exists
        new_parent_datastore_id = None
        if 'new_parent_datastore_id' in request.data and request.data['new_parent_datastore_id']:
            try:
                datastore = Data_Store.objects.get(pk=request.data['new_parent_datastore_id'], user=request.user)
                new_parent_datastore_id = datastore.id
            except Data_Store.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                 "resource_id": request.data['new_parent_datastore_id']}, status=status.HTTP_403_FORBIDDEN)

        # check permissions on new_parent_share
        if new_parent_share_id and not user_has_rights_on_share(request.user.id, new_parent_share_id, write=True):
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": new_parent_share_id}, status=status.HTTP_403_FORBIDDEN)

        # all checks passed, lets move the link with a delete and create at the new location
        delete_share_link(request.data['link_id'])

        for share_id in shares:
            create_share_link(request.data['link_id'], share_id, new_parent_share_id, new_parent_datastore_id)

        log_info(logger=logger, request=request, status='HTTP_200_OK', event='MOVE_SHARE_LINK_SUCCESS', request_resource=request.data['link_id'])

        return Response(status=status.HTTP_200_OK)



    def delete(self, request, *args, **kwargs):
        """
        Delete Share_Tree obj

        Necessary Rights:
            - write on parent_share
            - write on datastore

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400/ 403
        """

        # TODO Refactor to use serializer

        if request_misses_uuid(request, 'link_id'):
            return Response({"error": "IdNoUUID", 'message': "Link ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)


        link_id = str(request.data['link_id']).replace("-", "")

        shares = []
        parents = []
        datastores = []

        for s in Share_Tree.objects.filter(path__match='*.' + link_id).all():
            shares.append(s.share_id)
            if s.parent_share_id:
                parents.append(s.parent_share_id)
            if s.parent_datastore_id:
                datastores.append(s.parent_datastore_id)

        # remove duplicates
        shares = list(unique_everseen(shares))
        parents = list(unique_everseen(parents))
        datastores = list(unique_everseen(datastores))


        if not shares and not parents and not datastores:
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['link_id']}, status=status.HTTP_403_FORBIDDEN)

        # check write permissions on parents
        for parent_share_id in parents:
            if not user_has_rights_on_share(request.user.id, parent_share_id, write=True):
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": parent_share_id}, status=status.HTTP_403_FORBIDDEN)

        # check write permissions on datastores
        for datastore_id in datastores:
            try:
                Data_Store.objects.get(pk=datastore_id, user=request.user)
            except Data_Store.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": datastore_id}, status=status.HTTP_403_FORBIDDEN)

        delete_share_link(request.data['link_id'])

        log_info(logger=logger, request=request, status='HTTP_200_OK', event='DELETE_SHARE_LINK_SUCCESS', request_resource=request.data['link_id'])

        return Response(status=status.HTTP_200_OK)