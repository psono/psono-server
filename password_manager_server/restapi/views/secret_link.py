from  more_itertools import unique_everseen

from ..utils import user_has_rights_on_share, request_misses_uuid
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated


from ..models import (
    Share, Data_Store, Secret_Link
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
        :return: 200 / 403 / 404
        """

        if request_misses_uuid(request, 'link_id'):
            return Response({"error": "IdNoUUID", 'message': "Link ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        if request_misses_uuid(request, 'new_parent_share_id') and request_misses_uuid(request, 'new_parent_datastore_id'):
            return Response(
                {"error": "NotInRequest", 'message': "No parent (share or datastore) has been provided as parent"},
                status=status.HTTP_400_BAD_REQUEST)

        secrets = []
        old_parents = []
        old_datastores = []

        for s in Secret_Link.objects.filter(link_id=request.data['link_id']).all():
            secrets.append(s.secret_id)
            if s.parent_share_id:
                old_parents.append(s.parent_share_id)
            if s.parent_datastore_id:
                old_datastores.append(s.parent_datastore_id)

        # remove duplicates
        secrets = list(unique_everseen(secrets))
        old_parents = list(unique_everseen(old_parents))
        old_datastores = list(unique_everseen(old_datastores))

        if not secrets and not old_parents and not old_datastores:
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['link_id']}, status=status.HTTP_403_FORBIDDEN)

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
        delete_secret_link(request.data['link_id'])

        for secret_id in secrets:
            create_secret_link(request.data['link_id'], secret_id, new_parent_share_id, new_parent_datastore_id)

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
        :return: 200 / 400/ 403
        """

        if request_misses_uuid(request, 'link_id'):
            return Response({"error": "IdNoUUID", 'message': "Link ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        secrets = []
        parent_shares = []
        parent_datastores = []

        for s in Secret_Link.objects.filter(link_id=request.data['link_id']).all():
            secrets.append(s.secret_id)
            if s.parent_share_id:
                parent_shares.append(s.parent_share_id)
            if s.parent_datastore_id:
                parent_datastores.append(s.parent_datastore_id)

        # remove duplicates
        secrets = list(unique_everseen(secrets))
        parent_shares = list(unique_everseen(parent_shares))
        parent_datastores = list(unique_everseen(parent_datastores))


        if not secrets and not parent_shares and not parent_datastores:
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['link_id']}, status=status.HTTP_403_FORBIDDEN)

        # check write permissions on parent_shares
        for parent_share_id in parent_shares:
            if not user_has_rights_on_share(request.user.id, parent_share_id, write=True):
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": parent_share_id}, status=status.HTTP_403_FORBIDDEN)

        # check write permissions on parent_datastores
        for datastore_id in parent_datastores:
            try:
                Data_Store.objects.get(pk=datastore_id, user=request.user)
            except Data_Store.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": datastore_id}, status=status.HTTP_403_FORBIDDEN)

        delete_secret_link(request.data['link_id'])

        return Response(status=status.HTTP_200_OK)