from  more_itertools import unique_everseen

from ..utils import user_has_rights_on_share, is_uuid
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

from django.db import connection
from ..authentication import TokenAuthentication


def create_share_link(link_id, share_id, parent_share_id, parent_datastore_id):
    """
    DB wrapper to create a link between a share and a datastore or another (parent-)share and the correct creation of
    link paths to their children

    Takes care of "degenerated" tree structures (e.g a child has two parents)

    In addition checks if the link already exists, as this is a crucial part of the access rights system

    :param link_id:
    :param share_id:
    :param parent_share_id:
    :param parent_datastore_id:
    :return:
    """

    link_id = str(link_id).replace("-", "")

    # Prevent malicious (or by bad RNGs generated?) link ids
    # Not doing so could cause access rights problems
    if Share_Tree.objects.filter(path__match='*.' + link_id + '.*').count() > 0:
        return False

    cursor = connection.cursor()

    cursor.execute("""INSERT INTO restapi_share_tree (id, create_date, write_date, path, share_id, parent_share_id, parent_datastore_id)
    SELECT
      gen_random_uuid() id,
      now() create_date,
      now() write_date,
      CASE
        WHEN nlevel(one_old_parent.path) = nlevel(t.path) THEN COALESCE(new_parent.path, '') || %(link_id)s
        ELSE coalesce(new_parent.path, '') || %(link_id)s || subltree(t.path, nlevel(one_old_parent.path), nlevel(t.path))
      END path,
      t.share_id,
      CASE
        WHEN nlevel(one_old_parent.path) = nlevel(t.path) THEN new_parent.share_id
        ELSE t.parent_share_id
      END parent_share_id,
      CASE
        WHEN nlevel(one_old_parent.path) = nlevel(t.path) AND new_parent.share_id IS NOT NULL THEN NULL
        WHEN nlevel(one_old_parent.path) != nlevel(t.path) AND t.parent_share_id IS NOT NULL THEN NULL
        WHEN nlevel(one_old_parent.path) = nlevel(t.path) THEN COALESCE(%(parent_datastore_id)s, t.parent_datastore_id) --replace this null with datastore id if specified
        ELSE t.parent_datastore_id
      END parent_datastore_id
    FROM restapi_share_tree t
    JOIN (
      SELECT path
      FROM restapi_share_tree
      WHERE share_id = %(share_id)s
      LIMIT 1
    ) one_old_parent ON t.path <@ one_old_parent.path
    LEFT JOIN restapi_share_tree new_parent
      ON new_parent.share_id = %(parent_share_id)s""", {
        'parent_datastore_id': parent_datastore_id,
        'link_id': link_id,
        'share_id': share_id,
        'parent_share_id': parent_share_id,
    })

    if cursor.rowcount == 0:
        if parent_datastore_id:
            Share_Tree.objects.create(
                share_id=share_id,
                parent_datastore_id=parent_datastore_id,
                path=link_id
            )
        else:
            cursor.execute("""INSERT INTO restapi_share_tree (id, create_date, write_date, path, share_id, parent_share_id, parent_datastore_id)
            SELECT
                gen_random_uuid() id,
                now() create_date,
                now() write_date,
                path || %(link_id)s path,
                %(share_id)s share_id,
                %(parent_share_id)s parent_share_id,
                %(parent_datastore_id)s parent_datastore_id
                FROM restapi_share_tree
                WHERE share_id = %(parent_share_id)s""", {
                'link_id': link_id,
                'parent_share_id': parent_share_id,
                'parent_datastore_id': parent_datastore_id,
                'share_id': share_id,
            })

    return True

def delete_share_link(link_id):
    """
    DB wrapper to delete a link to a share (and all his child shares with the same link)

    :param link_id:
    :return:
    """

    link_id = str(link_id).replace("-", "")

    Share_Tree.objects.filter(path__match='*.'+link_id+'.*').delete()




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

        if 'link_id' not in request.data or not is_uuid(request.data['link_id']):
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

        if 'link_id' not in request.data or not is_uuid(request.data['link_id']):
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

        if 'link_id' not in request.data or not is_uuid(request.data['link_id']):
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

        return Response(status=status.HTTP_200_OK)