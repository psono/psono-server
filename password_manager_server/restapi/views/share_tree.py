from ..utils import user_has_rights_on_share, is_uuid
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from django.db.models import Q

from ..models import (
    Share, User_Share_Right, User, Share_Tree, Data_Store
)

from ..app_settings import (
    UserShareRightSerializer,
    CreateShareSerializer,
    ShareTreeSerializer
)
from rest_framework.exceptions import PermissionDenied

from django.db import connection
from ..authentication import TokenAuthentication

def create_link(link_id, parent_share_id, share_id, datastore_id):

    link_id = str(link_id).replace("-", "")

    # print("create_link with link_id:", link_id, 'parent_share_id:', parent_share_id, 'share_id:', share_id, 'datastore_id:', datastore_id)
    #
    # print("before A")
    # trees = Share_Tree.objects.all()
    # print("t.path, t.share_id, t.parent_share_id, t.datastore_id")
    # for t in trees:
    #     print(t.path, t.share_id, t.parent_share_id, t.datastore_id)

    cursor = connection.cursor()
    cursor.execute("""INSERT INTO restapi_share_tree (id, create_date, write_date, path, share_id, parent_share_id, datastore_id)
    SELECT
      uuid_generate_v4() id,
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
        WHEN nlevel(one_old_parent.path) = nlevel(t.path) THEN COALESCE(%(datastore_id)s, t.datastore_id) --replace this null with datastore id if specified
        ELSE t.datastore_id
      END datastore_id
    FROM restapi_share_tree t
    JOIN (
      SELECT path
      FROM restapi_share_tree
      WHERE share_id = %(share_id)s
      LIMIT 1
    ) one_old_parent ON t.path <@ one_old_parent.path
    LEFT JOIN restapi_share_tree new_parent
      ON new_parent.share_id = %(parent_share_id)s""", {
        'datastore_id': datastore_id,
        'link_id': link_id,
        'share_id': share_id,
        'parent_share_id': parent_share_id,
    })

    # print("after A")
    # trees = Share_Tree.objects.all()
    # print("t.path, t.share_id, t.parent_share_id, t.datastore_id")
    # for t in trees:
    #     print(t.path, t.share_id, t.parent_share_id, t.datastore_id)

    # print(cursor.rowcount)

    if cursor.rowcount == 0:
        if datastore_id:
            Share_Tree.objects.create(
                share_id=share_id,
                datastore_id=datastore_id,
                path=link_id
            )

        else:
            cursor.execute("""INSERT INTO restapi_share_tree (id, create_date, write_date, path, share_id, parent_share_id, datastore_id)
            SELECT
                uuid_generate_v4() id,
                now() create_date,
                now() write_date,
                path || %(link_id)s path,
                %(share_id)s share_id,
                %(parent_share_id)s parent_share_id,
                %(datastore_id)s datastore_id
                FROM restapi_share_tree
                WHERE share_id = %(parent_share_id)s""", {
                'link_id': link_id,
                'parent_share_id': parent_share_id,
                'datastore_id': datastore_id,
                'share_id': share_id,
            })

def delete_link(link_id):

    link_id = str(link_id).replace("-", "")

    Share_Tree.objects.filter(path__match='*.'+link_id+'.*').delete()


class ShareTreeView(GenericAPIView):

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
            return Response({"error": "IdNoUUID", 'message': "link ID not in request"},
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
        datastore_id = None
        if 'datastore_id' in request.data and request.data['datastore_id']:
            try:
                datastore = Data_Store.objects.get(pk=request.data['datastore_id'], user=request.user)
                datastore_id = datastore.id
            except Data_Store.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                 "resource_id": request.data['datastore_id']}, status=status.HTTP_403_FORBIDDEN)

        # check permissions on share
        if not user_has_rights_on_share(request.user.id, request.data['share_id'], grant=True):
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check permissions on parent
        if parent_share_id and not user_has_rights_on_share(request.user.id, parent_share_id, write=True):
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": parent_share_id}, status=status.HTTP_403_FORBIDDEN)


        create_link(request.data['link_id'], parent_share_id, share.id, datastore_id)

        return Response(status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Update Share_Tree obj

        Necessary Rights:
            - grant on share
            - write on old_parent_share
            - write on new_parent_share

        :param request:
        :param args:
        :param kwargs:
        :return: 201 / 403 / 404
        """

        if 'link_id' not in request.data or not is_uuid(request.data['link_id']):
            return Response({"error": "IdNoUUID", 'message': "link ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        # check if share exists
        try:
            share = Share.objects.get(pk=request.data['share_id'])
        except Share.DoesNotExist:
            return Response({"message":"You don't have permission to access or it does not exist.",
                             "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check if old_parent_share exists
        old_parent_share = None
        if 'old_parent_share_id' in request.data and request.data['old_parent_share_id']:
            try:
                old_parent_share = Share.objects.get(pk=request.data['old_parent_share_id'])
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                 "resource_id": request.data['old_parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check if new_parent_share exists
        new_parent_share = None
        if 'new_parent_share_id' in request.data and request.data['new_parent_share_id']:
            try:
                new_parent_share = Share.objects.get(pk=request.data['new_parent_share_id'])
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                 "resource_id": request.data['new_parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        if not old_parent_share and not new_parent_share:
            return Response({"message": "You don't have permission to access or it does not exist."}, status=status.HTTP_403_FORBIDDEN)

        # check grant permissions on share
        if not user_has_rights_on_share(request.user.id, request.data['share_id'], grant=True):
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check write permissions on old_parent
        if old_parent_share:
            if not user_has_rights_on_share(request.user.id, request.data['old_parent_share_id'], write=True):
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": request.data['old_parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check write permissions on new_parent
        if new_parent_share:
            if not user_has_rights_on_share(request.user.id, request.data['new_parent_share_id'], write=True):
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": request.data['new_parent_share_id']}, status=status.HTTP_403_FORBIDDEN)



        # TODO update Share_Tree obj

        # handle the move of the share
        if old_parent_share and new_parent_share:
            # its a move from an old parent to a new parent
            Share_Tree.objects\
                .filter(
                    share_id=request.data['share_id'],
                    parent_share_id=request.data['old_parent_share_id'],
                    path__match='*'+request.data['link_id'].replace("-", "")+'*'
                    )\
                .update(parent_share_id=request.data['new_parent_share_id'])
        elif old_parent_share:
            # its a move from an old parent to a datastore
            Share_Tree.objects\
                .filter(
                    share_id=request.data['share_id'],
                    parent_share_id=request.data['old_parent_share_id']
                    )\
                .delete()
        else:
            pass
            # its a move from a datastore to a parent
            # TODO create_link(request.data['link_id'], new_parent_share.id, share.id)


        # move all children of the share


        share_trees = Share_Tree.objects.filter(path__match='*.Astronomy.*')

        return Response(status=status.HTTP_200_OK)



    def delete(self, request, *args, **kwargs):
        """
        Delete Share_Tree obj

        Necessary Rights:
            - grant on share
            - write on parent_share

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 403
        """

        # check grant permissions on share
        if not user_has_rights_on_share(request.user.id, request.data['share_id'], grant=True):
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check write permissions on parent
        if not user_has_rights_on_share(request.user.id, request.data['parent_share_id'], write=True):
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        # TODO DELETE

        return Response(status=status.HTTP_200_OK)