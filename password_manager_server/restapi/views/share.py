from ..utils import user_has_rights_on_share, is_uuid, get_all_inherited_rights
from share_tree import create_share_link
from datastore import get_datastore
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..models import (
    Share, User_Share_Right
)

from ..app_settings import (
    CreateShareSerializer
)
from rest_framework.exceptions import PermissionDenied

from django.db import IntegrityError
from ..authentication import TokenAuthentication


class ShareView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    the share if the necessary access rights are granted

    Accept the following POST parameters: share_id (optional)
    Return a list of the shares or the share
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = CreateShareSerializer
    allowed_methods = ('GET', 'PUT', 'POST', 'OPTIONS', 'HEAD')

    def get(self, request, uuid = None, *args, **kwargs):
        """
        Returns a list of all shares with all own share rights on that share or
        returns a share with all rights existing on the share

        :param request:
        :param uuid:
        :param args:
        :param kwargs:
        :return: 200 / 400 / 403
        """
        if not uuid:

            # Generates a list of shares wherever the user has any rights for it and joins the user_share objects

            #TODO optimize query. this way its too inefficient ...

            response = []
            specific_right_share_index = {}
            share_index = {}

            try:
                shares = Share.objects.filter(user_share_rights__user=request.user).distinct()
            except Share.DoesNotExist:
                shares = []


            for s in shares:

                for u in s.user_share_rights.filter(user=request.user):

                    share = {
                        'id': s.id,
                        'share_right_id': u.id,
                        'share_right_user_id': u.user_id,
                        'share_right_title': u.title,
                        'share_right_title_nonce': u.title_nonce,
                        'share_right_key': u.key,
                        'share_right_key_nonce': u.key_nonce,
                        'share_right_key_type': u.key_type,
                        'share_right_read': u.read,
                        'share_right_write': u.write,
                        'share_right_grant': u.grant,
                        'share_right_accepted': u.accepted,
                        'share_right_create_user_id': u.owner.id,
                        'share_right_create_user_username': u.owner.username,
                        'share_right_create_user_public_key': u.owner.public_key}

                    # share.data = str(s.data) if s.data and s.share_right_read and s.share_right_accepted else ''
                    # share.data_nonce =  s.data_nonce if s.data_nonce and s.share_right_read and s.share_right_accepted else ''

                    share_index[s.id] = share
                    specific_right_share_index[s.id] = share


            # TODO get inherited share rights
            inherited_user_share_rights = []


            for s in inherited_user_share_rights:

                # if we already have a specific right for this share, we do not allow inherited rights anymore
                if s.id in specific_right_share_index:
                    continue

                if not s.id in share_index:
                    share_index[s.id] = {
                        'id': s.id,
                        'share_right_id': [],
                        'share_right_user_id': [],
                        'share_right_title': '',
                        'share_right_title_nonce': '',
                        'share_right_key': [],
                        'share_right_key_nonce': [],
                        'share_right_key_type': [],
                        'share_right_read': False,
                        'share_right_write': False,
                        'share_right_grant': False,
                        'share_right_accepted': False,
                        'share_right_create_user_id': [],
                        'share_right_create_user_username': [],
                        'share_right_create_user_public_key': []
                    }

                share_index[s.id]['share_right_id'].append(s.share_right.id)
                share_index[s.id]['share_right_user_id'].append(s.share_right.user_id)
                share_index[s.id]['share_right_key'].append(s.share_right.key)
                share_index[s.id]['share_right_key_nonce'].append(s.share_right.key_nonce)
                share_index[s.id]['share_right_key_type'].append(s.share_right.key_type)
                share_index[s.id]['share_right_read'] = share_index[s.id]['share_right_read'] or  s.share_right.read
                share_index[s.id]['share_right_write'] = share_index[s.id]['share_right_write'] or  s.share_right.write
                share_index[s.id]['share_right_grant'] = share_index[s.id]['share_right_grant'] or  s.share_right.grant
                share_index[s.id]['share_right_accepted'] = share_index[s.id]['share_right_accepted'] or  s.share_right.accepted
                share_index[s.id]['share_right_create_user_id'].append(s.share_right.owner.id)
                share_index[s.id]['share_right_create_user_username'].append(s.share_right.owner.username)
                share_index[s.id]['share_right_create_user_public_key'].append(s.share_right.owner.public_key)

            for share_id, share in share_index.items():
                response.append(share)

            return Response({'shares': response},
                status=status.HTTP_200_OK)

        else:
            # UUID specified
            # Returns the specified share if the user has any rights for it and joins the user_share objects

            try:
                share = Share.objects.get(pk=uuid)
            except ValueError:
                return Response({"error": "IdNoUUID", 'message': "Share ID is badly formed and no uuid"},
                                status=status.HTTP_400_BAD_REQUEST)
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)


            user_share_rights = []
            user_share_rights_inherited = []
            has_read_right = False

            for u in share.user_share_rights.filter(user=request.user):
                user_share_rights.append({
                    'id': u.id,
                    'key': u.key,
                    'key_nonce': u.key_nonce,
                    'key_type': u.key_type,
                    'read': u.read,
                    'write': u.write,
                    'grant': u.grant,
                    'user_id': u.user_id,
                })

                has_read_right = has_read_right or u.read


            if not user_share_rights:
                inherited_rights = get_all_inherited_rights(request.user.id, uuid)
                for u in inherited_rights:
                    user_share_rights_inherited.append({
                        'id': u.id,
                        'key': u.key,
                        'key_nonce': u.key_nonce,
                        'key_type': u.key_type,
                        'read': u.read,
                        'write': u.write,
                        'grant': u.grant,
                        'user_id': u.user_id,
                    })

                    has_read_right = has_read_right or u.read


            if not has_read_right:
                raise PermissionDenied({"message":"You don't have permission to read the share",
                                "resource_id": share.id})

            response = {
                'id': share.id,
                'data': str(share.data) if share.data else '',
                'data_nonce': share.data_nonce if share.data_nonce else '',
                'user_id': share.user_id,
                'user_share_rights': user_share_rights,
                'user_share_rights_inherited': user_share_rights_inherited,
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Creates a new share

        Necessary Rights:
            - write on new_parent_share
            - write on new_parent_datastore

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400 / 403 / 404
        :rtype:
        """

        if 'data' not in request.data:
            return Response({"error": "NotInRequest", 'message': "Data not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        if 'link_id' not in request.data or not is_uuid(request.data['link_id']):
            return Response({"error": "IdNoUUID", 'message': "link ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        parent_share = None
        parent_share_id = None
        if 'parent_share_id' in request.data and request.data['parent_share_id']:
            # check permissions on parent
            if not user_has_rights_on_share(request.user.id, request.data['parent_share_id'], write=True):
                return Response({"message": "You don't have permission to access or it does not exist.",
                                 "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

            try:
                parent_share = Share.objects.get(pk=request.data['parent_share_id'])
                parent_share_id = parent_share.id
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

        parent_datastore = None
        parent_datastore_id = None
        if 'parent_datastore_id' in request.data and request.data['parent_datastore_id']:
            parent_datastore = get_datastore(request.data['parent_datastore_id'], request.user)
            if not parent_datastore:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": request.data['parent_datastore_id']}, status=status.HTTP_403_FORBIDDEN)
            parent_datastore_id = parent_datastore.id

        if not parent_share and not parent_datastore:
            return Response({"message": "Either parent share or parent datastore need to be specified."},
                            status=status.HTTP_404_NOT_FOUND)

        try:
            share = Share.objects.create(
                data = str(request.data['data']),
                data_nonce = str(request.data['data_nonce']),
                user = request.user
            )
        except IntegrityError:
            return Response({"error": "DuplicateNonce", 'message': "Don't use a nonce twice"}, status=status.HTTP_400_BAD_REQUEST)

        User_Share_Right.objects.create(
                owner = request.user,
                user = request.user,
                share = share,
                key = request.data['key'],
                key_nonce = request.data['key_nonce'],
                key_type = request.data['key_type'],
                accepted= True,
                title="",
                title_nonce="",
                read = True,
                write = True,
                grant = True
            )

        if not create_share_link(request.data['link_id'], share.id, parent_share_id, parent_datastore_id):
            return Response({"error": "DuplicateLinkID", 'message': "Don't use a link id twice"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"share_id": share.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a share

        Necessary Rights:
            - write on share

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400 / 403
        :rtype:
        """

        if 'share_id' not in request.data or not is_uuid(request.data['share_id']):
            return Response({"error": "IdNoUUID", 'message': "Share ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        try:
            share = Share.objects.get(pk=request.data['share_id'])
        except ValueError:
            return Response({"error": "IdNoUUID", 'message': "Share ID is badly formed and no uuid"},
                            status=status.HTTP_400_BAD_REQUEST)
        except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check permissions on share
        if not user_has_rights_on_share(request.user.id, request.data['share_id'], write=True):
            return Response({"message": "You don't have permission to access or it does not exist.",
                             "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        if 'data' in request.data:
            share.data = str(request.data['data'])
        if 'data_nonce' in request.data:
            share.data_nonce = str(request.data['data_nonce'])

        share.save()

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


