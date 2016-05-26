from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from django.db.models import Q

from ..models import (
    Share, User_Share_Right, User, User_Share_Right_Inherit
)

from ..app_settings import (
    UserShareRightSerializer,
    CreateShareSerializer,
    UserShareRightInheritSerializer
)
from rest_framework.exceptions import PermissionDenied

from django.db import IntegrityError
from ..authentication import TokenAuthentication


class ShareRightView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    own share right if the necessary access rights are granted
    and the user is the user of the share right

    Accept the following GET parameters: share_id (optional)
    Return a list of the shares or the share and the access rights or a message for an update of rights
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = UserShareRightSerializer

    def get(self, request, uuid = None, *args, **kwargs):
        if not uuid:

            # Generate a list of a all share rights

            try:
                share_rights = User_Share_Right.objects.filter(Q(user=request.user)).distinct()
            except User_Share_Right.DoesNotExist:
                share_rights = []

            share_right_response = []

            for share_right in share_rights:
                share_right_response.append({
                    'id': share_right.id,
                    'title': share_right.title,
                    'key': share_right.key,
                    'key_nonce': share_right.key_nonce,
                    'read': share_right.read,
                    'write': share_right.write,
                    'grant': share_right.grant,
                    'share_id': share_right.share_id
                })

            try:
                share_rights_inherited = User_Share_Right_Inherit.objects.filter(Q(share_right__user=request.user)).distinct()
            except User_Share_Right_Inherit.DoesNotExist:
                share_rights_inherited = []

            for share_right in share_rights_inherited:
                share_right_response.append({
                    'id': share_right.id,
                    'title': share_right.share_right.title,
                    'key': share_right.share_right.key,
                    'key_nonce': share_right.share_right.key_nonce,
                    'read': share_right.share_right.read,
                    'write': share_right.share_right.write,
                    'grant': share_right.share_right.grant,
                    'share_id': share_right.share_right.share_id,
                    'parent_share_right_id': share_right.share_right_id
                })

            response = {
                'share_rights': share_right_response
            }

            return Response(response,
                status=status.HTTP_200_OK)

        else:
            # TODO update according to inherit share rights

            # Returns the specified share right if the user is the user

            try:
                share_right = User_Share_Right.objects.get(pk=uuid)
                if share_right.owner_id != request.user.id and share_right.user_id != request.user.id:
                    return Response({"message":"You don't have permission to access or it does not exist.",
                                    "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)
            except User_Share_Right.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

            response = {
                'id': share_right.id,
                'title': share_right.title,
                'key': share_right.key,
                'key_nonce': share_right.key_nonce,
                'read': share_right.read,
                'write': share_right.write,
                'grant': share_right.grant,
                'share_id': share_right.share_id
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):

        # Modifies rights of a share right

        try:
            User_Share_Right.objects.get(share_id=request.data['share_id'], user=request.user, grant=True)

            # Maybe adjust this later so "owners" cannot lose the rights on their shares

        except User_Share_Right.DoesNotExist:
            try:
                User_Share_Right_Inherit.objects.get(share_id=request.data['share_id'], share_right__user=request.user, share_right__grant=True)

            except User_Share_Right_Inherit.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        try:
            user = User.objects.get(pk=str(request.data['user_id']) )
        except User.DoesNotExist:
            return Response({"message":"Target user does not exist.",
                            "resource_id": str(request.data['user_id'])}, status=status.HTTP_404_NOT_FOUND)

        try:
            user_share_right_obj = User_Share_Right.objects.get(share_id=request.data['share_id'],
                                                                user_id=str(request.data['user_id']))
            user_share_right_obj.owner = request.user
            user_share_right_obj.read = request.data['read']
            user_share_right_obj.write = request.data['write']
            user_share_right_obj.grant = request.data['grant']
            user_share_right_obj.save()

            return Response({"share_right_id": str(user_share_right_obj.id)},
                            status=status.HTTP_201_CREATED)


        except User_Share_Right.DoesNotExist:
            user_share_right_obj2 = User_Share_Right.objects.create(
                key=str(request.data['key']),
                key_nonce=str(request.data['key_nonce']),
                title=str(request.data['title']),
                share_id=request.data['share_id'],
                owner=request.user,
                user=user,
                read=request.data['read'],
                write=request.data['write'],
                grant=request.data['grant'],
            )

        return Response({"share_right_id": str(user_share_right_obj2.id)},
            status=status.HTTP_201_CREATED)



    def delete(self, request, uuid, *args, **kwargs):

        if not uuid:
            return Response({"message": "UUID for share_right not specified."}, status=status.HTTP_404_NOT_FOUND)

        # check if share_right exists
        try:
            share_right = User_Share_Right.objects.get(pk=uuid)
        except User_Share_Right.DoesNotExist:
            return Response({"message": "You don't have permission to access or it does not exist.",
                         "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        # check if user has the rights
        try:
            User_Share_Right.objects.get(share_id=share_right.share_id, user=request.user, grant=True)
        except User_Share_Right.DoesNotExist:
            try:
                test1 = User_Share_Right_Inherit.objects.get(share_id=share_right.share_id)
                test2 = User_Share_Right_Inherit.objects.get(share_right__user=request.user)
                test3 = User_Share_Right_Inherit.objects.get(share_right__grant=True)
                User_Share_Right_Inherit.objects.get(share_id=share_right.share_id, share_right__user=request.user, share_right__grant=True)
            except User_Share_Right_Inherit.DoesNotExist:
                return Response({"message": "You don't have permission to access or it does not exist.",
                                 "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        # delete it
        share_right.delete()

        return Response(status=status.HTTP_200_OK)


class ShareRightInheritView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    own share right if the necessary access rights are granted
    and the user is the user of the share right

    Accept the following GET parameters: share_id (optional)
    Return a list of the shares or the share and the access rights or a message for an update of rights
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = UserShareRightInheritSerializer

    def put(self, request, *args, **kwargs):

        # creates the inherited rights of a share right

        try:
            #first lets try explicit rights
            user_share_right = User_Share_Right.objects.get(share_id=request.data['share_id'], user=request.user)

            if not user_share_right.grant == False:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        except User_Share_Right.DoesNotExist:
            # maybe he has inherited rights
            try:
                user_share_right_inherit = User_Share_Right_Inherit.objects.get(share_id=request.data['share_id'], share_right__user=request.user)

                if not user_share_right_inherit.share_right.grant == False:
                    return Response({"message":"You don't have permission to access or it does not exist.",
                                     "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

            except User_Share_Right_Inherit.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        try:
            User_Share_Right.objects.get(pk=str(request.data['share_right_id']) )
        except User_Share_Right.DoesNotExist:
            return Response({"message":"Target share_right does not exist.",
                            "resource_id": str(request.data['share_right_id'])}, status=status.HTTP_404_NOT_FOUND)

        try:
            User_Share_Right_Inherit.objects.create(
                share_id=request.data['share_id'],
                share_right=request.data['share_right_id'],
            )

        except IntegrityError:
            pass

        return Response(status=status.HTTP_201_CREATED)



    def delete(self, request, uuid, *args, **kwargs):

        if not uuid:
            return Response({"message": "UUID for share_right_inherit not specified."}, status=status.HTTP_404_NOT_FOUND)

        # check if share_right exists
        try:
            share_right = User_Share_Right_Inherit.objects.get(pk=uuid)
        except User_Share_Right_Inherit.DoesNotExist:
            return Response({"message": "You don't have permission to access or it does not exist.",
                         "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        # check if user has the rights
        try:
            user_share_right = User_Share_Right.objects.get(share_id=share_right.share_id, user=request.user)

            if not user_share_right.grant == False:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        except User_Share_Right.DoesNotExist:
            # maybe he has inherited rights
            try:
                user_share_right_inherit = User_Share_Right_Inherit.objects.get(share_id=share_right.share_id, user=request.user)
                if not user_share_right_inherit.share_right.grant == False:
                    return Response({"message":"You don't have permission to access or it does not exist.",
                                     "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)
            except User_Share_Right_Inherit.DoesNotExist:
                return Response({"message": "You don't have permission to access or it does not exist.",
                                 "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)


        # delete it
        share_right.delete()

        return Response(status=status.HTTP_200_OK)


class ShareRightAcceptView(GenericAPIView):

    """
    Check the REST Token and the object permissions and updates the share right as accepted with new symmetric
    encryption key and nonce
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    def post(self, request, uuid = None, *args, **kwargs):

        # Accepts or declines a share right

        if not uuid:
            return Response({"message": "UUID for share not specified."}, status=status.HTTP_404_NOT_FOUND)

        try:
            user_share_right_obj = User_Share_Right.objects.get(id=uuid, user=request.user, accepted=None)

            user_share_right_obj.accepted = True
            user_share_right_obj.title = ''
            user_share_right_obj.key_type = 'symmetric'
            user_share_right_obj.key = request.data['key']
            user_share_right_obj.key_nonce = request.data['key_nonce']
            user_share_right_obj.save()

        except User_Share_Right.DoesNotExist:
            return Response({"message":"You don't have permission to access it or it does not exist or you already accepted or declined this share.",
                            "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        if user_share_right_obj.read:
            share = Share.objects.get(pk=user_share_right_obj.share_id)
            return Response({
                "share_id": share.id,
                "share_data": str(share.data),
                "share_data_nonce": share.data_nonce
            }, status=status.HTTP_200_OK)

        return Response({
                "share_id": user_share_right_obj.share_id
            }, status=status.HTTP_200_OK)


class ShareRightDeclineView(GenericAPIView):

    """
    Check the REST Token and the object permissions and updates the share right as declined and removes title and keys
    from the share right
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    def post(self, request, uuid = None, *args, **kwargs):

        # Accepts or declines a share right

        if not uuid:
            return Response({"message": "UUID for share not specified."}, status=status.HTTP_404_NOT_FOUND)

        try:
            user_share_right_obj = User_Share_Right.objects.get(id=uuid, user=request.user, accepted=None)

            user_share_right_obj.accepted = False
            user_share_right_obj.title = ''
            user_share_right_obj.key_type = ''
            user_share_right_obj.key = ''
            user_share_right_obj.key_nonce = ''
            user_share_right_obj.save()

        except User_Share_Right.DoesNotExist:
            return Response({"message":"You don't have permission to access it or it does not exist or you already accepted or declined this share.",
                            "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        return Response(status=status.HTTP_200_OK)


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

    def get(self, request, uuid = None, *args, **kwargs):
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
                        'share_right_key': u.key,
                        'share_right_key_nonce': u.key_nonce,
                        'share_right_key_type': u.key_type,
                        'share_right_read': u.read,
                        'share_right_write': u.write,
                        'share_right_grant': u.grant,
                        'share_right_accepted': u.accepted,
                        'share_right_create_user_id': u.owner.id,
                        'share_right_create_user_email': u.owner.email}

                    # share.data = str(s.data) if s.data and s.share_right_read and s.share_right_accepted else ''
                    # share.data_nonce =  s.data_nonce if s.data_nonce and s.share_right_read and s.share_right_accepted else ''

                    share_index[s.id] = share
                    specific_right_share_index[s.id] = share

            try:
                inherited_user_share_rights = User_Share_Right_Inherit.objects.filter(share_right__user=request.user).distinct()
            except User_Share_Right_Inherit.DoesNotExist:
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
                        'share_right_key': [],
                        'share_right_key_nonce': [],
                        'share_right_key_type': [],
                        'share_right_read': False,
                        'share_right_write': False,
                        'share_right_grant': False,
                        'share_right_accepted': False,
                        'share_right_create_user_id': [],
                        'share_right_create_user_email': []
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
                share_index[s.id]['share_right_create_user_email'].append(s.share_right.owner.email)

            for share_id, share in share_index.items():
                response.append(share)

            return Response({'shares': response},
                status=status.HTTP_200_OK)

        else:
            # Returns the specified share if the user has any rights for it and joins the user_share objects

            try:
                share = Share.objects.get(pk=uuid)
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

                if u.read:
                    has_read_right = True

            if not user_share_rights:
                for u in share.user_share_right_inherits.filter(share_right__user=request.user):
                    user_share_rights_inherited.append({
                        'id': u.share_right.id,
                        'key': u.share_right.key,
                        'key_nonce': u.share_right.key_nonce,
                        'key_type': u.share_right.key_type,
                        'read': u.share_right.read,
                        'write': u.share_right.write,
                        'grant': u.share_right.grant,
                        'user_id': u.share_right.user_id,
                    })

                    if u.share_right.read:
                        has_read_right = True

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
        # TODO update according to inherit share rights
        # TODO implement check for more shares for enterprise users

        #TODO Check if secret_key and nonce exist

        if 'data' not in request.data:
            return Response({"error": "IdNoUUID", 'message': "Secret ID is badly formed and no uuid"},
                                status=status.HTTP_400_BAD_REQUEST)


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
                read = True,
                write = True,
                grant = True
            )

        return Response({"share_id": share.id}, status=status.HTTP_201_CREATED)

    def post(self, request, uuid = None, *args, **kwargs):
        # TODO update according to inherit share rights

        try:
            share = Share.objects.get(pk=uuid)
        except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        if share.user != request.user and share.user_share_rights.filter(user=request.user, write=True).count() < 0:
            raise PermissionDenied()

        if 'data' in request.data:
            share.data = str(request.data['data'])
        if 'data_nonce' in request.data:
            share.data_nonce = str(request.data['data_nonce'])
        if 'secret_key' in request.data:
            share.secret_key = str(request.data['secret_key'])
        if 'secret_key_nonce' in request.data:
            share.secret_key_nonce = str(request.data['secret_key_nonce'])

        share.save()

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)


class ShareRightsView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    the share rights of a specified share if the necessary access rights are granted

    Accept the following GET parameters: share_id
    Return a list of the share rights for the specified share
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = UserShareRightSerializer

    def get(self, request, uuid = None, *args, **kwargs):
        # TODO update according to inherit share rights

        if not uuid:
            return Response({"message": "UUID for share not specified."}, status=status.HTTP_404_NOT_FOUND)

        else:

            # Returns the specified share rights if the user has any rights for it and joins the user_share objects

            try:
                share = Share.objects.get(pk=uuid)
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

            own_share_right = {
                'id': [],
                'accepted': False,
                'read': False,
                'write': False,
                'grant': False,
                'user_id': [],
                'share_id': uuid,
                'email': [],
            }
            user_share_rights = []
            user_share_rights_inherited = []
            user_has_specific_rights = False


            for u in share.user_share_rights.all():

                right = {
                    'id': u.id,
                    'accepted': u.accepted,
                    'read': u.read,
                    'write': u.write,
                    'grant': u.grant,
                    'user_id': u.user_id,
                    'share_id': u.share_id,
                    'email': u.user.email,
                }

                if u.user_id == request.user.id and (u.read or u.write or u.grant):
                    user_has_specific_rights = True
                    own_share_right = right

                user_share_rights.append(right)

            try:
                user_share_right_inherit = User_Share_Right_Inherit.objects.get(share_id=uuid)


                for u in user_share_right_inherit.all():
                    right = {
                        'id': u.id,
                        'accepted': u.share_right.accepted,
                        'read': u.share_right.read,
                        'write': u.share_right.write,
                        'grant': u.share_right.grant,
                        'user_id': u.share_right.user_id,
                        'share_id': u.share_id,
                        'email': u.user.email,
                    }

                    if not user_has_specific_rights and u.user_id == request.user.id and\
                            (u.share_right.read or u.share_right.write or u.share_right.grant):
                        own_share_right['id'].push = right['id']
                        own_share_right['accepted'] = own_share_right['accepted'] or right['accepted']
                        own_share_right['read'] = own_share_right['read'] or right['read']
                        own_share_right['write'] = own_share_right['accepted'] or right['write']
                        own_share_right['grant'] = own_share_right['accepted'] or right['grant']
                        own_share_right['user_id'].push = right['user_id']
                        own_share_right['email'].push = right['email']

                    user_share_rights_inherited.append(right)

            except User_Share_Right_Inherit.DoesNotExist:
                pass

            if own_share_right['read'] or own_share_right['write'] or own_share_right['grant']:
                raise PermissionDenied({"message":"You don't have permission to access",
                                "resource_id": share.id})

            response = {
                'id': share.id,
                'own_share_rights': own_share_right,
                'user_share_rights': user_share_rights,
                'user_share_rights_inherited': user_share_rights_inherited
            }

            return Response(response,
                status=status.HTTP_200_OK)
