from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from django.db.models import Q

from ..models import (
    Share, User_Share_Right, User
)

from ..app_settings import (
    ShareRightSerializer,
    CreateShareSerializer,
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
    serializer_class = ShareRightSerializer

    def get(self, request, uuid = None, *args, **kwargs):

        if not uuid:

            # Generate a list of a all share rights

            try:
                #share_rights = User_Share_Right.objects.filter(Q(user=request.user) | Q(owner=request.user)).distinct()
                share_rights = User_Share_Right.objects.filter(Q(user=request.user)).distinct()
            except User_Share_Right.DoesNotExist:
                share_rights = []

            responnse = []

            for share_right in share_rights:
                responnse.append({
                    'id': share_right.id,
                    'title': share_right.title,
                    'key': share_right.key,
                    'key_nonce': share_right.key_nonce,
                    'read': share_right.read,
                    'write': share_right.write,
                    'grant': share_right.grant,
                    'share_id': share_right.share_id
                })

            response = {
                'share_rights': responnse
            }

            return Response(response,
                status=status.HTTP_200_OK)

        else:

            # Returns the specified share if the user is the user

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

        # Adds the rights for the specified user to the user_share_rights table

        try:
            User_Share_Right.objects.get(share_id=request.data['share_id'], user=request.user, grant=True)

            # Maybe adjust this later so "owners" cannot lose the rights on their shares
            # share = Share.objects.get(pk=request.data['share_id'], owner=request.user)

        except User_Share_Right.DoesNotExist:
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
            return Response({"message": "You don't have permission to access or it does not exist.",
                             "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        # delete it
        share_right.delete()

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

            try:
                shares = Share.objects.filter(user_share_rights__user=request.user).distinct()
            except Share.DoesNotExist:
                shares = []

            response = []

            for s in shares:
                user_share_rights = []

                for u in s.user_share_rights.filter(user=request.user):
                    user_share_rights.append({
                        'id': u.id,
                        'key': u.key,
                        'key_nonce': u.key_nonce,
                        'read': u.read,
                        'write': u.write,
                        'grant': u.grant,
                        'user_id': u.user_id,
                    })

                response.append({
                    'id': s.id,
                    'data': str(s.data) if s.data else '',
                    'data_nonce': s.data_nonce if s.data_nonce else '',
                    'user_id': s.user_id,
                    'user_share_rights': user_share_rights
                })

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

            for u in share.user_share_rights.filter(user=request.user):
                user_share_rights.append({
                    'id': u.id,
                    'key': u.key,
                    'key_nonce': u.key_nonce,
                    'read': u.read,
                    'write': u.write,
                    'grant': u.grant,
                    'user_id': u.user_id,
                })

            if not user_share_rights:
                raise PermissionDenied({"message":"You don't have permission to access",
                                "resource_id": share.id})

            response = {
                'id': share.id,
                'data': str(share.data) if share.data else '',
                'data_nonce': share.data_nonce if share.data_nonce else '',
                'user_id': share.user_id,
                'user_share_rights': user_share_rights
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
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
                key = "",
                key_nonce = "",
                title="",
                read = True,
                write = True,
                grant = True
            )

        return Response({"share_id": share.id}, status=status.HTTP_201_CREATED)

    def post(self, request, uuid = None, *args, **kwargs):

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
    serializer_class = ShareRightSerializer

    def get(self, request, uuid = None, *args, **kwargs):

        if not uuid:
            return Response({"message": "UUID for share not specified."}, status=status.HTTP_404_NOT_FOUND)

        else:

            # Returns the specified share rights if the user has any rights for it and joins the user_share objects

            try:
                share = Share.objects.get(pk=uuid)
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)


            user_share_rights = []
            user_has_rights = False

            for u in share.user_share_rights.all():

                user_share_rights.append({
                    'id': u.id,
                    'accepted': False if u.key or u.key_nonce else True,
                    'read': u.read,
                    'write': u.write,
                    'grant': u.grant,
                    'user_id': u.user_id,
                    'email': u.user.email,
                })

                if u.user_id == request.user.id and (u.write or u.write or u.grant):
                    user_has_rights = True


            if not user_has_rights:
                raise PermissionDenied({"message":"You don't have permission to access",
                                "resource_id": share.id})

            response = {
                'id': share.id,
                'user_share_rights': user_share_rights
            }

            return Response(response,
                status=status.HTTP_200_OK)
