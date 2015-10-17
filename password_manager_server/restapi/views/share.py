from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Share, User_Share_Right, User
)

from ..app_settings import (
    ShareSerializer,
)
from rest_framework.exceptions import PermissionDenied

from django.db import IntegrityError
from ..authentication import TokenAuthentication


class ShareRightsView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    the share rights if the necessary access rights are granted
    and the user is  the user of the share

    Accept the following GET parameters: share_id (optional)
    Return a list of the shares or the share and the access rights or a message for an update of rights
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = ShareSerializer

    def get(self, request, uuid = None, *args, **kwargs):

        if not uuid:

            # Generate a list of a all shares where the user is the user and join all user_share objects
            # Share data is not returned

            # TODO optimize query. this way its too inefficient ...

            try:
                shares = Share.objects.filter(user=request.user)
            except Share.DoesNotExist:
                shares = []

            response = []
            for s in shares:

                user_share_rights = []
                for u in s.user_share_rights.all():
                    user_share_rights.append({
                        'id': u.id,
                        'key': u.key,
                        'key_nonce': u.key_nonce,
                        'encryption_type': u.encryption_type,
                        'approved': u.approved,
                        'read': u.read,
                        'write': u.write,
                        'grant': u.grant,
                        'revoke': u.revoke,
                        'user_id': u.user_id,
                    })

                response.append({
                    'id': s.id,
                    'type': s.type,
                    'user_share_rights': user_share_rights
                })

            return Response({'shares': response},
                status=status.HTTP_200_OK)
        else:

            # Returns the specified share if the user is the user and join all user_share objects
            # Share data is not returned

            try:
                share = Share.objects.get(pk=uuid, user=request.user)
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)


            user_share_rights = []

            for u in share.user_share_rights.all():
                user_share_rights.append({
                    'id': u.id,
                    'key': u.key,
                    'key_nonce': u.key_nonce,
                    'encryption_type': u.encryption_type,
                    'approved': u.approved,
                    'read': u.read,
                    'write': u.write,
                    'grant': u.grant,
                    'revoke': u.revoke,
                    'user_id': u.user_id,
                })

            response = {
                'id': share.id,
                'type': share.type,
                'user_share_rights': user_share_rights
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, uuid = None, *args, **kwargs):

        if not uuid:
            return Response({"error": "NoIdProvided", 'message': "No share id provided"},
                            status=status.HTTP_400_BAD_REQUEST)
        else:

            # Adds the rights for the specified user to the user_share_rights table

            try:
                share = Share.objects.get(pk=uuid, user=request.user)
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)

            try:
                user = User.objects.get(pk=str(request.data['user_id']) )
            except User.DoesNotExist:
                return Response({"message":"Target user does not exist.",
                                "resource_id": str(request.data['user_id'])}, status=status.HTTP_404_NOT_FOUND)


            user_share_obj = User_Share_Right.objects.create(
                key=str(request.data['key']),
                key_nonce=str(request.data['nonce']),
                encryption_type='public',
                share=share,
                owner=request.user,
                user=user,
                approved=False,
                read=request.data['read'],
                write=request.data['write'],
            )

            return Response({"user_share_id": str(user_share_obj.id)},
                status=status.HTTP_201_CREATED)


class ShareView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    the share if the necessary access rights are granted

    Accept the following POST parameters: share_id (optional)
    Return a list of the shares or the share
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = ShareSerializer

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
                        'encryption_type': u.encryption_type,
                        'approved': u.approved,
                        'read': u.read,
                        'write': u.write,
                        'grant': u.grant,
                        'revoke': u.revoke,
                        'user_id': u.user_id,
                    })

                response.append({
                    'id': s.id,
                    'data': str(s.data) if s.data else '',
                    'data_nonce': s.data_nonce if s.data_nonce else '',
                    'type': s.type,
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
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)


            user_share_rights = []

            for u in share.user_share_rights.filter(user=request.user):
                user_share_rights.append({
                    'id': u.id,
                    'key': u.key,
                    'key_nonce': u.key_nonce,
                    'encryption_type': u.encryption_type,
                    'approved': u.approved,
                    'read': u.read,
                    'write': u.write,
                    'grant': u.grant,
                    'revoke': u.revoke,
                    'user_id': u.user_id,
                })

            if not user_share_rights:
                raise PermissionDenied({"message":"You don't have permission to access",
                                "resource_id": share.id})

            response = {
                'id': share.id,
                'data': str(share.data) if share.data else '',
                'data_nonce': share.data_nonce if share.data_nonce else '',
                'type': share.type,
                'user_id': share.user_id,
                'user_share_rights': user_share_rights
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        # TODO implement check for more shares for enterprise users

        #TODO Check if secret_key and nonce exist

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
                key = str(request.data['secret_key']),
                key_nonce = str(request.data['secret_key_nonce']),
                approved = True,
                encryption_type = 'secret',
                read = True,
                write = True,
                grant = True,
                revoke = True,
            )

        return Response({"share_id": share.id}, status=status.HTTP_201_CREATED)

    def post(self, request, uuid = None, *args, **kwargs):

        try:
            share = Share.objects.get(pk=uuid)
        except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_404_NOT_FOUND)

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
