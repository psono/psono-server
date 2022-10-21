from ..utils import calculate_user_rights_on_share
from .share_link import create_share_link
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..models import (
    Share, User_Share_Right
)

from ..app_settings import (
    CreateShareSerializer,
    UpdateShareSerializer,
)
from django.core.exceptions import ValidationError

from ..utils import readbuffer
from ..authentication import TokenAuthentication

class ShareView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'OPTIONS', 'HEAD')

    def get_shares(self, user):

            # Generates a list of shares wherever the user has any rights for it and joins the user_share objects

            specific_right_share_index = {}
            share_index = {}

            user_share_rights = User_Share_Right.objects\
                .select_related('creator')\
                .filter(user=user)\
                .exclude(creator__isnull=True, accepted__isnull=True)\
                .exclude(creator__isnull=True, accepted=False)\
                .only("id","share_id", "user_id", "title", "title_nonce", "key", "key_nonce",
                      "read", "write", "grant", "accepted", "creator__id", "creator__username",
                      "creator__public_key", "create_date", "write_date")

            for user_share_right in user_share_rights:

                share = {
                    'id': user_share_right.share_id,
                    'share_right_create_date': user_share_right.create_date,
                    'share_right_write_date': user_share_right.write_date,
                    'share_right_id': user_share_right.id,
                    'share_right_user_id': user_share_right.user_id,
                    'share_right_title': user_share_right.title,
                    'share_right_title_nonce': user_share_right.title_nonce,
                    'share_right_key': user_share_right.key,
                    'share_right_key_nonce': user_share_right.key_nonce,
                    'share_right_key_type': 'symmetric',
                    'share_right_read': user_share_right.read,
                    'share_right_write': user_share_right.write,
                    'share_right_grant': user_share_right.grant,
                    'share_right_accepted': user_share_right.accepted,
                    'share_right_create_user_id': user_share_right.creator.id if user_share_right.creator is not None else '',
                    'share_right_create_user_username': user_share_right.creator.username if user_share_right.creator is not None else '',
                    'share_right_create_user_public_key': user_share_right.creator.public_key if user_share_right.creator is not None else ''
                }

                share_index[user_share_right.share_id] = share
                specific_right_share_index[user_share_right.share_id] = share

            # shares = Share.objects.filter(user_share_rights__user=user).distinct()
            #
            # for share in shares:
            #
            #     for user_share_right in share.user_share_rights.filter(user=user):
            #
            #         s = {
            #             'id': share.id,
            #             'share_right_id': user_share_right.id,
            #             'share_right_user_id': user_share_right.user_id,
            #             'share_right_title': user_share_right.title,
            #             'share_right_title_nonce': user_share_right.title_nonce,
            #             'share_right_key': user_share_right.key,
            #             'share_right_key_nonce': user_share_right.key_nonce,
            #             'share_right_key_type': 'symmetric',
            #             'share_right_read': user_share_right.read,
            #             'share_right_write': user_share_right.write,
            #             'share_right_grant': user_share_right.grant,
            #             'share_right_accepted': user_share_right.accepted,
            #             'share_right_create_user_id': user_share_right.creator.id if user_share_right.creator is not None else '',
            #             'share_right_create_user_username': user_share_right.creator.username if user_share_right.creator is not None else '',
            #             'share_right_create_user_public_key': user_share_right.creator.public_key if user_share_right.creator is not None else ''
            #         }
            #
            #         share_index[share.id] = s
            #         specific_right_share_index[share.id] = s


            return [share for share_id, share in share_index.items()]

    def get_share(self, user, uuid):

        try:
            share = Share.objects.get(pk=uuid)
        except ValidationError:
            return None
        except Share.DoesNotExist:
            return None

        rights = calculate_user_rights_on_share(user.id, uuid)

        if not rights['read']:
            return None
        
        return {
            'share': share,
            'rights': rights,
        }

    def get(self, request, share_id = None, *args, **kwargs):
        """
        Returns a list of all shares with all own share rights on that share or
        returns a share with all rights existing on the share

        :param request:
        :param share_id:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """
        if not share_id:

            shares = self.get_shares(request.user)

            return Response({'shares': shares},
                status=status.HTTP_200_OK)

        else:

            # UUID specified
            # Returns the specified share if the user has any rights for it and joins the user_share objects

            share = self.get_share(request.user, share_id)

            if share is None:

                return Response("The share does not exist or you don't have read permissions",
                                status=status.HTTP_400_BAD_REQUEST)

            response = {
                'id': share['share'].id,
                'data': readbuffer(share['share'].data),
                'data_nonce': share['share'].data_nonce if share['share'].data_nonce else '',
                'user_id': share['share'].user_id,
                'rights': share['rights'],
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
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

        serializer = UpdateShareSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        share = serializer.validated_data['share']
        if serializer.validated_data['data']:
            share.data = serializer.validated_data['data'].encode()
        if 'data_nonce' in request.data:
            share.data_nonce = str(serializer.validated_data['data_nonce'])

        share.save()

        return Response({"success": "Data updated."},
                        status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
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

        serializer = CreateShareSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        share = Share.objects.create(
            data = request.data['data'].encode(),
            data_nonce = str(request.data['data_nonce']),
            user = request.user
        )

        User_Share_Right.objects.create(
                creator = request.user,
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

        if not create_share_link(request.data['link_id'], share.id, serializer.validated_data['parent_share_id'], serializer.validated_data['parent_datastore_id']):

            return Response({"error": "DuplicateLinkID", 'message': "Don't use a link id twice"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"share_id": share.id}, status=status.HTTP_201_CREATED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


