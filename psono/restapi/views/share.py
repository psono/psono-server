from ..utils import calculate_user_rights_on_share
from .share_link import create_share_link
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

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

import six

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)

class ShareView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'OPTIONS', 'HEAD')

    def get_shares(self, user):

            # Generates a list of shares wherever the user has any rights for it and joins the user_share objects

            #TODO optimize query. this way its too inefficient ...

            specific_right_share_index = {}
            share_index = {}

            shares = Share.objects.filter(user_share_rights__user=user).distinct()

            for s in shares:

                for u in s.user_share_rights.filter(user=user):

                    share = {
                        'id': s.id,
                        'share_right_id': u.id,
                        'share_right_user_id': u.user_id,
                        'share_right_title': u.title,
                        'share_right_title_nonce': u.title_nonce,
                        'share_right_key': u.key,
                        'share_right_key_nonce': u.key_nonce,
                        'share_right_key_type': 'symmetric',
                        'share_right_read': u.read,
                        'share_right_write': u.write,
                        'share_right_grant': u.grant,
                        'share_right_accepted': u.accepted,
                        'share_right_create_user_id': u.creator.id if u.creator is not None else '',
                        'share_right_create_user_username': u.creator.username if u.creator is not None else '',
                        'share_right_create_user_public_key': u.creator.public_key if u.creator is not None else ''
                    }

                    # share.data = str(s.data) if s.data and s.share_right_read and s.share_right_accepted else ''
                    # share.data_nonce =  s.data_nonce if s.data_nonce and s.share_right_read and s.share_right_accepted else ''

                    share_index[s.id] = share
                    specific_right_share_index[s.id] = share


            # inherited_user_share_rights = []
            #
            # for s in inherited_user_share_rights:
            #
            #     # if we already have a specific right for this share, we do not allow inherited rights anymore
            #     if s.id in specific_right_share_index:
            #         continue
            #
            #     if not s.id in share_index:
            #         share_index[s.id] = {
            #             'id': s.id,
            #             'share_right_id': [],
            #             'share_right_user_id': [],
            #             'share_right_title': '',
            #             'share_right_title_nonce': '',
            #             'share_right_key': [],
            #             'share_right_key_nonce': [],
            #             'share_right_key_type': [],
            #             'share_right_read': False,
            #             'share_right_write': False,
            #             'share_right_grant': False,
            #             'share_right_accepted': False,
            #             'share_right_create_user_id': [],
            #             'share_right_create_user_username': [],
            #             'share_right_create_user_public_key': []
            #         }
            #
            #     share_index[s.id]['share_right_id'].append(s.share_right.id)
            #     share_index[s.id]['share_right_user_id'].append(s.share_right.user_id)
            #     share_index[s.id]['share_right_key'].append(s.share_right.key)
            #     share_index[s.id]['share_right_key_nonce'].append(s.share_right.key_nonce)
            #     share_index[s.id]['share_right_key_type'].append(s.share_right.key_type)
            #     share_index[s.id]['share_right_read'] = share_index[s.id]['share_right_read'] or  s.share_right.read
            #     share_index[s.id]['share_right_write'] = share_index[s.id]['share_right_write'] or  s.share_right.write
            #     share_index[s.id]['share_right_grant'] = share_index[s.id]['share_right_grant'] or  s.share_right.grant
            #     share_index[s.id]['share_right_accepted'] = share_index[s.id]['share_right_accepted'] or  s.share_right.accepted
            #     share_index[s.id]['share_right_create_user_id'].append(s.share_right.creator.id)
            #     share_index[s.id]['share_right_create_user_username'].append(s.share_right.creator.username)
            #     share_index[s.id]['share_right_create_user_public_key'].append(s.share_right.creator.public_key)


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

            log_info(logger=logger, request=request, status='HTTP_200_OK', event='READ_ALL_SHARES_SUCCESS')

            return Response({'shares': self.get_shares(request.user)},
                status=status.HTTP_200_OK)

        else:

            # UUID specified
            # Returns the specified share if the user has any rights for it and joins the user_share objects

            share = self.get_share(request.user, share_id)

            if share is None:

                log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='READ_SHARE_SHARE_NOT_EXIST_ERROR')

                return Response("The share does not exist or you don't have read permissions",
                                status=status.HTTP_400_BAD_REQUEST)

            response = {
                'id': share['share'].id,
                'data': readbuffer(share['share'].data),
                'data_nonce': share['share'].data_nonce if share['share'].data_nonce else '',
                'user_id': share['share'].user_id,
                'rights': share['rights'],
            }

            log_info(logger=logger, request=request, status='HTTP_200_OK',
                     event='READ_SHARE_SUCCESS', request_resource=share['share'].id)

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

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='UPDATE_SHARE_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        share = serializer.validated_data['share']
        if serializer.validated_data['data']:
            share.data = six.b(str(serializer.validated_data['data']))
        if 'data_nonce' in request.data:
            share.data_nonce = str(serializer.validated_data['data_nonce'])

        share.save()

        log_info(logger=logger, request=request, status='HTTP_200_OK',
                 event='UPDATE_SHARE_SUCCESS', request_resource=share.id)

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

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='CREATE_SHARE_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        share = Share.objects.create(
            data = six.b(str(request.data['data'])),
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

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST',
                     event='CREATE_SHARE_DUPLICATE_LINK_ID_ERROR')

            return Response({"error": "DuplicateLinkID", 'message': "Don't use a link id twice"}, status=status.HTTP_400_BAD_REQUEST)

        log_info(logger=logger, request=request, status='HTTP_201_CREATED',
                 event='CREATE_SHARE_SUCCESS', request_resource=share.id)

        return Response({"share_id": share.id}, status=status.HTTP_201_CREATED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


