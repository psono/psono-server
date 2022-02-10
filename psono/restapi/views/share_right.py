import os

from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.core.cache import cache
from django.conf import settings

from ..utils import get_all_inherited_rights, decrypt_with_db_secret
from ..permissions import IsAuthenticated
from email.mime.image import MIMEImage
from ..models import (
    User_Share_Right,
    Group_Share_Right
)

from ..app_settings import (
    CreateShareRightSerializer,
    UpdateShareRightSerializer,
    DeleteShareRightSerializer,
)

from ..authentication import TokenAuthentication

class ShareRightView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    only the share right of the user who requested it.

    Accept the following GET parameters: share_id (optional)
    Return a list of the shares or the share and the access rights or a message for an update of rights
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, user_share_right_id = None, *args, **kwargs):
        """
        Returns a specific Share_Right or a list of all the Share_Rights of the user who requested it

        :param request:
        :param user_share_right_id:
        :param args:
        :param kwargs:
        :return: 200 / 403
        """
        if not user_share_right_id:

            # Generate a list of a all share rights

            user_share_rights = User_Share_Right.objects.filter(user=request.user, accepted=True).only("share_id", "read", "write", "grant")
            group_share_rights = Group_Share_Right.objects.raw("""SELECT gr.*
                FROM restapi_group_share_right gr
                    JOIN restapi_user_group_membership ms ON gr.group_id = ms.group_id
                WHERE ms.user_id = %(user_id)s
                    AND ms.accepted = true""", {
                'user_id': request.user.id,
            })


            share_right_index = {}
            share_right_response = []

            for share_right in user_share_rights:
                if share_right.share_id not in share_right_index:
                    share = {
                        'share_id': share_right.share_id,
                        'read': share_right.read,
                        'write': share_right.write,
                        'grant': share_right.grant,
                    }
                    share_right_response.append(share)
                    share_right_index[share_right.share_id] = share
                else:
                    share_right_index[share_right.share_id]['read'] = share_right_index[share_right.share_id]['read'] or share_right.read
                    share_right_index[share_right.share_id]['write'] = share_right_index[share_right.share_id]['write'] or share_right.write
                    share_right_index[share_right.share_id]['grant'] = share_right_index[share_right.share_id]['grant'] or share_right.grant


            for share_right in group_share_rights:
                if share_right.share_id not in share_right_index:
                    share = {
                        'share_id': share_right.share_id,
                        'read': share_right.read,
                        'write': share_right.write,
                        'grant': share_right.grant,
                    }
                    share_right_response.append(share)
                    share_right_index[share_right.share_id] = share
                else:
                    share_right_index[share_right.share_id]['read'] = share_right_index[share_right.share_id]['read'] or share_right.read
                    share_right_index[share_right.share_id]['write'] = share_right_index[share_right.share_id]['write'] or share_right.write
                    share_right_index[share_right.share_id]['grant'] = share_right_index[share_right.share_id]['grant'] or share_right.grant


            response = {
                'share_rights': share_right_response
            }

            return Response(response,
                status=status.HTTP_200_OK)

        else:
            # TODO update according to inherit share rights

            # Returns the specified share right if the user is the user

            try:
                share_right = User_Share_Right.objects.get(pk=user_share_right_id)
                if share_right.creator_id != request.user.id and share_right.user_id != request.user.id:

                    return Response({"message":"NO_PERMISSION_OR_NOT_EXIST",
                                    "resource_id": user_share_right_id}, status=status.HTTP_403_FORBIDDEN)
            except User_Share_Right.DoesNotExist:

                return Response({"message":"NO_PERMISSION_OR_NOT_EXIST",
                                "resource_id": user_share_right_id}, status=status.HTTP_403_FORBIDDEN)

            response = {
                'id': share_right.id,
                'title': share_right.title,
                'title_nonce': share_right.title_nonce,
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
        """
        Create Share_Right

        Necessary Rights:
            - grant on share

        :param request:
        :param args:
        :param kwargs:
        :return: 201 / 400
        """

        # it does not yet exist, so lets create it
        serializer = CreateShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


        if serializer.validated_data.get('user_id', False):
            # lets check if the user has already a path to access the share. if yes automatically approve rights
            accepted = None
            if len(list(get_all_inherited_rights(serializer.validated_data['user_id'], serializer.validated_data['share_id']))) > 0:
                accepted = True

            share_right = User_Share_Right.objects.create(
                key=serializer.validated_data['key'],
                key_nonce=serializer.validated_data['key_nonce'],
                title=serializer.validated_data['title'],
                title_nonce=serializer.validated_data['title_nonce'],
                type=serializer.validated_data['type'],
                type_nonce=serializer.validated_data['type_nonce'],
                share_id=serializer.validated_data['share_id'],
                creator=request.user,
                user=serializer.validated_data['user'],
                read=serializer.validated_data['read'],
                write=serializer.validated_data['write'],
                grant=serializer.validated_data['grant'],
                accepted=accepted,
            )

            if settings.CACHE_ENABLE:
                cache_key = 'psono_user_status_' + str(serializer.validated_data['user'].id)
                cache.delete(cache_key)


            if not settings.DISABLE_EMAIL_NEW_SHARE_CREATED:
                # send email
                if settings.WEB_CLIENT_URL:
                    pending_share_link = settings.WEB_CLIENT_URL + '/index.html#!/share/pendingshares'
                else:
                    pending_share_link = None

                msg_plain = render_to_string('email/new_share_created.txt', {
                    'pending_share_link': pending_share_link
                })
                msg_html = render_to_string('email/new_share_created.html', {
                    'pending_share_link': pending_share_link
                })


                if settings.EMAIL_BACKEND in ['anymail.backends.sendinblue.EmailBackend']:
                    # SenndInBlue does not support inline attachments
                    msg_html = msg_html.replace('cid:logo.png', f'{settings.WEB_CLIENT_URL}/img/logo.png')

                msg = EmailMultiAlternatives('New entry shared', msg_plain, settings.EMAIL_FROM,
                                             [decrypt_with_db_secret(serializer.validated_data['user'].email)])

                msg.attach_alternative(msg_html, "text/html")
                msg.mixed_subtype = 'related'

                if settings.EMAIL_BACKEND not in ['anymail.backends.sendinblue.EmailBackend']:
                    for f in ['logo.png']:
                        fp = open(os.path.join(os.path.dirname(__file__), '..', '..', 'static', 'email', f), 'rb')

                        msg_img = MIMEImage(fp.read())
                        fp.close()
                        msg_img.add_header('Content-ID', '<{}>'.format(f))
                        msg.attach(msg_img)

                try:
                    msg.send()
                except:  # nosec
                    # Lets not fail share creation for failing emails e.g. due to a completely missing email config
                    pass

        else:
            share_right = Group_Share_Right.objects.create(
                key=serializer.validated_data['key'],
                key_nonce=serializer.validated_data['key_nonce'],
                title=serializer.validated_data['title'],
                title_nonce=serializer.validated_data['title_nonce'],
                type=serializer.validated_data['type'],
                type_nonce=serializer.validated_data['type_nonce'],
                share_id=serializer.validated_data['share_id'],
                creator=request.user,
                group=serializer.validated_data['group'],
                read=serializer.validated_data['read'],
                write=serializer.validated_data['write'],
                grant=serializer.validated_data['grant'],
            )

            if settings.CACHE_ENABLE:
                cache_key = 'psono_user_status_' + str(request.user.id)
                cache.delete(cache_key)

        return Response({"share_right_id": share_right.id},
                        status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Update Share_Right

        Necessary Rights:
            - grant on share

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        # it does not yet exist, so lets create it
        serializer = UpdateShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


        share_right_obj = serializer.validated_data['share_right_obj']

        share_right_obj.read = serializer.validated_data['read']
        share_right_obj.write = serializer.validated_data['write']
        share_right_obj.grant = serializer.validated_data['grant']
        share_right_obj.save()

        return Response({"share_right_id": str(share_right_obj.id)},
                        status=status.HTTP_200_OK)





    def delete(self, request, *args, **kwargs):
        """
        Delete a Share_Right obj

        Necessary Rights:
            - grant on share

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        # it does not yet exist, so lets create it
        serializer = DeleteShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


        share_right = serializer.validated_data['share_right']

        if settings.CACHE_ENABLE:

            if isinstance(share_right, User_Share_Right):
                cache_key = 'psono_user_status_' + str(share_right.user.id)
                cache.delete(cache_key)
            else:
                for member in share_right.group.members.only('id').all():
                    cache_key = 'psono_user_status_' + str(member.user.id)
                    cache.delete(cache_key)

        # delete it
        share_right.delete()

        return Response(status=status.HTTP_200_OK)

