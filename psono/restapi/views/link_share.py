from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..app_settings import (
    CreateLinkShareSerializer,
    UpdateLinkShareSerializer,
    DeleteLinkShareSerializer,
)
from ..models import (
    Link_Share
)
from ..authentication import TokenAuthentication

class LinkShareView(GenericAPIView):

    """
    Check the REST Token and returns a list of all link_shares or the specified link_shares details
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')


    def get(self, request, link_share_id = None, *args, **kwargs):
        """
        Returns either a list of all link_shares with own access privileges or the members specified link_share
        
        :param request:
        :type request:
        :param link_share_id:
        :type link_share_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 403
        :rtype:
        """

        if not link_share_id:

            link_shares = []

            for link_share in Link_Share.objects.filter(user=request.user).exclude(valid_till__lt=timezone.now()).exclude(allowed_reads__lte=0):
                link_shares.append({
                    'id': link_share.id,
                    'public_title': link_share.public_title,
                    'allowed_reads': link_share.allowed_reads,
                    'valid_till': link_share.valid_till,
                })

            return Response({'link_shares': link_shares},
                status=status.HTTP_200_OK)
        else:
            # Returns the specified link_share if the user has any rights for it
            try:
                link_share = Link_Share.objects.get(id=link_share_id, user=request.user)
            except Link_Share.DoesNotExist:
                return Response({"message":"NO_PERMISSION_OR_NOT_EXIST",
                                 "resource_id": link_share_id}, status=status.HTTP_400_BAD_REQUEST)

            response = {
                'id': link_share.id,
                'public_title': link_share.public_title,
                'allowed_reads': link_share.allowed_reads,
                'valid_till': link_share.valid_till,
            }


            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Creates an link_share

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateLinkShareSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        secret_id = serializer.validated_data.get('secret_id')
        file_id = serializer.validated_data.get('file_id')
        allowed_reads = serializer.validated_data.get('allowed_reads')
        public_title = serializer.validated_data.get('public_title')
        node = serializer.validated_data.get('node')
        node_nonce = serializer.validated_data.get('node_nonce')
        passphrase = serializer.validated_data.get('passphrase')
        valid_till = serializer.validated_data.get('valid_till')

        link_share = Link_Share.objects.create(
            user = request.user,
            secret_id = secret_id,
            file_id = file_id,
            allowed_reads = allowed_reads,
            public_title = public_title,
            node = node.encode(),
            node_nonce = node_nonce,
            passphrase = passphrase,
            valid_till = valid_till,
        )

        return Response({
            "link_share_id": link_share.id,
        }, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a link_share

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = UpdateLinkShareSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        link_share = serializer.validated_data.get('link_share')
        allowed_reads = serializer.validated_data.get('allowed_reads')
        public_title = serializer.validated_data.get('public_title')
        passphrase = serializer.validated_data.get('passphrase')
        valid_till = serializer.validated_data.get('valid_till')

        # Update the object
        link_share.public_title = public_title
        link_share.allowed_reads = allowed_reads
        link_share.passphrase = passphrase
        link_share.valid_till = valid_till

        link_share.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an link_share

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteLinkShareSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        link_share = serializer.validated_data.get('link_share')

        # delete it
        link_share.delete()

        return Response({}, status=status.HTTP_200_OK)
