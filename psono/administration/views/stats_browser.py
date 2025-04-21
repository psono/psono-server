from django.db.models import Count
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Token


class StatsBrowserView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Returns the statistics of used devices

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        browsers = Token.objects.filter(valid_till__gt=timezone.now()).values('device_description').annotate(total=Count('device_description')).order_by()

        other = 0
        firefox = 0
        chrome = 0
        safari = 0
        vivaldi = 0
        edge = 0
        brave = 0
        opera = 0

        for browser in browsers:
            if 'chrome' in browser['device_description'].lower():
                chrome = chrome + browser['total']
            elif 'firefox' in browser['device_description'].lower():
                firefox = firefox + browser['total']
            elif 'safari' in browser['device_description'].lower():
                safari = safari + browser['total']
            elif 'edge' in browser['device_description'].lower():
                edge = edge + browser['total']
            elif 'vivaldi' in browser['device_description'].lower():
                vivaldi = vivaldi + browser['total']
            elif 'brave' in browser['device_description'].lower():
                brave = brave + browser['total']
            elif 'opera' in browser['device_description'].lower():
                opera = opera + browser['total']
            else:
                other = other + browser['total']

        return Response({
            'other': other,
            'firefox': firefox,
            'chrome': chrome,
            'safari': safari,
            'vivaldi': vivaldi,
            'edge': edge,
            'brave': brave,
            'opera': opera,
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
