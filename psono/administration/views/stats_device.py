from django.db.models import Count
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Token


class StatsDeviceView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        return Serializer

    def get(self, request, *args, **kwargs):
        """
        Returns the statistics of used devices
        """

        devices = Token.objects.filter(valid_till__gt=timezone.now()).values('device_description').annotate(total=Count('device_description')).order_by()

        other = 0
        linux = 0
        windows = 0
        mac = 0
        android = 0
        iphone = 0
        ipad = 0

        for device in devices:
            if 'windows' in device['device_description'].lower():
                windows = windows + device['total']
            elif 'linux' in device['device_description'].lower():
                linux = linux + device['total']
            elif 'android' in device['device_description'].lower():
                android = android + device['total']
            elif device['device_description'].lower().startswith('sm-'):
                android = android + device['total']
            elif device['device_description'].lower().startswith('pixel '):
                android = android + device['total']
            elif device['device_description'].lower().startswith('oneplus'):
                android = android + device['total']
            elif 'iphone' in device['device_description'].lower():
                iphone = iphone + device['total']
            elif 'mac' in device['device_description'].lower():
                mac = mac + device['total']
            elif 'ipad' in device['device_description'].lower():
                ipad = ipad + device['total']
            else:
                other = other + device['total']

        return Response({
            'other': other,
            'linux': linux,
            'windows': windows,
            'mac': mac,
            'android': android,
            'iphone': iphone,
            'ipad': ipad,
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
