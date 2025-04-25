from django.db.models import Count
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Token


class StatsOsView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Returns the statistics of used operations_systems

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        operations_systems = Token.objects.filter(valid_till__gt=timezone.now()).values('device_description').annotate(total=Count('device_description')).order_by()

        other = 0
        linux = 0
        windows = 0
        mac_os = 0
        android = 0
        ios = 0
        ipados = 0

        for operation_system in operations_systems:
            if 'windows' in operation_system['device_description'].lower():
                windows = windows + operation_system['total']
            elif any([term in operation_system['device_description'].lower() for term in ['linux', 'ubuntu']]):
                linux = linux + operation_system['total']
            elif 'mac os' in operation_system['device_description'].lower():
                mac_os = mac_os + operation_system['total']
            elif 'android' in operation_system['device_description'].lower():
                android = android + operation_system['total']
            elif operation_system['device_description'].lower().startswith('sm-'):
                android = android + operation_system['total']
            elif operation_system['device_description'].lower().startswith('pixel '):
                android = android + operation_system['total']
            elif operation_system['device_description'].lower().startswith('oneplus'):
                android = android + operation_system['total']
            elif 'ios' in operation_system['device_description'].lower():
                ios = ios + operation_system['total']
            elif 'ipad' in operation_system['device_description'].lower():
                ipados = ipados + operation_system['total']
            else:
                other = other + operation_system['total']

        return Response({
            'other': other,
            'linux': linux,
            'windows': windows,
            'mac_os': mac_os,
            'android': android,
            'ios': ios,
            'ipados': ipados,
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
