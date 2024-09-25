from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from ..authentication import TokenAuthentication
from django.core.cache import cache
from django.conf import settings

from ..models import (
    User_Share_Right,
    User_Group_Membership,
    SecurityReport,
)

class StatusView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    allowed_methods = ('GET', 'OPTIONS', 'HEAD')
    throttle_scope = 'status_check'

    def get(self, request, *args, **kwargs):
        """
        Returns the user status, e.g. unapproved shares and so on

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        cache_key = 'psono_user_status_' + str(request.user.id)
        user_status = None

        if settings.CACHE_ENABLE:
            user_status = cache.get(cache_key)

        if user_status is None:
            unaccepted_shares_count = User_Share_Right.objects.filter(user=request.user, accepted__isnull=True).exclude(creator__isnull=True).count()
            unaccepted_groups_count = User_Group_Membership.objects.filter(user=request.user, accepted__isnull=True).count()
            unaccepted_forced_groups_count = User_Group_Membership.objects.filter(user=request.user, accepted__isnull=True, group__forced_membership=True).count()

            try:
                latest_security_report = SecurityReport.objects.filter(user=request.user).latest('create_date')
            except SecurityReport.DoesNotExist:
                latest_security_report = None

            if latest_security_report:
                last_security_report_created = latest_security_report.create_date.isoformat()
            else:
                last_security_report_created = request.user.create_date.isoformat()

            user_status = {
                'unaccepted_shares_count': unaccepted_shares_count,
                'unaccepted_groups_count': unaccepted_groups_count,
                'unaccepted_forced_groups_count': unaccepted_forced_groups_count,
                'last_security_report_created': last_security_report_created,
            }

            if settings.CACHE_ENABLE:
                cache.set(cache_key, user_status, 7*24*60*60)

        return Response(user_status, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)