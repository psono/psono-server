from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from django.conf import settings
from django.db.models import Count
from django.db.models.functions import TruncMonth, TruncDay
from datetime import timedelta
from django.utils import timezone

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import User, Token

class InfoView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Returns the Server's signed information and some additional data for a nice dashboard

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        info = settings.SIGNATURE.copy()

        info['user_count_active'] = User.objects.filter(is_active=True).count()
        info['user_count_total'] = User.objects.count()
        info['token_count_total'] = Token.objects.count()
        info['token_count_device'] = Token.objects.values('device_fingerprint').annotate(num_sessions=Count('device_fingerprint')).count()
        info['token_count_user'] = Token.objects.values('user_id').annotate(num_sessions=Count('user_id')).count()


        monthly_registrations = User.objects.annotate(month=TruncMonth('create_date')).values('month').annotate(counter=Count('id')).values('month', 'counter').order_by('month')
        registrations_over_month = []
        count_total_month = 0
        for r in monthly_registrations:
            count_total_month = count_total_month + r['counter']
            registrations_over_month.append({
                'count_new': r['counter'],
                'count_total': count_total_month,
                'month': r['month'].strftime('%b %y')
            })
        info['registrations_over_month'] = registrations_over_month


        daily_registrations_offset = User.objects.filter(create_date__lt=timezone.now()-timedelta(days=16)).count()
        daily_registrations = User.objects.filter(create_date__gte=timezone.now()-timedelta(days=16)).annotate(day=TruncDay('create_date')).values('day').annotate(count_new=Count('id')).values('day', 'count_new').order_by('day')

        end_date = timezone.now()
        d = end_date - timedelta(days=16)
        registrations_over_day_index = {}
        while d <= end_date:
            registrations_over_day_index[d.strftime("%Y-%m-%d")] = {
                'date': d.strftime("%Y-%m-%d"),
                'count_new': 0,
                'count_total': 0,
                'weekday': d.strftime("%a"),
            }
            d += timedelta(days=1)

        for r in daily_registrations:
            registrations_over_day_index[r['day'].strftime('%Y-%m-%d')]['count_new'] = r['count_new']

        registrations_over_day = []
        for k in sorted(registrations_over_day_index):
            daily_registrations_offset = daily_registrations_offset + registrations_over_day_index[k]['count_new']
            registrations_over_day_index[k]['count_total'] = daily_registrations_offset
            registrations_over_day.append(registrations_over_day_index[k])

        info['registrations_over_day'] = registrations_over_day



        past_registrations = User.objects.order_by('-create_date')[:10]
        registrations = []
        for r in past_registrations:
            registrations.append({
                'date': r.create_date,
                'username': r.username,
                'active': r.is_active,
            })
        info['registrations'] = registrations

        return Response(info, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)