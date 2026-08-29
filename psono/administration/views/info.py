from datetime import timedelta

from administration.serializers.info_read import InfoReadSerializer
from django.conf import settings
from django.db.models import Count, Q
from django.db.models.functions import TruncDay, TruncMonth
from django.utils import timezone
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from restapi.authentication import TokenAuthentication
from restapi.models import Fileserver_Cluster_Members, Token, User

from ..permissions import AdminPermission


class InfoView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    allowed_methods = ("GET", "OPTIONS", "HEAD")

    def get_serializer_class(self):
        return InfoReadSerializer

    def get(self, request, *args, **kwargs):
        """
        Returns the Server's signed information and some additional data for a nice dashboard
        """

        serializer = InfoReadSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        info = settings.SIGNATURE.copy()
        now = timezone.now()

        token_counts = Token.objects.filter(valid_till__gt=now, active=True).aggregate(
            token_count_total=Count("pk"),
            token_count_device=Count("device_fingerprint", distinct=True),
            token_count_device_null=Count(
                "pk", filter=Q(device_fingerprint__isnull=True)
            ),
            token_count_user=Count("user_id", distinct=True),
        )
        info["token_count_total"] = token_counts["token_count_total"]
        info["token_count_device"] = token_counts["token_count_device"] + int(
            token_counts["token_count_device_null"] > 0
        )
        info["token_count_user"] = token_counts["token_count_user"]

        monthly_registrations = (
            User.objects.annotate(month=TruncMonth("create_date"))
            .values("month")
            .annotate(
                counter=Count("id"),
                active_counter=Count("id", filter=Q(is_active=True)),
            )
            .values("month", "counter", "active_counter")
            .order_by("month")
        )
        registrations_over_month = []
        count_total_month = 0
        user_count_active = 0
        for r in monthly_registrations:
            count_total_month = count_total_month + r["counter"]
            user_count_active = user_count_active + r["active_counter"]
            registrations_over_month.append(
                {
                    "count_new": r["counter"],
                    "count_total": count_total_month,
                    "month": r["month"].strftime("%b %y"),
                }
            )
        info["user_count_active"] = user_count_active
        info["user_count_total"] = count_total_month
        info["registrations_over_month"] = registrations_over_month

        daily_registrations = list(
            User.objects.filter(create_date__gte=now - timedelta(days=16))
            .annotate(day=TruncDay("create_date"))
            .values("day")
            .annotate(count_new=Count("id"))
            .values("day", "count_new")
            .order_by("day")
        )
        daily_registrations_offset = count_total_month - sum(
            registration["count_new"] for registration in daily_registrations
        )

        end_date = now
        d = end_date - timedelta(days=16)
        registrations_over_day_index = {}
        while d <= end_date:
            registrations_over_day_index[d.strftime("%Y-%m-%d")] = {
                "date": d.strftime("%Y-%m-%d"),
                "count_new": 0,
                "count_total": 0,
                "weekday": d.strftime("%a"),
            }
            d += timedelta(days=1)

        for r in daily_registrations:
            registrations_over_day_index[r["day"].strftime("%Y-%m-%d")]["count_new"] = (
                r["count_new"]
            )

        registrations_over_day = []
        for k in sorted(registrations_over_day_index):
            daily_registrations_offset = (
                daily_registrations_offset
                + registrations_over_day_index[k]["count_new"]
            )
            registrations_over_day_index[k]["count_total"] = daily_registrations_offset
            registrations_over_day.append(registrations_over_day_index[k])

        info["registrations_over_day"] = registrations_over_day

        fileserver_cluster_members = (
            Fileserver_Cluster_Members.objects.filter(
                valid_till__gt=now
                - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT)
            )
            .select_related("fileserver_cluster")
            .only("create_date", "fileserver_cluster__title", "hostname", "version")
        )

        fileserver = []
        for r in fileserver_cluster_members:
            fileserver.append(
                {
                    "create_date": r.create_date,
                    "fileserver_cluster_title": r.fileserver_cluster.title,
                    "hostname": r.hostname,
                    "version": r.version,
                }
            )

        info["fileserver"] = fileserver

        past_registrations = User.objects.order_by("-create_date").values(
            "create_date", "username", "is_active"
        )[:10]
        registrations = []
        for r in past_registrations:
            registrations.append(
                {
                    "date": r["create_date"],
                    "username": r["username"],
                    "active": r["is_active"],
                }
            )
        info["registrations"] = registrations

        return Response(info, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
