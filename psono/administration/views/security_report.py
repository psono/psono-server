from django.utils.duration import duration_string
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import SecurityReport, User

from ..app_settings import (
    ReadSecurityReportSerializer
)


class SecurityReportView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_security_report_info(self, security_report):

        entries = []
        for entry in security_report.security_report_entries.all():
            entries.append({
                'id': entry.id,
                'name': entry.name,
                'type': entry.type,
                'create_age': duration_string(entry.create_age) if entry.create_age is not None else None,
                'write_age': duration_string(entry.write_age) if entry.write_age is not None else None,
                'master_password': entry.master_password,
                'breached': entry.breached,
                'duplicate': entry.duplicate,
                'password_length': entry.password_length,
                'variation_count': entry.variation_count,
            })
        return {
            'id': security_report.id,
            'create_date': security_report.create_date,
            'username': security_report.user.username,
            'recovery_code_exists': security_report.recovery_code_exists,
            'two_factor_exists': security_report.two_factor_exists,
            'website_password_count': security_report.website_password_count,
            'breached_password_count': security_report.breached_password_count,
            'duplicate_password_count': security_report.duplicate_password_count,
            'check_haveibeenpwned': security_report.check_haveibeenpwned,
            'master_password_breached': security_report.master_password_breached,
            'master_password_duplicate': security_report.master_password_duplicate,
            'master_password_length': security_report.master_password_length,
            'master_password_variation_count': security_report.master_password_variation_count,
            'entries': entries,
        }

    def get(self, request, security_report_id = None, *args, **kwargs):
        """
        Returns a list of all security reports

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = ReadSecurityReportSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        if security_report_id:

            security_report = serializer.validated_data.get('security_report')
            security_report_info = self.get_security_report_info(security_report)

            return Response(security_report_info, status=status.HTTP_200_OK)

        else:

            security_reports = []
            for security_report in SecurityReport.objects.select_related('user').filter(user__is_active=True, user__is_email_active=True).order_by('user__username', '-create_date').distinct('user__username'):
                security_reports.append({
                    'id': security_report.id,
                    'create_date': security_report.create_date,
                    'username': security_report.user.username,
                    'recovery_code_exists': security_report.recovery_code_exists,
                    'two_factor_exists': security_report.two_factor_exists,
                    'website_password_count': security_report.website_password_count,
                    'breached_password_count': security_report.breached_password_count,
                    'duplicate_password_count': security_report.duplicate_password_count,
                    'check_haveibeenpwned': security_report.check_haveibeenpwned,
                    'master_password_breached': security_report.master_password_breached,
                    'master_password_duplicate': security_report.master_password_duplicate,
                    'master_password_length': security_report.master_password_length,
                    'master_password_variation_count': security_report.master_password_variation_count,
                })

            users_missing_reports = []
            for user in  User.objects.filter(is_active=True, is_email_active=True).filter(security_reports__isnull=True).order_by('username', '-create_date'):
                users_missing_reports.append({
                    'id': user.id,
                    'create_date': user.create_date,
                    'username': user.username,
                })

            return Response({
                'security_reports': security_reports,
                'user_count': User.objects.filter(is_active=True, is_email_active=True).count(),
                'users_missing_reports': users_missing_reports
            }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
