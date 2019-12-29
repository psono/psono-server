from django.utils.duration import duration_string
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import SecurityReport, User


class SecurityReportView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_security_report_info(self, security_report_id):

        try:
            seurity_report = SecurityReport.objects.select_related('user').prefetch_related('security_report_entries').get(pk=security_report_id)
        except SecurityReport.DoesNotExist:
            return None

        entries = []
        for entry in seurity_report.security_report_entries.all():
            entries.append({
                'id': entry.id,
                'name': entry.name,
                'type': entry.type,
                'create_age': duration_string(entry.create_age),
                'write_age': duration_string(entry.write_age),
                'master_password': entry.master_password,
                'breached': entry.breached,
                'duplicate': entry.duplicate,
                'password_length': entry.password_length,
                'variation_count': entry.variation_count,
            })
        return {
            'id': seurity_report.id,
            'create_date': seurity_report.create_date,
            'username': seurity_report.user.username,
            'recovery_code_exists': seurity_report.recovery_code_exists,
            'two_factor_exists': seurity_report.two_factor_exists,
            'website_password_count': seurity_report.website_password_count,
            'breached_password_count': seurity_report.breached_password_count,
            'duplicate_password_count': seurity_report.duplicate_password_count,
            'check_haveibeenpwned': seurity_report.check_haveibeenpwned,
            'master_password_breached': seurity_report.master_password_breached,
            'master_password_duplicate': seurity_report.master_password_duplicate,
            'master_password_length': seurity_report.master_password_length,
            'master_password_variation_count': seurity_report.master_password_variation_count,
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
        if security_report_id:


            security_report_info = self.get_security_report_info(security_report_id)

            if not security_report_info:
                return Response({"error": "SECURITY_REPORT_NOT_FOUND."}, status=status.HTTP_404_NOT_FOUND)

            return Response(security_report_info,
                status=status.HTTP_200_OK)

        else:

            security_reports = []
            for seurity_report in  SecurityReport.objects.select_related('user').filter(user__is_active=True, user__is_email_active=True).order_by('user__username', '-create_date').distinct('user__username'):
                security_reports.append({
                    'id': seurity_report.id,
                    'create_date': seurity_report.create_date,
                    'username': seurity_report.user.username,
                    'recovery_code_exists': seurity_report.recovery_code_exists,
                    'two_factor_exists': seurity_report.two_factor_exists,
                    'website_password_count': seurity_report.website_password_count,
                    'breached_password_count': seurity_report.breached_password_count,
                    'duplicate_password_count': seurity_report.duplicate_password_count,
                    'check_haveibeenpwned': seurity_report.check_haveibeenpwned,
                    'master_password_breached': seurity_report.master_password_breached,
                    'master_password_duplicate': seurity_report.master_password_duplicate,
                    'master_password_length': seurity_report.master_password_length,
                    'master_password_variation_count': seurity_report.master_password_variation_count,
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
