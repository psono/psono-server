from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from ..authentication import TokenAuthentication
from ..models import SecurityReport, SecurityReportEntry, Recovery_Code, Data_Store
from ..app_settings import CreateSecurityReportSerializer
from datetime import timedelta

class SecurityReportView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Creates a new security report

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        serializer = CreateSecurityReportSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        entries = serializer.validated_data['entries']
        check_haveibeenpwned = serializer.validated_data['check_haveibeenpwned']
        master_password_validated = serializer.validated_data['master_password_validated']

        website_password_count = 0
        breached_password_count = 0
        duplicate_password_count = 0
        master_password_tested = False
        master_password_breached = False
        master_password_duplicate = False
        master_password_length = 0
        master_password_variation_count = 0

        filtered_entries = []
        for entry in entries:
            if not master_password_validated and 'master_password' in entry and entry['master_password']:
                # skip an entry that is presented as the masterpassword but is not actually the masterpassword
                continue

            if master_password_validated and 'master_password' in entry and entry['master_password']:
                master_password_tested = True
                master_password_duplicate = entry['duplicate'] if 'duplicate' in entry else None
                master_password_breached = entry['breached'] if 'breached' in entry else None
                master_password_length = entry['password_length'] if 'password_length' in entry else None
                master_password_variation_count = entry['variation_count'] if 'variation_count' in entry else None

            if 'duplicate' in entry and entry['duplicate']:
                duplicate_password_count = duplicate_password_count + 1

            if 'breached' in entry and entry['breached']:
                breached_password_count = breached_password_count + 1

            if entry['type'] == 'website_password':
                website_password_count = website_password_count + 1

            filtered_entries.append(entry)

        if check_haveibeenpwned:
            breached_password_count = None

        security_report = SecurityReport.objects.create(
            user=request.user,
            recovery_code_exists=Recovery_Code.objects.filter(user=request.user).exists(),
            two_factor_exists=request.user.any_2fa_active(),
            website_password_count=website_password_count,
            breached_password_count=breached_password_count,
            duplicate_password_count=duplicate_password_count,
            check_haveibeenpwned=check_haveibeenpwned,
            master_password_tested=master_password_tested,
            master_password_breached=master_password_breached,
            master_password_duplicate=master_password_duplicate,
            master_password_length=master_password_length,
            master_password_variation_count=master_password_variation_count,
        )

        SecurityReportEntry.objects.bulk_create(
            [SecurityReportEntry(
                security_report=security_report,
                user=request.user,
                name=entry['name'] if 'name' in entry else None,
                type=entry['type'] if 'type' in entry else None,
                create_age=timedelta(days=entry['create_age']) if 'create_age' in entry else None,
                write_age=timedelta(days=entry['write_age']) if 'write_age' in entry else None,
                master_password=entry['master_password'] if 'master_password' in entry else None,
                breached=entry['breached'] if 'breached' in entry else None,
                duplicate=entry['duplicate'] if 'duplicate' in entry else None,
                password_length=entry['password_length'] if 'password_length' in entry else None,
                variation_count=entry['variation_count'] if 'variation_count' in entry else None,
            ) for entry in filtered_entries]
        )

        return Response(status=status.HTTP_201_CREATED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)