from rest_framework import serializers, exceptions
from restapi.models import SecurityReport
from .admin_access import AdminCapabilitySerializerMixin


class ReadSecurityReportSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "security_reports.read"

    def validate(self, attrs: dict) -> dict:
        security_report_id = (
            self.context["request"]
            .parser_context["kwargs"]
            .get("security_report_id", False)
        )

        if security_report_id:
            try:
                security_report = (
                    SecurityReport.objects.select_related("user")
                    .prefetch_related("security_report_entries")
                    .get(pk=security_report_id)
                )
            except SecurityReport.DoesNotExist:
                field = "group_id"
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError({field: msg})
            attrs["security_report"] = security_report

        access = self.validate_administrative_access(
            user=attrs.get("security_report").user
            if attrs.get("security_report")
            else None
        )
        attrs["admin_access"] = access

        return attrs
