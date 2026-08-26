from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers, exceptions

from restapi.models import Fileserver_Cluster_Members
from .admin_access import AdminCapabilitySerializerMixin


class ReadFileserverSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "fileservers.read"

    def validate(self, attrs: dict) -> dict:
        self.validate_global_administrative_access()
        fileserver_id = (
            self.context["request"].parser_context["kwargs"].get("fileserver_id", False)
        )

        if fileserver_id:
            try:
                fileserver = Fileserver_Cluster_Members.objects.get(pk=fileserver_id)
            except (DjangoValidationError, Fileserver_Cluster_Members.DoesNotExist):
                field = "fileserver_id"
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError({field: msg})
            attrs["fileserver"] = fileserver

        page = self.context["request"].query_params.get("page", False)
        if page and not page.isdigit():
            field = "page"
            msg = "ERROR_NO_VALID_INTEGER"
            raise exceptions.ValidationError({field: msg})
        if page and int(page) < 0:
            field = "page"
            msg = "ERROR_VALUE_TOO_SMALL"
            raise exceptions.ValidationError({field: msg})

        page_size = self.context["request"].query_params.get("page_size", False)
        if page_size and not page_size.isdigit():
            field = "page_size"
            msg = "ERROR_NO_VALID_INTEGER"
            raise exceptions.ValidationError({field: msg})
        if page_size and int(page_size) < 1:
            field = "page_size"
            msg = "ERROR_VALUE_TOO_SMALL"
            raise exceptions.ValidationError({field: msg})

        ordering = self.context["request"].query_params.get("ordering", "-create_date")
        allowed_ordering = (
            "create_date",
            "write_date",
            "hostname",
            "version",
            "url",
            "cluster_title",
            "valid_till",
        )
        if ordering.lstrip("-") not in allowed_ordering:
            field = "ordering"
            msg = "INVALID_ORDERING"
            raise exceptions.ValidationError({field: msg})

        search = self.context["request"].query_params.get("search", False)

        attrs["page"] = int(page) + 1
        attrs["page_size"] = int(page_size)
        attrs["ordering"] = ordering
        attrs["search"] = search

        return attrs
