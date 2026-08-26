from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers, exceptions

from restapi.models import Fileserver_Cluster
from .admin_access import AdminCapabilitySerializerMixin


class ReadFileserverClusterSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "fileservers.read"

    def validate(self, attrs: dict) -> dict:
        self.validate_global_administrative_access()
        cluster_id = (
            self.context["request"].parser_context["kwargs"].get("cluster_id", False)
        )

        if cluster_id:
            try:
                cluster = Fileserver_Cluster.objects.get(pk=cluster_id)
            except (DjangoValidationError, Fileserver_Cluster.DoesNotExist):
                field = "cluster_id"
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError({field: msg})
            attrs["cluster"] = cluster

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
            "title",
            "file_size_limit",
            "shard_count",
            "member_count",
            "live_member_count",
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
