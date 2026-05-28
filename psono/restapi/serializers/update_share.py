from rest_framework import serializers, exceptions
from ..fields import UUIDField

from ..utils import user_has_rights_on_share
from ..models import Share


class UpdateShareSerializer(serializers.Serializer):
    share_id = UUIDField(required=True)
    data = serializers.CharField(required=False)
    data_nonce = serializers.CharField(required=False, max_length=64)
    old_write_date = serializers.DateTimeField(required=False)

    def validate(self, attrs: dict) -> dict:

        share_id = attrs.get("share_id", "")

        try:
            share = Share.objects.get(pk=share_id)
        except Share.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check permissions on share
        if not user_has_rights_on_share(
            self.context["request"].user.id, share_id, write=True
        ):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        old_write_date = attrs.get("old_write_date")
        if old_write_date is not None and old_write_date != share.write_date:
            msg = "WRITE_DATE_MISMATCH"
            raise exceptions.ValidationError(msg)

        attrs["share"] = share
        attrs["data"] = attrs.get("data", False)
        attrs["data_nonce"] = attrs.get("data_nonce", False)

        return attrs
