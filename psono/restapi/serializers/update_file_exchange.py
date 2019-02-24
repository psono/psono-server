from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from rest_framework import serializers, exceptions

import json

from ..fields import UUIDField
from ..models import File_Exchange

class UpdateFileExchangeSerializer(serializers.Serializer):

    file_exchange_id = UUIDField(required=True)
    title = serializers.CharField(max_length=256, required=True)
    type = serializers.CharField(max_length=32, required=True)
    gcp_cloud_storage_bucket = serializers.CharField(required=False)
    gcp_cloud_storage_json_key = serializers.CharField(required=False)
    active = serializers.BooleanField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_exchange_id = attrs.get('file_exchange_id')
        title = attrs.get('title').strip()
        type = attrs.get('type').lower().strip()
        gcp_cloud_storage_bucket = attrs.get('gcp_cloud_storage_bucket', '').strip()
        gcp_cloud_storage_json_key = attrs.get('gcp_cloud_storage_json_key', '').strip()

        # Lets check if the current user can do that
        try:
            file_exchange = File_Exchange.objects.get(id=file_exchange_id, file_exchange_user__user=self.context['request'].user, file_exchange_user__write=True)
        except File_Exchange.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        if not title:
            msg = _("TITLE_IS_RQUIRED")
            raise exceptions.ValidationError(msg)

        if not type:
            msg = _("TYPE_IS_REQUIRED")
            raise exceptions.ValidationError(msg)

        if type not in settings.FILE_EXCHANGE_TYPES:
            msg = _("UNKNOWN_TYPE")
            raise exceptions.ValidationError(msg)

        data = {}

        if type == 'gcp_cloud_storage':

            if not gcp_cloud_storage_bucket:
                msg = _("BUCKET_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not gcp_cloud_storage_json_key:
                msg = _("JSON_KEY_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            try:
                json.loads(gcp_cloud_storage_json_key)
            except:
                msg = _("JSON_KEY_IS_INVALID")
                raise exceptions.ValidationError(msg)

            data = {
                'gcp_cloud_storage_bucket': gcp_cloud_storage_bucket,
                'gcp_cloud_storage_json_key': gcp_cloud_storage_json_key,
            }


        attrs['file_exchange'] = file_exchange
        attrs['title'] = title
        attrs['type'] = type
        attrs['data'] = data

        return attrs
