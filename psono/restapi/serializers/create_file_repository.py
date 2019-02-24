from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from rest_framework import serializers, exceptions

import json

class CreateFileRepositorySerializer(serializers.Serializer):

    title = serializers.CharField(max_length=256, required=True)
    type = serializers.CharField(max_length=32, required=True)
    gcp_cloud_storage_bucket = serializers.CharField(required=False)
    gcp_cloud_storage_json_key = serializers.CharField(required=False)

    def validate(self, attrs: dict) -> dict:

        title = attrs.get('title').strip()
        type = attrs.get('type').lower().strip()
        gcp_cloud_storage_bucket = attrs.get('gcp_cloud_storage_bucket', '').strip()
        gcp_cloud_storage_json_key = attrs.get('gcp_cloud_storage_json_key', '').strip()

        if not title:
            msg = _("TITLE_IS_RQUIRED")
            raise exceptions.ValidationError(msg)

        if not type:
            msg = _("TYPE_IS_REQUIRED")
            raise exceptions.ValidationError(msg)

        if type not in settings.FILE_REPOSITORY_TYPES:
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


        attrs['title'] = title
        attrs['type'] = type
        attrs['data'] = data

        return attrs
