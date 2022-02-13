from django.utils.translation import gettext_lazy as _
from django.conf import settings

from rest_framework import serializers, exceptions

from typing import Dict

import json

class CreateFileRepositorySerializer(serializers.Serializer):

    title = serializers.CharField(max_length=256, required=True)
    type = serializers.CharField(max_length=32, required=True)
    gcp_cloud_storage_bucket = serializers.CharField(required=False)
    gcp_cloud_storage_json_key = serializers.CharField(required=False)
    aws_s3_bucket = serializers.CharField(required=False)
    aws_s3_region = serializers.CharField(required=False)
    aws_s3_access_key_id = serializers.CharField(required=False)
    aws_s3_secret_access_key = serializers.CharField(required=False)

    azure_blob_storage_account_name = serializers.CharField(required=False)
    azure_blob_storage_account_primary_key = serializers.CharField(required=False)
    azure_blob_storage_account_container_name = serializers.CharField(required=False)

    other_s3_bucket = serializers.CharField(required=False)
    other_s3_region = serializers.CharField(required=False)
    other_s3_access_key_id = serializers.CharField(required=False)
    other_s3_secret_access_key = serializers.CharField(required=False)
    other_s3_endpoint_url = serializers.CharField(required=False)
    backblaze_bucket = serializers.CharField(required=False)
    backblaze_region = serializers.CharField(required=False)
    backblaze_access_key_id = serializers.CharField(required=False)
    backblaze_secret_access_key = serializers.CharField(required=False)
    do_space = serializers.CharField(required=False)
    do_region = serializers.CharField(required=False)
    do_key = serializers.CharField(required=False)
    do_secret = serializers.CharField(required=False)

    def validate(self, attrs: dict) -> dict:

        title = attrs.get('title', '').strip()
        type = attrs.get('type', '').lower().strip()
        gcp_cloud_storage_bucket = attrs.get('gcp_cloud_storage_bucket', '').strip()
        gcp_cloud_storage_json_key = attrs.get('gcp_cloud_storage_json_key', '').strip()
        aws_s3_bucket = attrs.get('aws_s3_bucket', '').strip()
        aws_s3_region = attrs.get('aws_s3_region', '').strip()
        aws_s3_access_key_id = attrs.get('aws_s3_access_key_id', '').strip()
        aws_s3_secret_access_key = attrs.get('aws_s3_secret_access_key', '').strip()
        azure_blob_storage_account_name = attrs.get('azure_blob_storage_account_name', '').strip()
        azure_blob_storage_account_primary_key = attrs.get('azure_blob_storage_account_primary_key', '').strip()
        azure_blob_storage_account_container_name = attrs.get('azure_blob_storage_account_container_name', '').strip()
        other_s3_bucket = attrs.get('other_s3_bucket', '').strip()
        other_s3_region = attrs.get('other_s3_region', '').strip()
        other_s3_access_key_id = attrs.get('other_s3_access_key_id', '').strip()
        other_s3_secret_access_key = attrs.get('other_s3_secret_access_key', '').strip()
        other_s3_endpoint_url = attrs.get('other_s3_endpoint_url', '').strip()
        backblaze_bucket = attrs.get('backblaze_bucket', '').strip()
        backblaze_region = attrs.get('backblaze_region', '').strip()
        backblaze_access_key_id = attrs.get('backblaze_access_key_id', '').strip()
        backblaze_secret_access_key = attrs.get('backblaze_secret_access_key', '').strip()
        do_space = attrs.get('do_space', '').strip()
        do_region = attrs.get('do_region', '').strip()
        do_key = attrs.get('do_key', '').strip()
        do_secret = attrs.get('do_secret', '').strip()

        if type not in settings.FILE_REPOSITORY_TYPES:
            msg = _("UNKNOWN_TYPE")
            raise exceptions.ValidationError(msg)

        data = {} # type: Dict

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

        if type == 'aws_s3':

            if not aws_s3_bucket:
                msg = _("BUCKET_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not aws_s3_region:
                msg = _("REGION_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not aws_s3_access_key_id:
                msg = _("ACCESS_KEY_ID_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not aws_s3_secret_access_key:
                msg = _("SECRET_ACCESS_KEY_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            data = {
                'aws_s3_bucket': aws_s3_bucket,
                'aws_s3_region': aws_s3_region,
                'aws_s3_access_key_id': aws_s3_access_key_id,
                'aws_s3_secret_access_key': aws_s3_secret_access_key,
            }

        if type == 'azure_blob':

            if not azure_blob_storage_account_name:
                msg = _("ACCOUNT_NAME_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not azure_blob_storage_account_primary_key:
                msg = _("PRIMARY_KEY_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not azure_blob_storage_account_container_name:
                msg = _("CONTAINER_NAME_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            data = {
                'azure_blob_storage_account_name': azure_blob_storage_account_name,
                'azure_blob_storage_account_primary_key': azure_blob_storage_account_primary_key,
                'azure_blob_storage_account_container_name': azure_blob_storage_account_container_name,
            }

        if type == 'other_s3':

            if not other_s3_bucket:
                msg = _("BUCKET_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not other_s3_region:
                msg = _("REGION_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not other_s3_endpoint_url:
                msg = _("URL_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not other_s3_access_key_id:
                msg = _("ACCESS_KEY_ID_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not other_s3_secret_access_key:
                msg = _("SECRET_ACCESS_KEY_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            data = {
                'other_s3_bucket': other_s3_bucket,
                'other_s3_region': other_s3_region,
                'other_s3_access_key_id': other_s3_access_key_id,
                'other_s3_secret_access_key': other_s3_secret_access_key,
                'other_s3_endpoint_url': other_s3_endpoint_url,
            }

        if type == 'backblaze':

            if not backblaze_bucket:
                msg = _("BUCKET_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not backblaze_region:
                msg = _("REGION_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not backblaze_access_key_id:
                msg = _("ACCESS_KEY_ID_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not backblaze_secret_access_key:
                msg = _("SECRET_ACCESS_KEY_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            data = {
                'backblaze_bucket': backblaze_bucket,
                'backblaze_region': backblaze_region,
                'backblaze_access_key_id': backblaze_access_key_id,
                'backblaze_secret_access_key': backblaze_secret_access_key,
            }

        if type == 'do_spaces':

            if not do_space:
                msg = _("SPACE_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not do_region:
                msg = _("REGION_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not do_key:
                msg = _("KEY_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            if not do_secret:
                msg = _("SECRET_IS_REQUIRED")
                raise exceptions.ValidationError(msg)

            data = {
                'do_space': do_space,
                'do_region': do_region,
                'do_key': do_key,
                'do_secret': do_secret,
            }


        attrs['title'] = title
        attrs['type'] = type
        attrs['data'] = data

        return attrs
