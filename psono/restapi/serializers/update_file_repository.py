from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from rest_framework import serializers, exceptions

from typing import Dict

import json

from ..fields import UUIDField, BooleanField
from ..models import File_Repository

class UpdateFileRepositorySerializer(serializers.Serializer):

    file_repository_id = UUIDField(required=True)
    title = serializers.CharField(max_length=256, required=True)
    type = serializers.CharField(max_length=32, required=True)
    gcp_cloud_storage_bucket = serializers.CharField(required=False)
    gcp_cloud_storage_json_key = serializers.CharField(required=False)
    active = BooleanField(required=True)
    aws_s3_bucket = serializers.CharField(required=False)
    aws_s3_region = serializers.CharField(required=False)
    aws_s3_access_key_id = serializers.CharField(required=False)
    aws_s3_secret_access_key = serializers.CharField(required=False)
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

        file_repository_id = attrs.get('file_repository_id')
        title = attrs.get('title', '').strip()
        type = attrs.get('type', '').lower().strip()
        gcp_cloud_storage_bucket = attrs.get('gcp_cloud_storage_bucket', '').strip()
        gcp_cloud_storage_json_key = attrs.get('gcp_cloud_storage_json_key', '').strip()
        aws_s3_bucket = attrs.get('aws_s3_bucket', '').strip()
        aws_s3_region = attrs.get('aws_s3_region', '').strip()
        aws_s3_access_key_id = attrs.get('aws_s3_access_key_id', '').strip()
        aws_s3_secret_access_key = attrs.get('aws_s3_secret_access_key', '').strip()
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

        # Lets check if the current user can do that
        try:
            file_repository = File_Repository.objects.get(id=file_repository_id, file_repository_right__user=self.context['request'].user, file_repository_right__write=True, file_repository_right__accepted=True)
        except File_Repository.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if type not in settings.FILE_REPOSITORY_TYPES:
            msg = "UNKNOWN_TYPE"
            raise exceptions.ValidationError(msg)

        data = {} # type: Dict

        if type == 'gcp_cloud_storage':

            if not gcp_cloud_storage_bucket:
                msg = "BUCKET_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not gcp_cloud_storage_json_key:
                msg = "JSON_KEY_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            try:
                json.loads(gcp_cloud_storage_json_key)
            except:
                msg = "JSON_KEY_IS_INVALID"
                raise exceptions.ValidationError(msg)

            data = {
                'gcp_cloud_storage_bucket': gcp_cloud_storage_bucket,
                'gcp_cloud_storage_json_key': gcp_cloud_storage_json_key,
            }

        if type == 'aws_s3':

            if not aws_s3_bucket:
                msg = "BUCKET_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not aws_s3_region:
                msg = "REGION_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not aws_s3_access_key_id:
                msg = "ACCESS_KEY_ID_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not aws_s3_secret_access_key:
                msg = "SECRET_ACCESS_KEY_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            data = {
                'aws_s3_bucket': aws_s3_bucket,
                'aws_s3_region': aws_s3_region,
                'aws_s3_access_key_id': aws_s3_access_key_id,
                'aws_s3_secret_access_key': aws_s3_secret_access_key,
            }

        if type == 'other_s3':

            if not other_s3_bucket:
                msg = "BUCKET_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not other_s3_region:
                msg = "REGION_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not other_s3_access_key_id:
                msg = "ACCESS_KEY_ID_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not other_s3_secret_access_key:
                msg = "SECRET_ACCESS_KEY_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not other_s3_endpoint_url:
                msg = "URL_IS_REQUIRED"
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
                msg = "BUCKET_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not backblaze_region:
                msg = "REGION_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not backblaze_access_key_id:
                msg = "ACCESS_KEY_ID_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not backblaze_secret_access_key:
                msg = "SECRET_ACCESS_KEY_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            data = {
                'backblaze_bucket': backblaze_bucket,
                'backblaze_region': backblaze_region,
                'backblaze_access_key_id': backblaze_access_key_id,
                'backblaze_secret_access_key': backblaze_secret_access_key,
            }

        if type == 'do_spaces':

            if not do_space:
                msg = "SPACE_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not do_region:
                msg = "REGION_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not do_key:
                msg = "KEY_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            if not do_secret:
                msg = "SECRET_IS_REQUIRED"
                raise exceptions.ValidationError(msg)

            data = {
                'do_space': do_space,
                'do_region': do_region,
                'do_key': do_key,
                'do_secret': do_secret,
            }


        attrs['file_repository'] = file_repository
        attrs['title'] = title
        attrs['type'] = type
        attrs['data'] = data

        return attrs
