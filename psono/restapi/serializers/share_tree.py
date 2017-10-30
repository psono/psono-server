import uuid

from django.utils.http import urlsafe_base64_decode as uid_decoder

from rest_framework import serializers
from ..serializers import PublicShareDetailsSerializer


class ShareTreeSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    parent_share = PublicShareDetailsSerializer()
    child_share = PublicShareDetailsSerializer()