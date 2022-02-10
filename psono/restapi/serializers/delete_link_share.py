from django.utils.translation import gettext_lazy as _

from ..models import Link_Share
from rest_framework import serializers, exceptions
from ..fields import UUIDField


class DeleteLinkShareSerializer(serializers.Serializer):

    link_share_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        link_share_id = attrs.get('link_share_id')

        # check if link_share exists
        try:
            link_share = Link_Share.objects.get(pk=link_share_id, user=self.context['request'].user)
        except Link_Share.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['link_share'] = link_share

        return attrs