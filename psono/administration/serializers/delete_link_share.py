from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Link_Share

class DeleteLinkShareSerializer(serializers.Serializer):
    link_share_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        link_share_id = attrs.get('link_share_id')

        try:
            link_share = Link_Share.objects.get(pk=link_share_id)
        except Link_Share.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['link_share'] = link_share

        return attrs
