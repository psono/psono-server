from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField, NullBooleanField
from ..models import API_Key

class UpdateAPIKeySerializer(serializers.Serializer):

    api_key_id = UUIDField(required=True)
    title = serializers.CharField(max_length=256, required=False)
    read = NullBooleanField(required=False)
    write = NullBooleanField(required=False)
    restrict_to_secrets = NullBooleanField(required=False)
    allow_insecure_access = NullBooleanField(required=False)

    def validate(self, attrs: dict) -> dict:

        api_key_id = attrs.get('api_key_id')
        title = attrs.get('title', None)
        read = attrs.get('read', None)
        write = attrs.get('write', None)
        restrict_to_secrets = attrs.get('restrict_to_secrets', None)
        allow_insecure_access = attrs.get('allow_insecure_access', None)


        # Lets check if the current user can do that
        try:
            api_key = API_Key.objects.get(id=api_key_id, user=self.context['request'].user)
        except API_Key.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        if title is None and read is None and write is None and restrict_to_secrets is None and allow_insecure_access is None:
            msg = _("Nothing to update")
            raise exceptions.ValidationError(msg)


        attrs['api_key'] = api_key
        attrs['title'] = title
        attrs['read'] = read
        attrs['write'] = write
        attrs['restrict_to_secrets'] = restrict_to_secrets
        attrs['allow_insecure_access'] = allow_insecure_access

        return attrs
